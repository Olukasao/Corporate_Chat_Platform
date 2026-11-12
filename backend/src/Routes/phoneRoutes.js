// Workscape Phone. Rotas do usuário em /api/phone; administração em /api/admin/phone (atrás de requireAdmin).
import { Router } from "express";
import multer from "multer";
import db from "../db/db.js";
import authMiddleware from "../middlewares/middleware.js";
import { criarLimitador } from "../services/assistenteIa.js";
import {
  auditar, cifrarSenha, decifrarSenha, garantirSchemaPhone, publica, telefoniaConfigurada, validarChamada, validarConta, validarTransferencia, extensaoDeDiscagem,
} from "../services/phoneService.js";
import {
  MAX_ARQUIVO, garantirSchemaTranscricao, ligarAoHistorico, lerConfig, receberGravacao, salvarConfig, validarGravacao,
} from "../services/phoneTranscricaoService.js";

const idValido = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const falha = (res, e, padrao) => {
  if (e?.status && e.status < 500) return res.status(e.status).json({ error: e.message });
  if (e?.status === 503) return res.status(503).json({ error: e.message });
  console.error("[phone]", e?.message);
  return res.status(500).json({ error: padrao });
};

const router = Router();
router.use(authMiddleware);
// Credenciais só são lidas pelo app ao conectar; o limite barra uso abusivo de um token roubado.
const limiteCredenciais = criarLimitador({ max: Number(process.env.PHONE_LIMITE_CREDENCIAIS_HORA) || 30 });
const limiteHistorico = criarLimitador({ max: 600 });
const dono = (req) => [req.user.empresa_id, req.user.id];

router.get("/status", async (req, res) => {
  try {
    await garantirSchemaPhone();
    const [linhas] = await db.query("SELECT * FROM phone_accounts WHERE empresa_id = ? AND usuario_id = ? AND ativo = 1", dono(req));
    res.json({ disponivel: telefoniaConfigurada(), conta: linhas[0] ? publica(linhas[0]) : null });
  } catch (e) { falha(res, e, "Não foi possível consultar o telefone."); }
});

// Devolve a senha SIP da própria conta, só para o processo principal do app (ele repassa ao motor, nunca à interface).
router.get("/credenciais", async (req, res) => {
  const permitido = limiteCredenciais(`${req.user.empresa_id}:${req.user.id}`);
  if (!permitido.ok) {
    res.set("Retry-After", String(permitido.tentarEmSeg));
    return res.status(429).json({ error: "Muitas tentativas de conectar o telefone. Aguarde alguns minutos." });
  }
  try {
    await garantirSchemaPhone();
    const [linhas] = await db.query("SELECT * FROM phone_accounts WHERE empresa_id = ? AND usuario_id = ? AND ativo = 1", dono(req));
    if (!linhas[0]) return res.status(404).json({ error: "Você não tem ramal cadastrado. Peça ao administrador." });
    res.set("Cache-Control", "no-store");
    res.json({ conta: publica(linhas[0]), senha: decifrarSenha(linhas[0].senha_cifrada) });
  } catch (e) { falha(res, e, "Não foi possível obter as credenciais do telefone."); }
});

// Presença: o app avisa a cada ~30 s que o telefone está registrado. Fica só na memória (volta sozinha em 30 s após reiniciar).
export const presenca = new Map();
const PRESENCA_VALIDA_MS = 90_000;
const limitePresenca = criarLimitador({ max: 240 });
router.post("/presenca", (req, res) => {
  if (!limitePresenca(`${req.user.empresa_id}:${req.user.id}`).ok) return res.status(429).json({ error: "Muitos avisos seguidos." });
  const registro = ["registrado", "registrando", "recusado", "falhou", "desconectado"].includes(req.body?.registro) ? req.body.registro : "desconectado";
  presenca.set(`${req.user.empresa_id}:${req.user.id}`, { em: Date.now(), registro, emChamada: req.body?.emChamada === true, naoPerturbe: req.body?.naoPerturbe === true });
  res.json({ ok: true });
});

router.get("/diretorio", async (req, res) => {
  try {
    await garantirSchemaPhone();
    const [linhas] = await db.query(
      `SELECT p.usuario_id, p.ramal, u.nome FROM phone_accounts p JOIN usuarios u ON u.id = p.usuario_id
       WHERE p.empresa_id = ? AND p.ativo = 1 AND u.deletado_em IS NULL ORDER BY u.nome ASC LIMIT 1000`, [req.user.empresa_id]);
    res.json({ ramais: linhas.map((l) => ({ usuarioId: l.usuario_id, nome: l.nome, ramal: extensaoDeDiscagem(l.ramal) })) });
  } catch (e) { falha(res, e, "Não foi possível carregar os ramais."); }
});

// Quem transfere um cliente avisa o ramal de destino: a ficha abre lá com o cliente de verdade (a central só manda "asterisk").
const limiteTransferencia = criarLimitador({ max: 60 });
router.post("/transferencia", async (req, res) => {
  if (!limiteTransferencia(`${req.user.empresa_id}:${req.user.id}`).ok) return res.status(429).json({ error: "Muitas transferências seguidas." });
  try {
    const t = validarTransferencia(req.body);
    await garantirSchemaPhone();
    const [contas] = await db.query(
      `SELECT p.usuario_id FROM phone_accounts p JOIN usuarios u ON u.id = p.usuario_id
       WHERE p.empresa_id = ? AND p.ativo = 1 AND u.deletado_em IS NULL AND p.ramal IN (${t.ramais.map(() => "?").join(",")}) LIMIT 1`,
      [req.user.empresa_id, ...t.ramais]);
    // Destino que não é uma pessoa (fila, por exemplo): não há ficha para abrir, e tudo bem.
    if (!contas.length) return res.json({ ok: true, avisou: false });
    req.app?.get?.("io")?.to(`user_${contas[0].usuario_id}`).emit("phone:transferida", { numero: t.numero, de: String(req.user.nome || "").slice(0, 80), em: Date.now() });
    res.json({ ok: true, avisou: true });
  } catch (e) { falha(res, e, "Não foi possível avisar a transferência."); }
});

router.post("/chamadas", async (req, res) => {
  if (!limiteHistorico(`${req.user.empresa_id}:${req.user.id}`).ok) return res.status(429).json({ error: "Muitos registros seguidos." });
  try {
    await garantirSchemaPhone();
    const c = validarChamada(req.body);
    await db.query("INSERT INTO phone_calls (empresa_id, usuario_id, direcao, numero, resultado, duracao_seg, inicio) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [...dono(req), c.direcao, c.numero, c.resultado, c.duracaoSeg, c.inicio]);
    // A gravação pode ter chegado antes desta linha: liga as duas (sem isso o histórico não mostraria a transcrição).
    await garantirSchemaTranscricao().then(() => ligarAoHistorico({ empresaId: req.user.empresa_id, usuarioId: req.user.id, numero: c.numero, inicioMs: c.inicio.getTime() })).catch(() => {});
    res.status(201).json({ ok: true });
  } catch (e) { falha(res, e, "Não foi possível registrar a chamada."); }
});

router.get("/chamadas", async (req, res) => {
  try {
    await garantirSchemaPhone();
    const [linhas] = await db.query(
      "SELECT id, direcao, numero, resultado, duracao_seg, inicio FROM phone_calls WHERE empresa_id = ? AND usuario_id = ? ORDER BY inicio DESC LIMIT 50", dono(req));
    res.json({ chamadas: linhas.map((l) => ({ id: l.id, direcao: l.direcao, numero: l.numero, resultado: l.resultado, duracaoSeg: l.duracao_seg, inicio: l.inicio })) });
  } catch (e) { falha(res, e, "Não foi possível carregar o histórico."); }
});

// ---- gravação e transcrição ------------------------------------------------------------------------
const enviarAudio = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_ARQUIVO, files: 2, fields: 8 } })
  .fields([{ name: "local", maxCount: 1 }, { name: "remoto", maxCount: 1 }]);
const limiteGravacao = criarLimitador({ max: 120 });

// O app pergunta antes de cada chamada se gravar está liberado (o administrador decide em Admin > Histórico de chamadas).
router.get("/gravacao-config", async (req, res) => {
  try { res.set("Cache-Control", "no-store"); res.json({ ativa: (await lerConfig(req.user.empresa_id)).ativa }); }
  catch (e) { falha(res, e, "Não foi possível consultar a gravação."); }
});

router.post("/gravacoes", (req, res) => {
  if (!limiteGravacao(`${req.user.empresa_id}:${req.user.id}`).ok) return res.status(429).json({ error: "Muitos envios seguidos." });
  enviarAudio(req, res, async (erroUpload) => {
    if (erroUpload) return res.status(erroUpload.code === "LIMIT_FILE_SIZE" ? 413 : 400).json({ error: "Arquivo de áudio inválido ou grande demais." });
    try {
      const cfg = await lerConfig(req.user.empresa_id);
      if (!cfg.ativa) return res.status(403).json({ error: "A gravação de chamadas está desligada." });
      const dados = validarGravacao(req.body, req.files);
      const id = await receberGravacao({ empresaId: req.user.empresa_id, usuarioId: req.user.id, dados, io: req.app?.get?.("io") });
      res.status(201).json({ ok: true, id });
    } catch (e) { falha(res, e, "Não foi possível receber a gravação."); }
  });
});

const dig8 = (v) => String(v ?? "").replace(/\D/g, "").slice(-8);
const publicaTrans = (l, detalhe = false) => ({
  id: l.id, usuarioId: l.usuario_id, nome: l.nome ?? undefined, direcao: l.direcao, numero: l.numero, inicioMs: Number(l.inicio_ms), duracaoSeg: l.duracao_seg,
  status: l.status, resumo: l.resumo, motivo: l.motivo, erro: l.status === "erro" ? l.erro : null,
  ...(detalhe ? { falas: (() => { try { return JSON.parse(l.segmentos || "[]"); } catch { return []; } })() } : {}),
});

// As transcrições das próprias ligações da pessoa, por número do cliente (usado na conversa e na ficha do cliente).
router.get("/transcricoes", async (req, res) => {
  try {
    await garantirSchemaTranscricao();
    const final = dig8(req.query.numero);
    if (final.length !== 8) return res.status(400).json({ error: "Informe o telefone do cliente." });
    const [linhas] = await db.query(
      `SELECT * FROM phone_gravacoes WHERE empresa_id = ? AND usuario_id = ? AND REPLACE(REPLACE(REPLACE(REPLACE(numero,'-',''),' ',''),'(',''),')','') LIKE ?
       ORDER BY inicio_ms DESC LIMIT 20`, [...dono(req), `%${final}`]);
    res.json({ transcricoes: linhas.map((l) => publicaTrans(l, true)) });
  } catch (e) { falha(res, e, "Não foi possível carregar as transcrições."); }
});

export default router;

/** Administração: cadastrar contas SIP, ligar a funcionários, desativar, ver histórico e auditoria. */
export function criarPhoneAdminRoutes({ requireAdmin }) {
  const admin = Router();
  admin.use(requireAdmin);
  const empresa = (req) => req.user.empresa_id;

  // Estas rotas ficam antes das de "/:usuarioId", senão "gravacao-config" seria lido como número de pessoa.
  admin.get("/gravacao-config", async (req, res) => {
    try { res.json(await lerConfig(empresa(req))); } catch (e) { falha(res, e, "Não foi possível carregar a configuração."); }
  });
  admin.put("/gravacao-config", async (req, res) => {
    try {
      const dias = req.body?.dias === undefined ? undefined : Number(req.body.dias);
      if (dias !== undefined && (!Number.isFinite(dias) || dias < 1 || dias > 3650)) return res.status(400).json({ error: "O prazo precisa ficar entre 1 e 3650 dias." });
      if (req.body?.ativa !== undefined && typeof req.body.ativa !== "boolean") return res.status(400).json({ error: "Valor inválido." });
      const cfg = await salvarConfig(empresa(req), { ativa: req.body?.ativa, dias });
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "gravacao_config", detalhe: `${cfg.ativa ? "ligada" : "desligada"}, guarda ${cfg.dias} dias` });
      res.json(cfg);
    } catch (e) { falha(res, e, "Não foi possível salvar a configuração."); }
  });


  admin.get("/", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const [contas] = await db.query(
        `SELECT p.*, u.nome AS usuario_nome FROM phone_accounts p JOIN usuarios u ON u.id = p.usuario_id
         WHERE p.empresa_id = ? AND u.deletado_em IS NULL ORDER BY u.nome ASC`, [empresa(req)]);
      const [pessoas] = await db.query(
        "SELECT id, nome FROM usuarios WHERE empresa_id = ? AND deletado_em IS NULL ORDER BY nome ASC LIMIT 2000", [empresa(req)]);
      res.json({ configurada: telefoniaConfigurada(), contas: contas.map((c) => {
        const p = presenca.get(`${empresa(req)}:${c.usuario_id}`);
        const vivo = !!p && Date.now() - p.em < PRESENCA_VALIDA_MS;
        return { ...publica(c), nome: c.usuario_nome, online: vivo && p.registro === "registrado" && c.ativo === 1, emChamada: vivo && p.emChamada, naoPerturbe: vivo && p.naoPerturbe, visto: vivo ? new Date(p.em).toISOString() : null };
      }), pessoas });
    } catch (e) { falha(res, e, "Não foi possível carregar o telefone."); }
  });

  admin.put("/:usuarioId", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const alvo = idValido(req.params.usuarioId);
      if (!alvo) return res.status(400).json({ error: "Pessoa inválida." });
      const [pessoa] = await db.query("SELECT id FROM usuarios WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL", [alvo, empresa(req)]);
      if (!pessoa[0]) return res.status(404).json({ error: "Pessoa não encontrada." });
      const [atual] = await db.query("SELECT id FROM phone_accounts WHERE empresa_id = ? AND usuario_id = ?", [empresa(req), alvo]);
      const c = validarConta(req.body, { senhaObrigatoria: !atual[0] });
      const ativo = req.body?.ativo === false ? 0 : 1;
      try {
        if (atual[0]) {
          await db.query(
            `UPDATE phone_accounts SET ramal = ?, sip_user = ?, sip_domain = ?, sip_server = ?, sip_port = ?, transport = ?, display_name = ?, ativo = ?
             ${c.senha ? ", senha_cifrada = ?" : ""} WHERE empresa_id = ? AND usuario_id = ?`,
            [c.ramal, c.sipUser, c.sipDomain, c.sipServer, c.sipPort, c.transport, c.displayName, ativo, ...(c.senha ? [cifrarSenha(c.senha)] : []), empresa(req), alvo]);
        } else {
          await db.query(
            `INSERT INTO phone_accounts (empresa_id, usuario_id, ramal, sip_user, sip_domain, sip_server, sip_port, transport, display_name, senha_cifrada, ativo)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [empresa(req), alvo, c.ramal, c.sipUser, c.sipDomain, c.sipServer, c.sipPort, c.transport, c.displayName, cifrarSenha(c.senha), ativo]);
        }
      } catch (e) {
        if (e?.code === "ER_DUP_ENTRY") return res.status(409).json({ error: "Esse ramal já está ligado a outra pessoa." });
        throw e;
      }
      // A auditoria nunca leva a senha: só diz que ela foi trocada.
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: atual[0] ? "conta_editada" : "conta_criada", alvoUsuarioId: alvo,
        detalhe: `ramal ${c.ramal}${c.senha ? ", senha trocada" : ""}${ativo ? "" : ", desativada"}` });
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível salvar a conta."); }
  });

  admin.delete("/:usuarioId", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const alvo = idValido(req.params.usuarioId);
      if (!alvo) return res.status(400).json({ error: "Pessoa inválida." });
      const [r] = await db.query("UPDATE phone_accounts SET ativo = 0 WHERE empresa_id = ? AND usuario_id = ?", [empresa(req), alvo]);
      if (!r.affectedRows) return res.status(404).json({ error: "Conta não encontrada." });
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "conta_desativada", alvoUsuarioId: alvo });
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível desativar a conta."); }
  });

  // Ativa de novo uma conta que foi desativada (a senha e o ramal continuam guardados).
  admin.post("/:usuarioId/reativar", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const alvo = idValido(req.params.usuarioId);
      if (!alvo) return res.status(400).json({ error: "Pessoa inválida." });
      const [r] = await db.query("UPDATE phone_accounts SET ativo = 1 WHERE empresa_id = ? AND usuario_id = ?", [empresa(req), alvo]);
      if (!r.affectedRows) return res.status(404).json({ error: "Conta não encontrada." });
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "conta_reativada", alvoUsuarioId: alvo });
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível ativar a conta."); }
  });

  // Apaga o ramal cadastrado de vez (o histórico de chamadas da pessoa é mantido). O ramal fica livre para outro cadastro.
  admin.delete("/:usuarioId/definitivo", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const alvo = idValido(req.params.usuarioId);
      if (!alvo) return res.status(400).json({ error: "Pessoa inválida." });
      const [atual] = await db.query("SELECT ramal FROM phone_accounts WHERE empresa_id = ? AND usuario_id = ?", [empresa(req), alvo]);
      if (!atual[0]) return res.status(404).json({ error: "Conta não encontrada." });
      await db.query("DELETE FROM phone_accounts WHERE empresa_id = ? AND usuario_id = ?", [empresa(req), alvo]);
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "conta_excluida", alvoUsuarioId: alvo, detalhe: `ramal ${atual[0].ramal}` });
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível excluir a conta."); }
  });

  admin.get("/chamadas", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const alvo = req.query.usuarioId ? idValido(req.query.usuarioId) : null;
      const [linhas] = await db.query(
        `SELECT c.id, c.usuario_id, u.nome, c.direcao, c.numero, c.resultado, c.duracao_seg, c.inicio FROM phone_calls c
         JOIN usuarios u ON u.id = c.usuario_id WHERE c.empresa_id = ? ${alvo ? "AND c.usuario_id = ?" : ""} ORDER BY c.inicio DESC LIMIT 200`,
        alvo ? [empresa(req), alvo] : [empresa(req)]);
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "historico_consultado", alvoUsuarioId: alvo });
      res.json({ chamadas: linhas.map((l) => ({ id: l.id, usuarioId: l.usuario_id, nome: l.nome, direcao: l.direcao, numero: l.numero, resultado: l.resultado, duracaoSeg: l.duracao_seg, inicio: l.inicio })) });
    } catch (e) { falha(res, e, "Não foi possível carregar o histórico."); }
  });

  admin.get("/auditoria", async (req, res) => {
    try {
      await garantirSchemaPhone();
      const [linhas] = await db.query(
        `SELECT a.id, a.acao, a.detalhe, a.criado_em, ator.nome AS ator, alvo.nome AS alvo FROM phone_audit a
         LEFT JOIN usuarios ator ON ator.id = a.ator_id LEFT JOIN usuarios alvo ON alvo.id = a.alvo_usuario_id
         WHERE a.empresa_id = ? ORDER BY a.id DESC LIMIT 100`, [empresa(req)]);
      res.json({ eventos: linhas });
    } catch (e) { falha(res, e, "Não foi possível carregar a auditoria."); }
  });

  // ---- histórico de chamadas com transcrição ----------------------------------------------------------
  // Todas as chamadas registradas, com o estado da transcrição de cada uma. Filtros: pessoa, texto (busca na transcrição) e datas.
  admin.get("/historico", async (req, res) => {
    try {
      await garantirSchemaTranscricao();
      const alvo = req.query.usuarioId ? idValido(req.query.usuarioId) : null;
      const busca = String(req.query.q ?? "").trim().slice(0, 80);
      const de = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.de ?? "")) ? `${req.query.de} 00:00:00` : null;
      const ate = /^\d{4}-\d{2}-\d{2}$/.test(String(req.query.ate ?? "")) ? `${req.query.ate} 23:59:59` : null;
      const onde = ["c.empresa_id = ?"]; const args = [empresa(req)];
      if (alvo) { onde.push("c.usuario_id = ?"); args.push(alvo); }
      if (de) { onde.push("c.inicio >= ?"); args.push(de); }
      if (ate) { onde.push("c.inicio <= ?"); args.push(ate); }
      if (busca) {
        const like = `%${busca.replace(/[%_\\]/g, "\\$&")}%`;
        onde.push("(c.numero LIKE ? OR u.nome LIKE ? OR g.segmentos LIKE ? OR g.resumo LIKE ?)"); args.push(like, like, like, like);
      }
      const [linhas] = await db.query(
        `SELECT c.id AS chamada_id, c.usuario_id, u.nome, c.direcao, c.numero, c.resultado, c.duracao_seg AS duracao_chamada, c.inicio,
                g.id AS grav_id, g.status, g.resumo, g.motivo
         FROM phone_calls c JOIN usuarios u ON u.id = c.usuario_id
         LEFT JOIN phone_gravacoes g ON g.call_id = c.id
         WHERE ${onde.join(" AND ")} ORDER BY c.inicio DESC LIMIT 300`, args);
      res.json({ chamadas: linhas.map((l) => ({
        id: l.chamada_id, usuarioId: l.usuario_id, nome: l.nome, direcao: l.direcao, numero: l.numero, resultado: l.resultado,
        duracaoSeg: l.duracao_chamada, inicio: l.inicio, transcricaoId: l.grav_id ?? null, transcricao: l.status ?? null, resumo: l.resumo ?? null, motivo: l.motivo ?? null,
      })) });
    } catch (e) { falha(res, e, "Não foi possível carregar o histórico."); }
  });

  admin.get("/transcricoes/:id", async (req, res) => {
    try {
      await garantirSchemaTranscricao();
      const id = idValido(req.params.id);
      if (!id) return res.status(400).json({ error: "Transcrição inválida." });
      const [linhas] = await db.query("SELECT g.*, u.nome FROM phone_gravacoes g JOIN usuarios u ON u.id = g.usuario_id WHERE g.id = ? AND g.empresa_id = ?", [id, empresa(req)]);
      if (!linhas[0]) return res.status(404).json({ error: "Transcrição não encontrada." });
      // Ler o que o cliente falou é sensível: fica na auditoria de quem leu.
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "transcricao_lida", alvoUsuarioId: linhas[0].usuario_id, detalhe: `transcrição ${id}` });
      res.json(publicaTrans(linhas[0], true));
    } catch (e) { falha(res, e, "Não foi possível carregar a transcrição."); }
  });

  admin.delete("/transcricoes/:id", async (req, res) => {
    try {
      await garantirSchemaTranscricao();
      const id = idValido(req.params.id);
      if (!id) return res.status(400).json({ error: "Transcrição inválida." });
      const [r] = await db.query("DELETE FROM phone_gravacoes WHERE id = ? AND empresa_id = ? AND status NOT IN ('fila','transcrevendo')", [id, empresa(req)]);
      if (!r.affectedRows) return res.status(404).json({ error: "Transcrição não encontrada ou ainda em andamento." });
      await auditar({ empresaId: empresa(req), atorId: req.user.id, acao: "transcricao_excluida", detalhe: `transcrição ${id}` });
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível excluir a transcrição."); }
  });

  return admin;
}
