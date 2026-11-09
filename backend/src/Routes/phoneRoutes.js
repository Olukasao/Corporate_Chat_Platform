// Workscape Phone. Rotas do usuário em /api/phone; administração em /api/admin/phone (atrás de requireAdmin).
import { Router } from "express";
import db from "../db/db.js";
import authMiddleware from "../middlewares/middleware.js";
import { criarLimitador } from "../services/assistenteIa.js";
import {
  auditar, cifrarSenha, decifrarSenha, garantirSchemaPhone, publica, telefoniaConfigurada, validarChamada, validarConta, extensaoDeDiscagem,
} from "../services/phoneService.js";

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

router.post("/chamadas", async (req, res) => {
  if (!limiteHistorico(`${req.user.empresa_id}:${req.user.id}`).ok) return res.status(429).json({ error: "Muitos registros seguidos." });
  try {
    await garantirSchemaPhone();
    const c = validarChamada(req.body);
    await db.query("INSERT INTO phone_calls (empresa_id, usuario_id, direcao, numero, resultado, duracao_seg, inicio) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [...dono(req), c.direcao, c.numero, c.resultado, c.duracaoSeg, c.inicio]);
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

export default router;

/** Administração: cadastrar contas SIP, ligar a funcionários, desativar, ver histórico e auditoria. */
export function criarPhoneAdminRoutes({ requireAdmin }) {
  const admin = Router();
  admin.use(requireAdmin);
  const empresa = (req) => req.user.empresa_id;

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

  return admin;
}
