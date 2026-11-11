// Terminal do Workspace: lista de equipamentos única para a empresa, mantida pelos administradores.
// Todos veem a lista e conectam (o app busca a senha só no processo principal, nunca na interface); só administradores
// criam, editam, apagam e importam. Cada pessoa tem a própria observação (nome, lembrete) em cada equipamento.
import { Router } from "express";
import db from "../db/db.js";
import authMiddleware from "../middlewares/middleware.js";
import { criarLimitador } from "../services/assistenteIa.js";
import { cifrarSenha, decifrarSenha } from "../services/phoneService.js";

const RE_HOST = /^[A-Za-z0-9._:-]{1,253}$/;
const MODOS = new Set(["nulo", "enter", "espaco"]);
const falha = (res, e, padrao) => {
  if (e?.status && e.status < 600 && e.status !== 500) return res.status(e.status).json({ error: e.message });
  console.error("[terminal]", e?.message);
  return res.status(500).json({ error: padrao });
};
const idValido = (v) => { const n = Number(v); return Number.isInteger(n) && n > 0 ? n : null; };
const chave = (req) => `${req.user.empresa_id}:${req.user.id}`;

// A chave da senha pode ser a própria do terminal ou a do telefone (mesmo formato AES-256-GCM).
const envCifra = () => ({ PHONE_SECRET_KEY: process.env.TERMINAL_SECRET_KEY || process.env.PHONE_SECRET_KEY });

let esquemaPronto = null;
const garantirEsquema = () => esquemaPronto ??= (async () => {
  const motor = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
  await db.query(`CREATE TABLE IF NOT EXISTS terminal_equipamentos (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    empresa_id INT NOT NULL,
    nome VARCHAR(80) NOT NULL,
    grupo VARCHAR(60) NOT NULL DEFAULT '',
    protocolo VARCHAR(6) NOT NULL DEFAULT 'ssh',
    host VARCHAR(253) NOT NULL,
    porta INT NOT NULL DEFAULT 22,
    usuario VARCHAR(120) NOT NULL DEFAULT '',
    senha_cifrada TEXT NULL,
    anti_idle TINYINT(1) NOT NULL DEFAULT 1,
    anti_idle_segundos INT NOT NULL DEFAULT 60,
    anti_idle_modo VARCHAR(8) NOT NULL DEFAULT 'nulo',
    criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX (empresa_id)
  ) ${motor}`);
  await db.query(`CREATE TABLE IF NOT EXISTS terminal_observacoes (
    equipamento_id INT NOT NULL,
    usuario_id INT NOT NULL,
    texto VARCHAR(300) NOT NULL DEFAULT '',
    atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (equipamento_id, usuario_id)
  ) ${motor}`);
})().catch((e) => { esquemaPronto = null; throw e; });

const publico = (l, observacao = "") => ({
  id: `srv:${l.id}`,
  nome: l.nome,
  grupo: l.grupo,
  protocolo: l.protocolo,
  host: l.host,
  porta: l.porta,
  usuario: l.usuario,
  temSenha: Boolean(l.senha_cifrada),
  antiIdle: l.anti_idle === 1,
  antiIdleSegundos: l.anti_idle_segundos,
  antiIdleModo: l.anti_idle_modo,
  observacao,
});

/** Valida o corpo de um equipamento. `senha` vazia/ausente mantém a atual; `guardarSenha:false` apaga. */
export function validarEquipamento(b = {}) {
  const erro = (m) => Object.assign(new Error(m), { status: 400 });
  const nome = String(b.nome ?? "").trim();
  const host = String(b.host ?? "").trim();
  const protocolo = b.protocolo === "telnet" ? "telnet" : b.protocolo === "ssh" ? "ssh" : null;
  const porta = Number(b.porta);
  if (!nome || nome.length > 80) throw erro("Informe o nome (até 80 letras).");
  if (!protocolo) throw erro("Protocolo inválido.");
  if (!RE_HOST.test(host)) throw erro("Endereço inválido.");
  if (!Number.isInteger(porta) || porta < 1 || porta > 65535) throw erro("Porta inválida.");
  const segundos = Number.isInteger(Number(b.antiIdleSegundos)) ? Math.min(3600, Math.max(10, Number(b.antiIdleSegundos))) : 60;
  return {
    nome,
    grupo: String(b.grupo ?? "").trim().slice(0, 60),
    protocolo,
    host,
    porta,
    usuario: String(b.usuario ?? "").slice(0, 120),
    senha: typeof b.senha === "string" && b.senha ? b.senha.slice(0, 512) : undefined,
    guardarSenha: protocolo === "ssh" && b.guardarSenha !== false,
    antiIdle: b.antiIdle === false ? 0 : 1,
    antiIdleSegundos: segundos,
    antiIdleModo: MODOS.has(b.antiIdleModo) ? b.antiIdleModo : "nulo",
  };
}

const router = Router();
router.use(authMiddleware);
const limiteCredencial = criarLimitador({ max: 120 });

async function listaComObservacoes(req) {
  await garantirEsquema();
  const [linhas] = await db.query("SELECT * FROM terminal_equipamentos WHERE empresa_id = ? ORDER BY grupo ASC, nome ASC LIMIT 2000", [req.user.empresa_id]);
  const [obs] = await db.query(
    "SELECT o.equipamento_id, o.texto FROM terminal_observacoes o JOIN terminal_equipamentos e ON e.id = o.equipamento_id WHERE e.empresa_id = ? AND o.usuario_id = ?",
    [req.user.empresa_id, req.user.id]);
  const mapa = new Map(obs.map((o) => [o.equipamento_id, o.texto]));
  return linhas.map((l) => publico(l, mapa.get(l.id) ?? ""));
}

router.get("/equipamentos", async (req, res) => {
  try { res.json({ equipamentos: await listaComObservacoes(req) }); } catch (e) { falha(res, e, "Não foi possível carregar os equipamentos."); }
});

router.put("/equipamentos/:id/observacao", async (req, res) => {
  try {
    await garantirEsquema();
    const id = idValido(String(req.params.id).replace(/^srv:/, ""));
    if (!id) return res.status(400).json({ error: "Equipamento inválido." });
    const texto = String(req.body?.texto ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
    const [[eq]] = await db.query("SELECT id FROM terminal_equipamentos WHERE id = ? AND empresa_id = ?", [id, req.user.empresa_id]);
    if (!eq) return res.status(404).json({ error: "Equipamento não encontrado." });
    if (!texto) await db.query("DELETE FROM terminal_observacoes WHERE equipamento_id = ? AND usuario_id = ?", [id, req.user.id]);
    else await db.query(
      "INSERT INTO terminal_observacoes (equipamento_id, usuario_id, texto) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE texto = VALUES(texto)",
      [id, req.user.id, texto]);
    res.json({ ok: true, texto });
  } catch (e) { falha(res, e, "Não foi possível salvar a observação."); }
});

// Só o processo principal do app lê isto; a interface nunca recebe a senha.
router.get("/equipamentos/:id/credencial", async (req, res) => {
  if (!limiteCredencial(chave(req)).ok) return res.status(429).json({ error: "Muitas conexões seguidas. Aguarde um pouco." });
  try {
    await garantirEsquema();
    const id = idValido(String(req.params.id).replace(/^srv:/, ""));
    const [[l]] = id ? await db.query("SELECT * FROM terminal_equipamentos WHERE id = ? AND empresa_id = ?", [id, req.user.empresa_id]) : [[]];
    if (!l) return res.status(404).json({ error: "Equipamento não encontrado." });
    res.set("Cache-Control", "no-store");
    res.json({
      protocolo: l.protocolo, host: l.host, porta: l.porta, usuario: l.usuario,
      senha: l.senha_cifrada ? decifrarSenha(l.senha_cifrada, envCifra()) : undefined,
    });
  } catch (e) { falha(res, e, "Não foi possível obter o acesso do equipamento."); }
});

export default router;

export function criarTerminalAdminRoutes({ requireAdmin }) {
  const admin = Router();
  admin.use(requireAdmin);
  const empresa = (req) => req.user.empresa_id;

  const montarSenha = (e, anterior) => {
    if (!e.guardarSenha) return null;
    if (e.senha) return cifrarSenha(e.senha, envCifra());
    return anterior ?? null;
  };

  admin.get("/", async (req, res) => {
    try {
      const equipamentos = await listaComObservacoes(req);
      const [obs] = await db.query(
        `SELECT o.equipamento_id, o.texto, u.nome FROM terminal_observacoes o
         JOIN terminal_equipamentos e ON e.id = o.equipamento_id JOIN usuarios u ON u.id = o.usuario_id
         WHERE e.empresa_id = ? ORDER BY u.nome ASC LIMIT 5000`, [empresa(req)]);
      res.json({
        equipamentos: equipamentos.map((e) => ({ ...e, observacao: undefined, observacoes: obs.filter((o) => `srv:${o.equipamento_id}` === e.id).map((o) => ({ pessoa: o.nome, texto: o.texto })) })),
      });
    } catch (e) { falha(res, e, "Não foi possível carregar os equipamentos."); }
  });

  admin.post("/", async (req, res) => {
    try {
      await garantirEsquema();
      const e = validarEquipamento(req.body);
      const [r] = await db.query(
        `INSERT INTO terminal_equipamentos (empresa_id, nome, grupo, protocolo, host, porta, usuario, senha_cifrada, anti_idle, anti_idle_segundos, anti_idle_modo)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [empresa(req), e.nome, e.grupo, e.protocolo, e.host, e.porta, e.usuario, montarSenha(e, null), e.antiIdle, e.antiIdleSegundos, e.antiIdleModo]);
      res.status(201).json({ id: `srv:${r.insertId}` });
    } catch (e) { falha(res, e, "Não foi possível salvar o equipamento."); }
  });

  admin.put("/:id", async (req, res) => {
    try {
      await garantirEsquema();
      const id = idValido(String(req.params.id).replace(/^srv:/, ""));
      const [[atual]] = id ? await db.query("SELECT * FROM terminal_equipamentos WHERE id = ? AND empresa_id = ?", [id, empresa(req)]) : [[]];
      if (!atual) return res.status(404).json({ error: "Equipamento não encontrado." });
      const e = validarEquipamento(req.body);
      await db.query(
        `UPDATE terminal_equipamentos SET nome=?, grupo=?, protocolo=?, host=?, porta=?, usuario=?, senha_cifrada=?, anti_idle=?, anti_idle_segundos=?, anti_idle_modo=?
         WHERE id = ? AND empresa_id = ?`,
        [e.nome, e.grupo, e.protocolo, e.host, e.porta, e.usuario, montarSenha(e, atual.senha_cifrada), e.antiIdle, e.antiIdleSegundos, e.antiIdleModo, id, empresa(req)]);
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível salvar o equipamento."); }
  });

  admin.delete("/:id", async (req, res) => {
    try {
      await garantirEsquema();
      const id = idValido(String(req.params.id).replace(/^srv:/, ""));
      if (!id) return res.status(400).json({ error: "Equipamento inválido." });
      const [r] = await db.query("DELETE FROM terminal_equipamentos WHERE id = ? AND empresa_id = ?", [id, empresa(req)]);
      if (r.affectedRows) await db.query("DELETE FROM terminal_observacoes WHERE equipamento_id = ?", [id]);
      res.json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível excluir o equipamento."); }
  });

  // Importa a lista salva no computador de um administrador. Não duplica: mesmo nome + endereço + porta atualiza.
  admin.post("/importar", async (req, res) => {
    try {
      await garantirEsquema();
      const lista = Array.isArray(req.body?.equipamentos) ? req.body.equipamentos.slice(0, 500) : [];
      let novos = 0, atualizados = 0, ignorados = 0;
      for (const bruto of lista) {
        let e;
        try { e = validarEquipamento({ ...bruto, guardarSenha: Boolean(bruto?.senha) || bruto?.guardarSenha }); } catch { ignorados++; continue; }
        const [[ja]] = await db.query("SELECT id, senha_cifrada FROM terminal_equipamentos WHERE empresa_id = ? AND nome = ? AND host = ? AND porta = ?", [empresa(req), e.nome, e.host, e.porta]);
        const senha = montarSenha(e, ja?.senha_cifrada ?? null);
        if (ja) {
          await db.query(
            "UPDATE terminal_equipamentos SET grupo=?, protocolo=?, usuario=?, senha_cifrada=?, anti_idle=?, anti_idle_segundos=?, anti_idle_modo=? WHERE id = ?",
            [e.grupo, e.protocolo, e.usuario, senha, e.antiIdle, e.antiIdleSegundos, e.antiIdleModo, ja.id]);
          atualizados++;
        } else {
          await db.query(
            `INSERT INTO terminal_equipamentos (empresa_id, nome, grupo, protocolo, host, porta, usuario, senha_cifrada, anti_idle, anti_idle_segundos, anti_idle_modo)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [empresa(req), e.nome, e.grupo, e.protocolo, e.host, e.porta, e.usuario, senha, e.antiIdle, e.antiIdleSegundos, e.antiIdleModo]);
          novos++;
        }
      }
      res.json({ novos, atualizados, ignorados });
    } catch (e) { falha(res, e, "Não foi possível importar os equipamentos."); }
  });

  return admin;
}
