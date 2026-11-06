// Suporte remoto. O app de cada pessoa informa o ID do próprio computador e guarda a própria senha de acesso (ela só
// aparece na tela dela). Administradores veem quem está online e conectam de duas formas: pelo painel, que pede aceite
// na tela da pessoa; ou digitando o código e a senha que a pessoa informou por telefone/chat, que entra direto. Toda
// conexão fica registrada para todos os administradores verem.
import { Router } from "express";
import db from "../db/db.js";
import authMiddleware from "../middlewares/middleware.js";
import { criarLimitador } from "../services/assistenteIa.js";

const falha = (res, e, padrao) => { console.error("[remoto]", e?.message); return res.status(500).json({ error: padrao }); };
const ID_REMOTO = /^[0-9]{6,12}$/;
const VALIDO_MS = 5 * 60_000;
const chave = (req) => `${req.user.empresa_id}:${req.user.id}`;

// Só memória: o app volta a avisar a cada 60 s, então a lista se refaz sozinha depois de reiniciar o servidor.
const dispositivos = new Map();
const pedidos = [];

let esquemaPronto = null;
const garantirEsquema = () => esquemaPronto ??= db.query(
  `CREATE TABLE IF NOT EXISTS remoto_auditoria (
     id BIGINT AUTO_INCREMENT PRIMARY KEY, empresa_id INT NOT NULL, admin_id INT NOT NULL, alvo_id INT NOT NULL,
     remoto_id VARCHAR(16) NOT NULL, modo VARCHAR(10) NOT NULL DEFAULT 'pedido', criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP, INDEX (empresa_id, criado_em)
   )`)
  .then(() => db.query("ALTER TABLE remoto_auditoria ADD COLUMN modo VARCHAR(10) NOT NULL DEFAULT 'pedido'").catch((e) => { if (e?.errno !== 1060) throw e; }))
  .catch((e) => { esquemaPronto = null; throw e; });

const router = Router();
router.use(authMiddleware);
const limite = criarLimitador({ max: 240 });
const limitePedido = criarLimitador({ max: 10 });

router.post("/registro", (req, res) => {
  if (!limite(chave(req)).ok) return res.status(429).json({ error: "Muitos avisos seguidos." });
  const id = String(req.body?.id ?? "");
  if (!ID_REMOTO.test(id)) return res.status(400).json({ error: "ID inválido." });
  const computador = String(req.body?.computador ?? "").replace(/[^\w .-]/g, "").slice(0, 40);
  dispositivos.set(chave(req), { id, computador, em: Date.now() });
  res.json({ ok: true });
});

router.post("/pedir", (req, res) => {
  if (!limitePedido(chave(req)).ok) return res.status(429).json({ error: "Aguarde um pouco antes de pedir de novo." });
  const mensagem = String(req.body?.mensagem ?? "").replace(/\s+/g, " ").trim().slice(0, 300);
  const d = dispositivos.get(chave(req));
  pedidos.unshift({ empresaId: req.user.empresa_id, usuarioId: req.user.id, nome: req.user.nome || "", mensagem, id: d?.id ?? null, em: Date.now() });
  pedidos.length = Math.min(pedidos.length, 100);
  res.status(201).json({ ok: true });
});

export default router;

export function criarRemotoAdminRoutes({ requireAdmin }) {
  const admin = Router();
  admin.use(requireAdmin);

  admin.get("/", async (req, res) => {
    try {
      const empresa = req.user.empresa_id;
      const [pessoas] = await db.query("SELECT id, nome FROM usuarios WHERE empresa_id = ? AND deletado_em IS NULL ORDER BY nome ASC LIMIT 2000", [empresa]);
      const agora = Date.now();
      const lista = pessoas.map((p) => {
        const d = dispositivos.get(`${empresa}:${p.id}`);
        return { usuarioId: p.id, nome: p.nome, computador: d?.computador ?? "", online: !!d && agora - d.em < VALIDO_MS, visto: d ? new Date(d.em).toISOString() : null, temId: !!d };
      }).filter((p) => p.temId);
      await garantirEsquema();
      const [auditoria] = await db.query(
        `SELECT a.criado_em, adm.nome AS admin, COALESCE(alvo.nome, 'Desconhecido') AS alvo, a.modo FROM remoto_auditoria a
         JOIN usuarios adm ON adm.id = a.admin_id LEFT JOIN usuarios alvo ON alvo.id = a.alvo_id
         WHERE a.empresa_id = ? ORDER BY a.id DESC LIMIT 30`, [empresa]);
      res.json({
        dispositivos: lista.sort((a, b) => Number(b.online) - Number(a.online) || a.nome.localeCompare(b.nome)),
        pedidos: pedidos.filter((p) => p.empresaId === empresa).slice(0, 20).map((p) => ({ usuarioId: p.usuarioId, nome: pessoas.find((x) => x.id === p.usuarioId)?.nome ?? p.nome, mensagem: p.mensagem, em: new Date(p.em).toISOString() })),
        auditoria: auditoria.map((a) => ({ em: a.criado_em, admin: a.admin, alvo: a.alvo, modo: a.modo })),
      });
    } catch (e) { falha(res, e, "Não foi possível carregar o suporte remoto."); }
  });

  // Entrega o ID a quem é administrador e deixa a conexão registrada. A pessoa ainda precisa aceitar na tela dela.
  admin.post("/conectar", async (req, res) => {
    try {
      const alvo = Number(req.body?.usuarioId);
      if (!Number.isInteger(alvo) || alvo <= 0) return res.status(400).json({ error: "Pessoa inválida." });
      const d = dispositivos.get(`${req.user.empresa_id}:${alvo}`);
      if (!d || Date.now() - d.em >= VALIDO_MS) return res.status(409).json({ error: "Essa pessoa está sem o Workspace aberto agora." });
      await garantirEsquema();
      await db.query("INSERT INTO remoto_auditoria (empresa_id, admin_id, alvo_id, remoto_id, modo) VALUES (?, ?, ?, ?, 'pedido')", [req.user.empresa_id, req.user.id, alvo, d.id]);
      res.json({ id: d.id });
    } catch (e) { falha(res, e, "Não foi possível iniciar a conexão."); }
  });

  // Só registra no histórico: a conexão em si (com o código e a senha que a pessoa informou) já aconteceu no computador do administrador.
  admin.post("/conectar-manual", async (req, res) => {
    try {
      const id = String(req.body?.id ?? "");
      if (!ID_REMOTO.test(id)) return res.status(400).json({ error: "Código inválido." });
      const empresa = req.user.empresa_id;
      const dono = [...dispositivos.entries()].find(([k, d]) => k.startsWith(`${empresa}:`) && d.id === id);
      const alvo = dono ? Number(dono[0].split(":")[1]) : 0;
      await garantirEsquema();
      await db.query("INSERT INTO remoto_auditoria (empresa_id, admin_id, alvo_id, remoto_id, modo) VALUES (?, ?, ?, ?, 'manual')", [empresa, req.user.id, alvo, id]);
      res.status(201).json({ ok: true });
    } catch (e) { falha(res, e, "Não foi possível registrar a conexão."); }
  });
  return admin;
}
