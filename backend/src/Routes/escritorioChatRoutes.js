// /api/escritorio-s2s — o Escritório (Office 3D) conversa pelo chat interno, em nome da pessoa logada nele.
// Servidor a servidor: autenticado pelo segredo compartilhado (ESCRITORIO_TOKEN), nunca pelo navegador.
// "de" vem da sessão do Escritório (conferida lá); aqui só aceitamos pessoas da empresa ligada.
import { createHash, timingSafeEqual } from "node:crypto";
import { Router } from "express";
import db from "../db/db.js";
import { escritorioAtivo } from "../services/escritorioService.js";

const empresaId = () => Number(process.env.ESCRITORIO_EMPRESA_ID || 1);
const igual = (a, b) => { const x = createHash("sha256").update(a).digest(), y = createHash("sha256").update(b).digest(); return timingSafeEqual(x, y); };
const id = (v) => (/^\d{1,12}$/.test(String(v ?? "")) ? Number(v) : null);

export function criarRotasEscritorioChat() {
    const router = Router();
    router.use((req, res, next) => {
        if (!escritorioAtivo()) return res.status(404).json({ error: "Ligação com o Escritório desligada." });
        const dado = String(req.headers.authorization || "").replace(/^Bearer /i, "");
        if (!dado || !igual(dado, String(process.env.ESCRITORIO_TOKEN))) return res.status(401).json({ error: "Token inválido." });
        next();
    });

    // as duas pessoas precisam ser da empresa ligada e estar ativas
    const par = async (de, para) => {
        if (!de || !para || de === para) return null;
        const [r] = await db.query("SELECT id, nome, avatar FROM usuarios WHERE id IN (?, ?) AND empresa_id = ? AND deletado_em IS NULL", [de, para, empresaId()]);
        return r.length === 2 ? r : null;
    };
    const conversa = async (a, b, criar) => {
        const q = "SELECT id FROM conversas_diretas WHERE (usuario1_id = ? AND usuario2_id = ?) OR (usuario1_id = ? AND usuario2_id = ?) LIMIT 1";
        let [c] = await db.query(q, [a, b, b, a]);
        if (!c.length && criar) {
            await db.query("INSERT INTO conversas_diretas (usuario1_id, usuario2_id) VALUES (?, ?)", [a, b]);
            [c] = await db.query(q, [a, b, b, a]);
        }
        return c[0]?.id ?? null;
    };

    router.get("/mensagens", async (req, res) => {
        try {
            const de = id(req.query.de), para = id(req.query.para);
            if (!(await par(de, para))) return res.status(404).json({ error: "Pessoa não encontrada." });
            const conversaId = await conversa(de, para, false);
            if (!conversaId) return res.json({ mensagens: [] });
            const [rows] = await db.query(
                `SELECT id, remetente_id, mensagem, tipo_mensagem, criada_em FROM mensagens
                  WHERE conversa_direta_id = ? AND deletada_em IS NULL ORDER BY id DESC LIMIT 100`, [conversaId]);
            res.json({ mensagens: rows.reverse().map((m) => ({
                id: m.id, remetente_id: m.remetente_id, criada_em: m.criada_em,
                // o mapa só mostra texto; figurinha, áudio e anexo aparecem como aviso curto
                texto: m.tipo_mensagem === "texto" ? String(m.mensagem ?? "") : `[${m.tipo_mensagem === "audio" ? "áudio" : m.tipo_mensagem === "sticker" ? "figurinha" : "anexo"}] abra no chat interno`,
            })) });
        } catch (e) { console.error("[ESCRITORIO-CHAT] listar:", e.message); res.status(500).json({ error: "Falha ao carregar a conversa." }); }
    });

    router.post("/mensagem", async (req, res) => {
        try {
            const de = id(req.body?.de), para = id(req.body?.para);
            const texto = typeof req.body?.texto === "string" ? req.body.texto.trim() : "";
            if (!texto || texto.length > 2000) return res.status(400).json({ error: "Mensagem vazia ou longa demais." });
            const pessoas = await par(de, para);
            if (!pessoas) return res.status(404).json({ error: "Pessoa não encontrada." });
            const conversaId = await conversa(de, para, true);
            const [r] = await db.query("INSERT INTO mensagens (remetente_id, conversa_direta_id, mensagem, tipo_mensagem) VALUES (?, ?, ?, 'texto')", [de, conversaId, texto]);
            await db.query("UPDATE conversas_diretas SET atualizada_em = NOW() WHERE id = ?", [conversaId]);
            await db.query("DELETE FROM conversas_ocultas_usuario WHERE conversa_direta_id = ? AND usuario_id IN (?, ?)", [conversaId, de, para]).catch(() => {});
            // tempo real: a mensagem chega na hora no chat de quem recebeu (mesmos eventos do envio pelo chat)
            const io = req.app.get("io");
            const remetente = pessoas.find((p) => p.id === de);
            const msg = { id: r.insertId, remetente_id: de, usuario_id: para, conversa_id: conversaId, remetente_nome: remetente?.nome, remetente_avatar: remetente?.avatar ?? null,
                mensagem: texto, tipo_mensagem: "texto", anexo_nome: null, anexo_mime: null, sticker_id: null, lida: false, entregue_em: null, lida_em: null, reacoes: [], criada_em: new Date() };
            io?.to(`conversa_${conversaId}`).emit("receive_direct_message", msg);
            io?.to(`user_${para}`).emit("new_direct_message_notification", { ...msg, preview: texto.slice(0, 120) });
            res.status(201).json({ id: r.insertId, criada_em: msg.criada_em });
        } catch (e) { console.error("[ESCRITORIO-CHAT] enviar:", e.message); res.status(500).json({ error: "Falha ao enviar a mensagem." }); }
    });

    return router;
}
export default criarRotasEscritorioChat();
