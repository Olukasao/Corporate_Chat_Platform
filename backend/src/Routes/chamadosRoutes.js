// Chamados abertos pelo site, para a aba Chamados do Workspace. Montado em /api/chamados.
import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { criarServicoChamados } from "../services/chamadosSiteService.js";
import { destacar, listarDestaques, protocolosDestacados, removerDestaque } from "../services/avaliacoesDestaquesService.js";
import { criarServicoAvaliacoes } from "../services/avaliacoesSiteService.js";
import { ErroMarketing } from "../services/marketingSiteService.js";

export function criarRotasChamados({ auth = authMiddleware, servico = criarServicoChamados(), avaliacoes = criarServicoAvaliacoes() } = {}) {
    const router = Router();
    router.use(auth);

    router.get("/site", async (req, res) => {
        try {
            res.setHeader("Cache-Control", "no-store");
            res.json(await servico.listar(req.query));
        } catch (e) {
            if (e instanceof ErroMarketing) return res.status(e.status).json({ error: e.message });
            console.error("[chamados] falha inesperada:", e?.message);
            res.status(500).json({ error: "Não foi possível carregar os chamados do site." });
        }
    });

    router.get("/avaliacoes", async (req, res) => {
        try {
            res.setHeader("Cache-Control", "no-store");
            const dados = await avaliacoes.listar(String(req.query.period || "30d"));
            const marcados = await protocolosDestacados(req.user.empresa_id);
            res.json({
                ...dados,
                podeDestacar: req.user.perfil === "admin",
                itens: dados.itens.map((i) => ({ ...i, destaque: marcados.has(i.protocolo) })),
            });
        } catch (e) {
            if (e instanceof ErroMarketing) return res.status(e.status).json({ error: e.message });
            console.error("[chamados] avaliações:", e?.message);
            res.status(500).json({ error: "Não foi possível carregar as avaliações." });
        }
    });

    // Destaques do Início: qualquer pessoa logada vê (sem nome de cliente); só administrador escolhe.
    router.get("/avaliacoes/destaques", async (req, res) => {
        try {
            res.setHeader("Cache-Control", "no-store");
            res.json({ itens: await listarDestaques(req.user.empresa_id) });
        } catch (e) {
            console.error("[chamados] destaques:", e?.message);
            res.status(500).json({ error: "Não foi possível carregar os destaques." });
        }
    });

    // "Notificar equipe": o administrador manda esta avaliação, como aviso, para todo mundo que está online agora.
    const ultimaNotificacao = new Map();
    router.post("/avaliacoes/notificar", async (req, res) => {
        try {
            if (req.user.perfil !== "admin") return res.status(403).json({ error: "Só administradores notificam a equipe." });
            const protocolo = String(req.body?.protocolo || "").trim().slice(0, 40);
            if (!protocolo) return res.status(400).json({ error: "Dados inválidos." });
            const chave = `${req.user.empresa_id}:${protocolo}`;
            if (Date.now() - (ultimaNotificacao.get(chave) || 0) < 60_000) return res.status(429).json({ error: "Esta avaliação acabou de ser enviada. Espere 1 minuto para enviar de novo." });
            const { itens } = await avaliacoes.listar("90d");
            const alvo = itens.find((i) => i.protocolo === protocolo);
            if (!alvo) return res.status(404).json({ error: "Avaliação não encontrada nos últimos 90 dias." });
            const io = req.app?.get?.("io");
            const sala = `empresa_${req.user.empresa_id}`;
            const sockets = io ? await io.in(sala).fetchSockets() : [];
            const pessoas = new Set(sockets.map((s) => String(s.data?.usuarioId ?? s.data?.userId ?? s.id)));
            io?.to(sala).emit("avaliacoes:notificada", { item: { protocolo: alvo.protocolo, nota: alvo.nota, comentario: alvo.comentario, tecnico: alvo.tecnico, cliente: alvo.cliente, assunto: alvo.assunto, respondidoEm: alvo.respondidoEm }, por: req.user.nome || "" });
            ultimaNotificacao.set(chave, Date.now());
            if (ultimaNotificacao.size > 200) ultimaNotificacao.clear();
            res.json({ ok: true, alcancados: pessoas.size });
        } catch (e) {
            if (e instanceof ErroMarketing) return res.status(e.status).json({ error: e.message });
            console.error("[chamados] notificar:", e?.message);
            res.status(500).json({ error: "Não foi possível enviar a notificação." });
        }
    });

    router.put("/avaliacoes/destaque", async (req, res) => {
        try {
            if (req.user.perfil !== "admin") return res.status(403).json({ error: "Só administradores escolhem os destaques." });
            const protocolo = String(req.body?.protocolo || "").trim().slice(0, 40);
            if (!protocolo || typeof req.body?.destacar !== "boolean") return res.status(400).json({ error: "Dados inválidos." });
            if (!req.body.destacar) {
                await removerDestaque(req.user.empresa_id, protocolo);
                return res.json({ ok: true, destaque: false });
            }
            const { itens } = await avaliacoes.listar("90d");
            const alvo = itens.find((i) => i.protocolo === protocolo);
            if (!alvo) return res.status(404).json({ error: "Avaliação não encontrada nos últimos 90 dias." });
            await destacar(req.user.empresa_id, alvo, req.user.id);
            res.json({ ok: true, destaque: true });
        } catch (e) {
            if (e instanceof ErroMarketing) return res.status(e.status).json({ error: e.message });
            console.error("[chamados] destacar:", e?.message);
            res.status(500).json({ error: "Não foi possível salvar o destaque." });
        }
    });

    router.get("/site/:protocolo", async (req, res) => {
        try {
            res.setHeader("Cache-Control", "no-store");
            res.json(await servico.detalhe(req.params.protocolo));
        } catch (e) {
            if (e instanceof ErroMarketing) return res.status(e.status).json({ error: e.message });
            console.error("[chamados] falha inesperada:", e?.message);
            res.status(500).json({ error: "Não foi possível carregar o chamado." });
        }
    });

    return router;
}

export default criarRotasChamados();
