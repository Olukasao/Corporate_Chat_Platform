// Situação de presença (almoço, visita, em ligação…). Montado em /api/presenca.
import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { servicoSituacao, SITUACOES } from "../services/situacaoService.js";
import { agendarPresenca as avisarEscritorio } from "../services/escritorioService.js";

export function criarRotasPresenca({ auth = authMiddleware, servico = servicoSituacao } = {}) {
    const router = Router();
    router.use(auth);
    const falha = (res, e, padrao) => {
        if (e?.status && e.status < 500) return res.status(e.status).json({ error: e.message });
        console.error("[presenca]", e?.message);
        return res.status(500).json({ error: padrao });
    };
    const avisar = (req, usuarioId, ef) => {
        avisarEscritorio();
        req.app?.get?.("io")?.to(`empresa_${req.user.empresa_id}`).emit("situacao_changed", { usuario_id: Number(usuarioId), situacao: ef.situacao, ate: ef.ate });
    };

    router.get("/situacoes", async (req, res) => {
        try {
            res.setHeader("Cache-Control", "no-store");
            res.json({ opcoes: SITUACOES, itens: await servico.listar(req.user.empresa_id) });
        } catch (e) { falha(res, e, "Não foi possível carregar as situações."); }
    });

    router.put("/situacao", async (req, res) => {
        try {
            const situacao = req.body?.situacao === null ? null : String(req.body?.situacao || "");
            const ef = await servico.definir(req.user.empresa_id, req.user.id, situacao, req.body?.minutos);
            avisar(req, req.user.id, ef);
            res.json(ef);
        } catch (e) { falha(res, e, "Não foi possível mudar a situação."); }
    });

    router.put("/ligacao", async (req, res) => {
        try {
            if (typeof req.body?.ativa !== "boolean") return res.status(400).json({ error: "Dados inválidos." });
            const ef = await servico.marcarLigacao(req.user.empresa_id, req.user.id, req.body.ativa);
            avisar(req, req.user.id, ef);
            res.json(ef);
        } catch (e) { falha(res, e, "Não foi possível atualizar a ligação."); }
    });

    return router;
}

export default criarRotasPresenca();
