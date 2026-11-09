// Cartão do cliente na ligação do softphone. Montado em /api/clientes/ligacao.
import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { criarServicoClienteLigacao } from "../services/clienteLigacaoService.js";

export function criarRotasClienteLigacao({ auth = authMiddleware, servico = criarServicoClienteLigacao() } = {}) {
    const router = Router();
    router.use(auth);
    const falha = (res, e, padrao) => {
        if (e?.status && e.status < 500) return res.status(e.status).json({ error: e.message });
        console.error("[cliente-ligacao]", e?.message);
        return res.status(500).json({ error: padrao });
    };

    router.get("/", async (req, res) => {
        try {
            res.setHeader("Cache-Control", "no-store");
            res.json(await servico.porTelefone(req.user.empresa_id, String(req.query.numero || ""), req.query.ddd ? String(req.query.ddd) : null));
        } catch (e) { falha(res, e, "Não foi possível consultar o cliente agora."); }
    });

    router.put("/vinculo", async (req, res) => {
        try {
            res.json(await servico.vincular(req.user.empresa_id, String(req.body?.numero || ""), String(req.body?.contrato || ""), req.user.id));
        } catch (e) { falha(res, e, "Não foi possível vincular o cliente."); }
    });

    router.delete("/vinculo", async (req, res) => {
        try {
            await servico.desvincular(req.user.empresa_id, String(req.query.numero || ""));
            res.json({ ok: true });
        } catch (e) { falha(res, e, "Não foi possível desfazer o vínculo."); }
    });

    return router;
}

export default criarRotasClienteLigacao();
