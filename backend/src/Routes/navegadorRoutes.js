// Sites do Navegador por setor. /api/navegador (qualquer pessoa logada: o que ela vê) e /api/admin/navegador (administração).
import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { servicoNavegador } from "../services/navegadorService.js";

const falha = (res, e, padrao) => {
    if (e?.status && e.status < 500) return res.status(e.status).json({ error: e.message });
    console.error("[navegador]", e?.message);
    return res.status(500).json({ error: padrao });
};

export function criarRotasNavegador({ auth = authMiddleware, servico = servicoNavegador } = {}) {
    const router = Router();
    router.use(auth);
    router.get("/sites", async (req, res) => {
        try { res.setHeader("Cache-Control", "no-store"); res.json({ sites: await servico.paraUsuario(req.user) }); }
        catch (e) { falha(res, e, "Não foi possível carregar os sites."); }
    });
    return router;
}

/** Administração: já montado atrás de authMiddleware + requireAdmin. */
export function criarRotasNavegadorAdmin({ requireAdmin, servico = servicoNavegador }) {
    const router = Router();
    router.use(requireAdmin);
    const empresa = (req) => req.admin.empresa_id;
    router.get("/", async (req, res) => { try { res.setHeader("Cache-Control", "no-store"); res.json(await servico.configuracao(empresa(req))); } catch (e) { falha(res, e, "Não foi possível carregar."); } });
    router.post("/sites", async (req, res) => { try { res.status(201).json(await servico.criarSite(empresa(req), req.body || {}, req.admin.id)); } catch (e) { falha(res, e, "Não foi possível adicionar o site."); } });
    router.put("/sites/:id", async (req, res) => { try { res.json(await servico.atualizarSite(empresa(req), req.params.id, req.body || {})); } catch (e) { falha(res, e, "Não foi possível salvar o site."); } });
    router.delete("/sites/:id", async (req, res) => { try { await servico.removerSite(empresa(req), req.params.id); res.json({ ok: true }); } catch (e) { falha(res, e, "Não foi possível remover o site."); } });
    router.put("/setor/:setorId", async (req, res) => {
        try {
            const setorId = Number(req.params.setorId);
            if (!Number.isInteger(setorId) || setorId <= 0) return res.status(400).json({ error: "Dados inválidos." });
            const sites = req.body?.sites;
            if (sites !== null && !Array.isArray(sites)) return res.status(400).json({ error: "Dados inválidos." });
            res.json({ ok: true, sites: await servico.salvarAcesso(empresa(req), setorId, sites, req.admin.id) });
        } catch (e) { falha(res, e, "Não foi possível salvar."); }
    });
    return router;
}

export default criarRotasNavegador();
