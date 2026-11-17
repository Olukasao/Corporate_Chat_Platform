// /api/escritorio — login único no Escritório (Office 3D) para quem já está logado no Workspace.
import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { criarBilhete, escritorioAtivo, usuarioPodeVerEscritorio } from "../services/escritorioService.js";

export function criarRotasEscritorio({ auth = authMiddleware } = {}) {
    const router = Router();
    router.use(auth);
    // O app consulta isto para decidir se mostra o item "Escritório" no menu (não gera bilhete).
    router.get("/disponivel", (req, res) => {
        res.setHeader("Cache-Control", "no-store");
        res.json({ disponivel: escritorioAtivo() && usuarioPodeVerEscritorio(req.user) });
    });
    router.get("/sso", (req, res) => {
        res.setHeader("Cache-Control", "no-store");
        if (!escritorioAtivo() || !usuarioPodeVerEscritorio(req.user)) return res.json({ ativo: false });
        const b = criarBilhete({ id: req.user.id, perfil: req.user.perfil });
        res.json({ ativo: true, url: b.url, origem: b.origem });
    });
    return router;
}
export default criarRotasEscritorio();
