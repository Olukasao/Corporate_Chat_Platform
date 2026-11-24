// Roteador do cliente (Workspace). Montado em /api/roteador. Só quem tem o módulo "roteador" (Admin > Funções) e administradores.
import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { usuarioTemModulo } from "../services/funcoesService.js";
import { servicoRoteadorCliente } from "../services/roteadorClienteService.js";

export function criarRotasRoteador({ auth = authMiddleware, servico = servicoRoteadorCliente, temModulo = usuarioTemModulo } = {}) {
    const router = Router();
    router.use(auth);
    router.use(async (req, res, next) => {
        res.setHeader("Cache-Control", "no-store");
        try {
            if (!(await temModulo(req.user, "roteador"))) return res.status(403).json({ error: "Seu setor não tem acesso ao roteador do cliente." });
            next();
        } catch (e) {
            console.error("[roteador] permissão:", e?.message);
            res.status(500).json({ error: "Não foi possível verificar a permissão." });
        }
    });
    const falha = (res, e, padrao) => {
        if (e?.status && e.status < 500 || e?.status === 503) return res.status(e.status).json({ error: e.message });
        console.error("[roteador]", e?.message);
        return res.status(500).json({ error: padrao });
    };

    router.get("/clientes", async (req, res) => {
        try { res.json(await servico.buscar(req.query.q)); } catch (e) { falha(res, e, "Não foi possível buscar o cliente."); }
    });
    router.post("/painel", async (req, res) => {
        try { res.json(await servico.abrir(req.user, req.body?.contrato, { nome: req.body?.nome, req })); } catch (e) { falha(res, e, "Não foi possível abrir o painel."); }
    });
    router.delete("/painel/:contrato", async (req, res) => {
        try { res.json(await servico.fechar(req.user, req.params.contrato)); } catch (e) { falha(res, e, "Não foi possível encerrar o painel."); }
    });
    return router;
}

export default criarRotasRoteador();
