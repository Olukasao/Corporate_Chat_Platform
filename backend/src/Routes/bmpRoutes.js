import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { usuarioPodeVerRedeOlt } from "./oltRoutes.js";

// Rotas BGP (OpenBMP via AcessaRoute), somente leitura. Mesmo acesso da tela de Rede: quem é do NOC.
// O Workspace nunca fala com a VM direto: o servidor consulta a API do AcessaRoute e repassa só o que a tela usa.
const router = Router();
const BASE = (process.env.ACESSAROUTE_URL || "http://192.168.1.134:9100/api/v1").replace(/\/+$/, "");

const exigirPermissao = async (req, res, next) => {
    try {
        if (!(await usuarioPodeVerRedeOlt(req.user))) return res.status(403).json({ error: "Você não possui permissão para ver as rotas BGP." });
        return next();
    } catch {
        return res.status(500).json({ error: "Não foi possível validar a permissão." });
    }
};

async function consultar(caminho) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
        const resposta = await fetch(`${BASE}${caminho}`, { signal: controller.signal, headers: { Accept: "application/json" } });
        const corpo = await resposta.json().catch(() => ({}));
        return { status: resposta.status, corpo };
    } finally {
        clearTimeout(timer);
    }
}

function repassar(caminhoFn) {
    return async (req, res) => {
        res.set("Cache-Control", "no-store");
        try {
            const caminho = caminhoFn(req);
            if (!caminho) return res.status(400).json({ error: "Informe um IP, prefixo ou ASN válido." });
            const { status, corpo } = await consultar(caminho);
            if (status >= 500) return res.json({ disponivel: false });
            return res.status(status).json({ disponivel: true, ...corpo });
        } catch (erro) {
            console.error("[BMP] Erro:", erro?.message);
            return res.json({ disponivel: false });
        }
    };
}

router.get("/integrations/bmp/resumo", authMiddleware, exigirPermissao, repassar(() => "/dashboard"));
router.get("/integrations/bmp/peers", authMiddleware, exigirPermissao, repassar(() => "/peers"));
router.get("/integrations/bmp/mudancas", authMiddleware, exigirPermissao, repassar(() => "/bgp/updates?limit=30"));
router.get(
    "/integrations/bmp/busca",
    authMiddleware,
    exigirPermissao,
    repassar((req) => {
        const q = String(req.query.q ?? "").trim();
        return /^[0-9a-fA-F:.\/]{2,64}$|^(AS)?\d{1,10}$/i.test(q) ? `/bgp/search?q=${encodeURIComponent(q)}` : "";
    })
);

export default router;
