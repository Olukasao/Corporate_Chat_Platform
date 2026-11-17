import { Router } from "express";
import authMiddleware from "../middlewares/middleware.js";
import { userHasNetworkDiagnosticPermission } from "../services/networkDiagnosticPermissionsService.js";
import {
    OltCloudError,
    listarEquipamentosOffline,
    listarIncidentesAtivos,
    obterPanorama,
    oltCloudConfigurada,
} from "../services/oltCloudService.js";
import { estabilidadeDoContrato, marcarUsoAnalises, obterInstaveis, obterRankingPons, obterSinalCritico } from "../services/oltInsightsService.js";
import { usuarioTemModulo } from "../services/funcoesService.js";
import { sincronizarAlertasIgnorados } from "../services/iaAdminService.js";
import { searchCustomers } from "../services/sgpCustomerService.js";

// Incidentes de rede (OLT Cloud), somente leitura. Quem já tem acesso aos diagnósticos de rede (NOC) vê a tela.
const router = Router();

export const usuarioPodeVerRedeOlt = async (usuario) =>
    (await usuarioTemModulo(usuario, "rede")) && (await userHasNetworkDiagnosticPermission(usuario, "network_diagnostics.view"));

const exigirPermissao = async (req, res, next) => {
    try {
        if (!(await usuarioPodeVerRedeOlt(req.user))) {
            return res.status(403).json({ error: "Você não possui permissão para ver os incidentes de rede." });
        }
        return next();
    } catch {
        return res.status(500).json({ error: "Não foi possível validar a permissão." });
    }
};

const responderErro = (res, erro) => {
    if (erro instanceof OltCloudError) {
        return res.status(erro.status === 503 ? 200 : erro.status).json(
            erro.status === 503 ? { configurada: false, incidentes: [] } : { error: erro.message, codigo: erro.codigo }
        );
    }
    console.error("[OLT] Erro:", erro?.message);
    return res.status(500).json({ error: "Não foi possível consultar a rede agora." });
};

router.get("/integrations/olt/incidentes", authMiddleware, exigirPermissao, async (_req, res) => {
    res.set("Cache-Control", "no-store");
    if (!oltCloudConfigurada()) return res.json({ configurada: false, incidentes: [] });
    try {
        const { atualizadoEm, incidentes } = await listarIncidentesAtivos();
        return res.json({ configurada: true, atualizadoEm, incidentes });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

router.get("/integrations/olt/panorama", authMiddleware, exigirPermissao, async (_req, res) => {
    res.set("Cache-Control", "no-store");
    if (!oltCloudConfigurada()) return res.json({ configurada: false });
    try {
        return res.json({ configurada: true, ...(await obterPanorama()) });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

// O app guarda os alertas ignorados em cada computador; esta lista só serve para o briefing do chat não citá-los.
router.put("/integrations/olt/ignorados", authMiddleware, exigirPermissao, async (req, res) => {
    try {
        const total = await sincronizarAlertasIgnorados({ empresaId: req.user.empresa_id ?? 1, usuarioId: req.user.id, ids: req.body?.ids });
        return res.json({ ok: true, total });
    } catch (erro) {
        console.error("[OLT] ignorados:", erro?.message);
        return res.status(500).json({ error: "Não foi possível salvar." });
    }
});

const nomeDoContrato = async (contrato) => {
    const controle = new AbortController();
    const timer = setTimeout(() => controle.abort(), 4000);
    try {
        const resultado = await searchCustomers(contrato, { signal: controle.signal });
        const achado = (resultado?.customers || []).find((c) => String(c.contractId || c.id || "") === contrato) || resultado?.customers?.[0];
        return achado?.name ? String(achado.name).slice(0, 120) : "";
    } catch {
        return "";
    } finally {
        clearTimeout(timer);
    }
};

router.get("/integrations/olt/incidentes/:id/clientes", authMiddleware, exigirPermissao, async (req, res) => {
    res.set("Cache-Control", "no-store");
    const id = String(req.params.id || "").slice(0, 64);
    if (!oltCloudConfigurada()) return res.json({ configurada: false, clientes: [] });
    try {
        const { incidentes } = await listarIncidentesAtivos();
        const incidente = incidentes.find((i) => i.id === id);
        if (!incidente) return res.status(404).json({ error: "Incidente não encontrado ou já encerrado." });
        const equipamentos = await listarEquipamentosOffline(incidente);
        const LIMITE = 60;
        const vistos = new Set();
        const unicos = equipamentos.filter((e) => {
            const chave = e.contrato || `s:${e.serie}`;
            if (vistos.has(chave)) return false;
            vistos.add(chave);
            return true;
        });
        const visiveis = unicos.slice(0, LIMITE);
        // Nome do cliente vem do SGP (melhor esforço, 5 por vez); sem ele a lista ainda mostra o contrato.
        const clientes = [];
        for (let i = 0; i < visiveis.length; i += 5) {
            const lote = visiveis.slice(i, i + 5);
            const nomes = await Promise.all(lote.map((e) => (e.contrato ? nomeDoContrato(e.contrato) : "")));
            lote.forEach((e, k) => clientes.push({ contrato: e.contrato || null, nome: nomes[k] || null, serie: e.serie || null, ultimaQueda: e.ultimaQueda }));
        }
        return res.json({ configurada: true, total: unicos.length, exibidos: clientes.length, clientes });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

// ---- análises (sinal crítico, instabilidade, ranking de PONs, estabilidade do contrato) ----
const lerConfigurada = (res) => {
    marcarUsoAnalises();
    return oltCloudConfigurada() ? true : (res.json({ configurada: false }), false);
};

router.get("/integrations/olt/sinal", authMiddleware, exigirPermissao, async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!lerConfigurada(res)) return undefined;
    try {
        return res.json({ configurada: true, ...(await obterSinalCritico({ dbm: req.query?.dbm })) });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

router.get("/integrations/olt/instaveis", authMiddleware, exigirPermissao, async (_req, res) => {
    res.set("Cache-Control", "no-store");
    if (!lerConfigurada(res)) return undefined;
    try {
        return res.json({ configurada: true, ...(await obterInstaveis()) });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

router.get("/integrations/olt/ranking", authMiddleware, exigirPermissao, async (_req, res) => {
    res.set("Cache-Control", "no-store");
    if (!lerConfigurada(res)) return undefined;
    try {
        return res.json({ configurada: true, ...(await obterRankingPons()) });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

// Nomes dos clientes (SGP, melhor esforço) para as listas de sinal e instabilidade: ?contratos=1,2,3 (até 60).
router.get("/integrations/olt/nomes", authMiddleware, exigirPermissao, async (req, res) => {
    res.set("Cache-Control", "no-store");
    const contratos = [...new Set(String(req.query?.contratos || "").split(",").map((c) => c.replace(/\D/g, "").slice(0, 20)).filter(Boolean))].slice(0, 60);
    const nomes = {};
    for (let i = 0; i < contratos.length; i += 5) {
        const lote = contratos.slice(i, i + 5);
        const achados = await Promise.all(lote.map((c) => nomeDoContrato(c)));
        lote.forEach((c, k) => { if (achados[k]) nomes[c] = achados[k]; });
    }
    return res.json({ nomes });
});

// Ficha do cliente: quedas nas últimas 24 h / 7 dias e sinal. Qualquer atendente logado (não traz endereço, login nem senha).
router.get("/integrations/olt/clientes/:contrato/estabilidade", authMiddleware, async (req, res) => {
    res.set("Cache-Control", "no-store");
    if (!oltCloudConfigurada()) return res.json({ configurada: false });
    try {
        const r = await estabilidadeDoContrato(req.params.contrato);
        return res.json({ configurada: true, encontrado: Boolean(r), ...(r ?? {}) });
    } catch (erro) {
        return responderErro(res, erro);
    }
});

export default router;
