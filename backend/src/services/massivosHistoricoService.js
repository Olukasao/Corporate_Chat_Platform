// Histórico de massivos: o painel NOC só mostra o que está acontecendo agora. A cada poucos minutos guardamos os
// backbones com clientes afetados, para o relatório semanal contar ocorrências e duração.
import db from "../db/db.js";
import { dashboardRelay } from "./dashboardRelayService.js";
import { gravarConfig, lerConfig } from "./iaAdminService.js";

export const BACKBONES = [
    { id: "MRT", key: "BACKBONE GPON ACESSANET | MRT" },
    { id: "DAS", key: "BACKBONE GPON ACESSANET | DAS" },
    { id: "SRP", key: "BACKBONE GPON ACESSANET | SRP" },
    { id: "PV", key: "BACKBONE GPON ACESSANET | PV" },
    { id: "LRJ", key: "BACKBONE GPON ACESSANET | LRJ" },
];
const INTERVALO_MS = 5 * 60_000;

let pronta = null;
export const garantirTabelaMassivos = (banco = db) => {
    pronta ??= banco.query(`
        CREATE TABLE IF NOT EXISTS massivo_historico (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            momento DATETIME NOT NULL,
            backbone VARCHAR(20) NOT NULL,
            total INT NOT NULL,
            KEY idx_massivo (empresa_id, momento)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `).catch((e) => { pronta = null; throw e; });
    return pronta;
};

/** Backbones com clientes afetados num retrato do painel. */
export function massivosDoPainel(grupos = {}) {
    return BACKBONES
        .map((b) => ({ backbone: b.id, total: Number(grupos?.[b.key]) || 0 }))
        .filter((m) => m.total > 0);
}

/**
 * Junta os retratos em ocorrências: retratos do mesmo backbone com menos de `folgaMin` minutos entre si são o mesmo massivo.
 * Duração = do primeiro ao último retrato + um intervalo (o retrato cobre o período até o próximo).
 */
export function agruparOcorrencias(linhas, { folgaMin = 20, intervaloMin = 5 } = {}) {
    const porBackbone = new Map();
    for (const l of [...linhas].sort((a, b) => new Date(a.momento) - new Date(b.momento))) {
        const lista = porBackbone.get(l.backbone) || [];
        const t = new Date(l.momento).getTime();
        const ultima = lista[lista.length - 1];
        if (ultima && t - ultima.fim <= folgaMin * 60_000) {
            ultima.fim = t; ultima.pico = Math.max(ultima.pico, l.total);
        } else lista.push({ backbone: l.backbone, inicio: t, fim: t, pico: l.total });
        porBackbone.set(l.backbone, lista);
    }
    return [...porBackbone.values()].flat()
        .map((o) => ({ backbone: o.backbone, inicio: new Date(o.inicio).toISOString(), minutos: Math.round((o.fim - o.inicio) / 60_000) + intervaloMin, pico: o.pico }))
        .sort((a, b) => a.inicio.localeCompare(b.inicio));
}

export async function ocorrenciasNoPeriodo(empresaId, deIso, ateIso, banco = db) {
    await garantirTabelaMassivos(banco);
    const [rows] = await banco.query("SELECT momento, backbone, total FROM massivo_historico WHERE empresa_id = ? AND momento >= ? AND momento < ?", [empresaId, deIso, ateIso]);
    // Dia em que o registro começou a rodar (gravado ao ligar): sem ele não dá para saber se "nenhum massivo" é verdade.
    const desde = (await lerConfig(empresaId).catch(() => ({}))).massivos_desde || null;
    return { ocorrencias: agruparOcorrencias(rows), registradoDesde: desde };
}

/** Guarda um retrato a cada 5 minutos enquanto houver massivo. */
export function iniciarRegistroMassivos({ empresaId = 1, banco = db, relay = dashboardRelay, intervaloMs = INTERVALO_MS } = {}) {
    relay.start();
    void lerConfig(empresaId).then((c) => { if (!c.massivos_desde) return gravarConfig(empresaId, "massivos_desde", new Date().toISOString()); }).catch(() => {});
    const tick = async () => {
        try {
            const { update, connected } = relay.read();
            if (!connected || !update?.grupos) return;
            const afetados = massivosDoPainel(update.grupos);
            if (!afetados.length) return;
            await garantirTabelaMassivos(banco);
            for (const m of afetados) await banco.query("INSERT INTO massivo_historico (empresa_id, momento, backbone, total) VALUES (?, NOW(), ?, ?)", [empresaId, m.backbone, m.total]);
        } catch (e) { console.error("[massivos] não guardou o retrato:", e?.message); }
    };
    const timer = setInterval(tick, intervaloMs);
    timer.unref?.();
    setTimeout(tick, 15_000).unref?.();
    return () => clearInterval(timer);
}
