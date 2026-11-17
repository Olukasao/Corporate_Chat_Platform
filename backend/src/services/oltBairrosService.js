// Clientes afetados de uma queda agrupados por BAIRRO (SGP) e por estado do equipamento ("Sem Energia" x "LOSS").
// Ajuda a separar queda de energia (muitos "Sem Energia", concentrada em bairros) de rompimento de fibra ("LOSS").
// So leitura; devolve bairro e contagens, nunca nome, endereco completo ou contrato.
import { consultarContratosUra } from "./sgpCustomerService.js";

const TTL_BAIRRO_MS = 12 * 3600_000;
const LIMITE_CLIENTES = 150;
const cache = new Map(); // contrato -> { ate, bairro, cidade }

const limpar = (v) => String(v ?? "").replace(/\s+/g, " ").trim();
const MINUSCULAS = new Set(["da", "de", "do", "das", "dos", "e"]);
/** O SGP costuma devolver bairro EM MAIUSCULAS: mostra com iniciais maiusculas. */
export const bairroBonito = (v) => {
    const t = limpar(v);
    return t && t === t.toUpperCase() ? t.toLowerCase().split(" ").map((p, i) => (i > 0 && MINUSCULAS.has(p) ? p : p.charAt(0).toUpperCase() + p.slice(1))).join(" ") : t;
};

export const estadoDoEquipamento = (status) => (/energia/i.test(String(status)) ? "semEnergia" : "loss");

/**
 * itens: [{ bairro, cidade, estado: "semEnergia" | "loss" }] -> bairros em ordem de quantidade, com a divisao por estado.
 * O mesmo bairro com a grafia diferente (maiuscula/minuscula, espaco) conta junto.
 */
export const agruparPorBairro = (itens) => {
    const mapa = new Map();
    for (const it of itens) {
        const bairro = bairroBonito(it.bairro) || "Sem bairro";
        const chave = `${bairro.toLowerCase()}|${limpar(it.cidade).toLowerCase()}`;
        const g = mapa.get(chave) ?? { bairro, cidade: bairroBonito(it.cidade), clientes: 0, semEnergia: 0, loss: 0 };
        g.clientes += 1;
        g[it.estado === "semEnergia" ? "semEnergia" : "loss"] += 1;
        mapa.set(chave, g);
    }
    const total = itens.length || 1;
    return [...mapa.values()].map((g) => ({ ...g, pct: Math.round((g.clientes / total) * 100) })).sort((a, b) => b.clientes - a.clientes || a.bairro.localeCompare(b.bairro, "pt-BR"));
};

/** Texto-guia (heuristica, nao certeza): energia aparece como "Sem Energia"; corte de fibra como "LOSS". */
export const leituraDaQueda = (semEnergia, loss) => {
    const n = semEnergia + loss;
    if (n === 0) return "";
    const pctEnergia = Math.round((semEnergia / n) * 100);
    if (pctEnergia >= 70) return "Maioria sem energia: sugere falta de energia na região, não problema de fibra.";
    if (pctEnergia <= 30) return "Maioria em LOSS (perda de sinal): sugere problema na fibra, conector ou OLT, não falta de energia.";
    return "Mistura de sem energia e LOSS: pode ser queda de energia com fibra afetada, ou mais de um problema ao mesmo tempo.";
};

const bairroDoContrato = async (contrato, consultar) => {
    const hit = cache.get(contrato);
    if (hit && Date.now() < hit.ate) return hit;
    const controle = new AbortController();
    const timer = setTimeout(() => controle.abort(), 6000);
    try {
        const lista = await consultar({ contrato }, { signal: controle.signal });
        const c = (Array.isArray(lista) ? lista : []).find((x) => String(x?.contratoId ?? x?.contrato ?? "") === contrato) ?? lista?.[0];
        const valor = { bairro: limpar(c?.endereco_bairro), cidade: limpar(c?.endereco_cidade) };
        if (cache.size > 6000) cache.clear();
        cache.set(contrato, { ...valor, ate: Date.now() + TTL_BAIRRO_MS });
        return valor;
    } catch {
        return { bairro: "", cidade: "", falhou: true };
    } finally {
        clearTimeout(timer);
    }
};

/** equipamentos: afetados da PON ({ contrato, status }). Conta cada contrato uma vez; olha ate 150 (o resto entra em "nao consultados"). */
export const bairrosDosAfetados = async (equipamentos, { consultar = consultarContratosUra, limite = LIMITE_CLIENTES } = {}) => {
    const unicos = new Map();
    let semContrato = 0;
    for (const e of equipamentos) {
        const c = limpar(e.contrato);
        if (!/\d/.test(c)) { semContrato += 1; continue; }
        if (!unicos.has(c)) unicos.set(c, estadoDoEquipamento(e.status));
    }
    const contratos = [...unicos.keys()];
    const consultados = contratos.slice(0, limite);
    const itens = [];
    for (let i = 0; i < consultados.length; i += 6) {
        const lote = consultados.slice(i, i + 6);
        const dados = await Promise.all(lote.map((c) => bairroDoContrato(c, consultar)));
        lote.forEach((c, k) => itens.push({ bairro: dados[k].bairro, cidade: dados[k].cidade, estado: unicos.get(c) }));
    }
    let semEnergia = 0;
    for (const estado of unicos.values()) if (estado === "semEnergia") semEnergia += 1;
    const loss = unicos.size - semEnergia;
    return {
        total: unicos.size,
        consultados: itens.length,
        semContrato,
        semEnergia,
        loss,
        leitura: leituraDaQueda(semEnergia, loss),
        bairros: agruparPorBairro(itens).slice(0, 30),
    };
};
