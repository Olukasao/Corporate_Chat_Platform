// Análises da rede em cima da OLT Cloud (SOMENTE LEITURA): sinal crítico por PON, clientes que "piscam" (quedas repetidas),
// ranking de PONs problemáticas e a estabilidade de um contrato (para a ficha do cliente).
// Nada aqui devolve senha, login PPPoE ou endereço: só contrato, série da ONU, sinal e horários.
import { get, listaDe, parametros, todasAsPaginas, texto, numero, normalizarAlerta, equipamentoAfetado, equipamentosDoContrato } from "./oltCloudService.js";

const FUSO = "-03:00"; // a OLT Cloud devolve data/hora local de Brasília, sem fuso
const HORA = 3600_000;
const DIA = 24 * HORA;

/** "2026-11-17 01:54:10" (Brasília) -> milissegundos; inválido = null. */
export const lerDataOlt = (valor) => {
    const t = String(valor ?? "").trim();
    if (!t) return null;
    const ms = Date.parse(/[zZ]|[+-]\d{2}:?\d{2}$/.test(t) ? t : `${t.replace(" ", "T")}${FUSO}`);
    return Number.isFinite(ms) ? ms : null;
};

// ---- sinal ----
export const LIMITE_SINAL_PADRAO = -27;
const SEM_LEITURA = -90; // a OLT Cloud usa -99,99 quando não há leitura (ONU desligada)
export const limiteSinal = (valor) => {
    const n = Number(valor ?? process.env.OLT_SINAL_CRITICO_DBM);
    return Number.isFinite(n) && n <= -15 && n >= -35 ? n : LIMITE_SINAL_PADRAO;
};
const leituraValida = (v) => Number.isFinite(v) && v > SEM_LEITURA;

const equipamentoResumo = (e) => ({
    idOlt: texto(e, ["id"]),
    contrato: texto(e, ["external_client_contract_id"]),
    serie: texto(e, ["serial_number"]),
    status: texto(e, ["status"]),
    olt: texto(e, ["olt"]),
    oltId: texto(e, ["olt_id"]),
    slot: texto(e, ["slot"]),
    pon: texto(e, ["pon"]),
    rxOnu: numero(e, "device_rx"),
    rxOlt: numero(e, "olt_rx"),
    ultimaQueda: texto(e, ["last_disconnection"]) || null,
    noArDesde: texto(e, ["uptime_since"]) || null,
});

const TTL_EQUIPAMENTOS_MS = 10 * 60_000;
let cacheEquipamentos = { ate: 0, valor: null, pendente: null };
/** Todos os equipamentos (10 mil+), em cache: várias telas usam a mesma leitura. */
export const listarTodosEquipamentos = async ({ forcar = false } = {}) => {
    if (!forcar && cacheEquipamentos.valor && Date.now() < cacheEquipamentos.ate) return cacheEquipamentos.valor;
    cacheEquipamentos.pendente ??= (async () => {
        const brutos = await todasAsPaginas("/api/v2/ftth/equipment/list", {}, ["data", "equipment", "items", "results"], 1000);
        const valor = { lidoEm: new Date().toISOString(), equipamentos: brutos.map(equipamentoResumo) };
        cacheEquipamentos = { ate: Date.now() + TTL_EQUIPAMENTOS_MS, valor, pendente: null };
        return valor;
    })().finally(() => { cacheEquipamentos.pendente = null; });
    return cacheEquipamentos.pendente;
};

const chaveDaPon = (e) => `${e.olt}|${e.slot}|${e.pon}`;

/**
 * Clientes online com sinal pior que o limite (RX da ONU, ou RX da OLT 3 dB pior que o limite), agrupados por PON.
 * Equipamento sem contrato nao e cliente: fica de fora. `dbm` e o RX da ONU (padrao -27).
 */
export const agruparSinalPorPon = (equipamentos, dbm = LIMITE_SINAL_PADRAO) => {
    const pons = new Map();
    for (const e of equipamentos) {
        const p = pons.get(chaveDaPon(e)) ?? { olt: e.olt || "OLT não informada", slot: e.slot, pon: e.pon, total: 0, avisos: 0, criticos: 0, clientes: [] };
        pons.set(chaveDaPon(e), p);
        if (!/\d/.test(e.contrato)) continue;
        p.total += 1;
        if (String(e.status).trim().toLowerCase() !== "online") continue;
        const ruimOnu = leituraValida(e.rxOnu) && e.rxOnu <= dbm;
        const ruimOlt = leituraValida(e.rxOlt) && e.rxOlt <= dbm - 3; // o sinal de subida e naturalmente mais baixo: so conta bem pior
        if (ruimOnu || ruimOlt) {
            p.criticos += 1;
            p.clientes.push({ contrato: e.contrato, serie: e.serie, rxOnu: leituraValida(e.rxOnu) ? e.rxOnu : null, rxOlt: leituraValida(e.rxOlt) ? e.rxOlt : null });
        } else if ((leituraValida(e.rxOnu) && e.rxOnu <= dbm + 2) || (leituraValida(e.rxOlt) && e.rxOlt <= dbm - 1)) {
            p.avisos += 1;
        }
    }
    return [...pons.values()]
        .filter((p) => p.criticos > 0)
        .map((p) => ({ ...p, pctCriticos: p.total ? Math.round((p.criticos / p.total) * 100) : 0, clientes: p.clientes.sort((a, b) => (a.rxOnu ?? 0) - (b.rxOnu ?? 0)).slice(0, 200) }))
        .sort((a, b) => b.criticos - a.criticos || b.pctCriticos - a.pctCriticos);
};

export const obterSinalCritico = async ({ dbm } = {}) => {
    const limite = limiteSinal(dbm);
    const { lidoEm, equipamentos } = await listarTodosEquipamentos();
    const pons = agruparSinalPorPon(equipamentos, limite);
    return {
        atualizadoEm: lidoEm,
        limite,
        totalClientes: pons.reduce((s, p) => s + p.criticos, 0),
        totalPons: pons.length,
        pons: pons.slice(0, 40),
    };
};

// ---- quedas repetidas ----
/** Quedas = vezes que o equipamento saiu de "Online" (varios estados ruins seguidos contam uma vez). `logs` vem do mais novo ao mais antigo. */
export const contarQuedas = (logs, agora = Date.now()) => {
    const eventos = (Array.isArray(logs) ? logs : [])
        .map((l) => ({ em: lerDataOlt(l?.date), ruim: equipamentoAfetado(l?.status) }))
        .filter((l) => l.em !== null)
        .sort((a, b) => a.em - b.em);
    let anteriorRuim = null;
    const quedas = [];
    for (const ev of eventos) {
        if (ev.ruim && anteriorRuim !== true) quedas.push(ev.em);
        anteriorRuim = ev.ruim;
    }
    const desde = (ms) => quedas.filter((q) => agora - q <= ms).length;
    return { quedas24h: desde(DIA), quedas7d: desde(7 * DIA), ultimas: quedas.slice(-5).reverse().map((q) => new Date(q).toISOString()) };
};

const buscarLogs = async (id) => {
    const r = await get(`/api/v2/ftth/equipment/${encodeURIComponent(id)}/status_logs`);
    return listaDe(r, ["results", "data"]);
};

const comLimite = async (itens, limite, trabalho) => {
    let i = 0;
    await Promise.all(Array.from({ length: Math.min(limite, itens.length) }, async () => {
        while (i < itens.length) await trabalho(itens[i++]);
    }));
};

const TTL_INSTAVEIS_MS = 15 * 60_000;
export const MIN_QUEDAS_INSTAVEL = 3;
let cacheInstaveis = { ate: 0, valor: null, pendente: null };
/**
 * Clientes que cairam 3 vezes ou mais nas ultimas 24 h. Para nao consultar o historico de 10 mil ONUs, so olha quem teve
 * queda nas ultimas 24 h (campo "ultima queda") e tem contrato.
 */
export const obterInstaveis = async ({ forcar = false } = {}) => {
    if (!forcar && cacheInstaveis.valor && Date.now() < cacheInstaveis.ate) return cacheInstaveis.valor;
    cacheInstaveis.pendente ??= (async () => {
        const { equipamentos } = await listarTodosEquipamentos();
        const agora = Date.now();
        const candidatos = equipamentos.filter((e) => /\d/.test(e.contrato) && e.idOlt !== "" && (lerDataOlt(e.ultimaQueda) ?? 0) >= agora - DIA);
        const achados = [];
        await comLimite(candidatos.slice(0, 800), 8, async (e) => {
            try {
                const c = contarQuedas(await buscarLogs(e.idOlt), agora);
                if (c.quedas24h >= MIN_QUEDAS_INSTAVEL) achados.push({ contrato: e.contrato, serie: e.serie, olt: e.olt, slot: e.slot, pon: e.pon, status: e.status, rxOnu: leituraValida(e.rxOnu) ? e.rxOnu : null, ...c });
            } catch {
                // um equipamento sem historico nao derruba a lista
            }
        });
        achados.sort((a, b) => b.quedas24h - a.quedas24h || b.quedas7d - a.quedas7d);
        const valor = { atualizadoEm: new Date().toISOString(), verificados: Math.min(candidatos.length, 800), minimoQuedas: MIN_QUEDAS_INSTAVEL, clientes: achados.slice(0, 100) };
        cacheInstaveis = { ate: Date.now() + TTL_INSTAVEIS_MS, valor, pendente: null };
        return valor;
    })().finally(() => { cacheInstaveis.pendente = null; });
    return cacheInstaveis.pendente;
};

// ---- ficha do cliente ----
export const classificarSinal = (rxOnu, rxOlt, dbm = LIMITE_SINAL_PADRAO) => {
    const onu = leituraValida(rxOnu) ? rxOnu : null;
    const olt = leituraValida(rxOlt) ? rxOlt : null;
    if (onu === null && olt === null) return "sem_leitura";
    if ((onu !== null && onu <= dbm) || (olt !== null && olt <= dbm - 3)) return "critico";
    if ((onu !== null && onu <= dbm + 2) || (olt !== null && olt <= dbm - 1)) return "fraco";
    return "ok";
};

/** Estabilidade de um contrato (para a ficha): quedas nas ultimas 24 h / 7 dias e sinal atual. null = contrato sem equipamento na OLT. */
export const estabilidadeDoContrato = async (contrato) => {
    const id = String(contrato ?? "").replace(/\D/g, "").slice(0, 20);
    if (!id) return null;
    const brutos = (await equipamentosDoContrato(id)).filter((e) => texto(e, ["external_client_contract_id"]) === id);
    if (!brutos.length) return null;
    const equipamentos = await Promise.all(brutos.slice(0, 3).map(async (e) => {
        const r = equipamentoResumo(e);
        let q = { quedas24h: 0, quedas7d: 0, ultimas: [] };
        try {
            q = contarQuedas(await buscarLogs(texto(e, ["id"])));
        } catch { /* sem historico: mostra so o sinal */ }
        return { serie: r.serie, status: r.status, olt: r.olt, slot: r.slot, pon: r.pon, rxOnu: leituraValida(r.rxOnu) ? r.rxOnu : null, rxOlt: leituraValida(r.rxOlt) ? r.rxOlt : null, sinal: classificarSinal(r.rxOnu, r.rxOlt), ...q };
    }));
    const pior = equipamentos.reduce((a, b) => (b.quedas24h > a.quedas24h ? b : a), equipamentos[0]);
    return { contrato: id, instavel: pior.quedas24h >= MIN_QUEDAS_INSTAVEL, equipamentos };
};

// ---- ranking de PONs ----
/** Junta alertas da mesma PON que se sobrepoem (pon_down + pon_loss do mesmo evento viram UM episodio). */
export const episodiosPorPon = (alertas, agora = Date.now(), janelaMs = 30 * DIA) => {
    const porPon = new Map();
    for (const a of alertas) {
        if (!String(a.tipo).startsWith("pon_") || a.ignorado) continue;
        const ini = Date.parse(a.inicio ?? "");
        if (!Number.isFinite(ini) || agora - ini > janelaMs) continue;
        const fim = a.fim ? Date.parse(a.fim) : agora;
        const chave = `${a.olt}|${a.slotPon || a.pon}`;
        (porPon.get(chave) ?? porPon.set(chave, []).get(chave)).push({ ini, fim: Number.isFinite(fim) ? Math.max(fim, ini) : agora, afetados: a.dispositivosAtivos ?? 0, olt: a.olt, slotPon: a.slotPon, pon: a.pon });
    }
    const resultado = [];
    for (const [chave, lista] of porPon) {
        lista.sort((x, y) => x.ini - y.ini);
        const eps = [];
        for (const x of lista) {
            const ultimo = eps.at(-1);
            if (ultimo && x.ini <= ultimo.fim + 5 * 60_000) {
                ultimo.fim = Math.max(ultimo.fim, x.fim);
                ultimo.afetados = Math.max(ultimo.afetados, x.afetados);
            } else eps.push({ ini: x.ini, fim: x.fim, afetados: x.afetados });
        }
        const janela = (ms) => eps.filter((e) => agora - e.ini <= ms);
        const resumo = (lst) => ({ quedas: lst.length, minutos: Math.round(lst.reduce((s, e) => s + (e.fim - e.ini), 0) / 60000), maxAfetados: lst.reduce((m, e) => Math.max(m, e.afetados), 0) });
        resultado.push({ chave, olt: lista[0].olt || "OLT não informada", slotPon: lista[0].slotPon, pon: lista[0].pon, semana: resumo(janela(7 * DIA)), mes: resumo(eps), ultima: new Date(eps.at(-1).ini).toISOString() });
    }
    return resultado;
};

const TTL_RANKING_MS = 30 * 60_000;
const PAGINA_ALERTAS = 500;
const PAGINAS_MAXIMAS_RANKING = 24;
/** A OLT Cloud lista alertas do mais antigo ao mais novo: le de tras para frente, em grupos de 4 paginas, ate cobrir os ultimos 30 dias. */
const alertasDos30Dias = async () => {
    const caminho = "/api/v2/ftth/alert/list";
    const sonda = await get(`${caminho}?page_size=1`);
    const total = Number(sonda?.count);
    if (!Number.isFinite(total) || total <= 0) return listaDe(sonda, ["data", "alerts", "items", "results"]);
    const ultima = Math.max(1, Math.ceil(total / PAGINA_ALERTAS));
    const limite = Date.now() - 31 * DIA;
    const todos = [];
    let pagina = ultima;
    for (let lidas = 0; pagina >= 1 && lidas < PAGINAS_MAXIMAS_RANKING; ) {
        const numeros = [];
        for (let k = 0; k < 4 && pagina - k >= 1; k++) numeros.push(pagina - k);
        const respostas = await Promise.all(numeros.map((n) => get(`${caminho}?${parametros({ page_size: PAGINA_ALERTAS, page: n })}`)));
        const lote = respostas.flatMap((r) => listaDe(r, ["data", "alerts", "items", "results"]));
        todos.push(...lote);
        lidas += numeros.length;
        pagina -= numeros.length;
        const maisAntigo = lote.reduce((m, a) => Math.min(m, Date.parse(a?.initial_date ?? "") || m), Infinity);
        if (maisAntigo < limite) break;
    }
    return todos;
};

let cacheRanking = { ate: 0, valor: null, pendente: null };
export const obterRankingPons = async ({ forcar = false } = {}) => {
    if (!forcar && cacheRanking.valor && Date.now() < cacheRanking.ate) return cacheRanking.valor;
    cacheRanking.pendente ??= (async () => {
        const alertas = (await alertasDos30Dias()).map(normalizarAlerta).filter((a) => a.id);
        const eps = episodiosPorPon(alertas);
        const ordena = (campo) => eps.filter((p) => p[campo].quedas > 0).sort((a, b) => b[campo].quedas - a[campo].quedas || b[campo].minutos - a[campo].minutos).slice(0, 20);
        const maisAntigo = alertas.reduce((m, a) => Math.min(m, Date.parse(a.inicio ?? "") || m), Date.now());
        const valor = { atualizadoEm: new Date().toISOString(), cobreDesde: new Date(maisAntigo).toISOString(), semana: ordena("semana"), mes: ordena("mes") };
        cacheRanking = { ate: Date.now() + TTL_RANKING_MS, valor, pendente: null };
        return valor;
    })().finally(() => { cacheRanking.pendente = null; });
    return cacheRanking.pendente;
};

// ---- renovacao em segundo plano: enquanto alguem usou as telas na ultima hora, mantem as leituras quentes (a 1a leitura leva ~20 s) ----
let ultimoUso = 0;
export const marcarUsoAnalises = () => { ultimoUso = Date.now(); };
let temporizadorAquecimento;
export const iniciarAquecimentoAnalises = ({ intervaloMs = 5 * 60_000 } = {}) => {
    if (temporizadorAquecimento) return;
    temporizadorAquecimento = setInterval(async () => {
        if (Date.now() - ultimoUso > HORA) return;
        // cada funcao so refaz a leitura quando o cache dela venceu
        for (const f of [obterSinalCritico, obterInstaveis, obterRankingPons]) await f().catch(() => undefined);
    }, intervaloMs);
    temporizadorAquecimento.unref?.();
};
