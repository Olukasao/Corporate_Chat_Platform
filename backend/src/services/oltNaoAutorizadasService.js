// ONUs instaladas que estao esperando autorizacao na OLT (lista "nao autorizadas" da OLT Cloud). SOMENTE LEITURA:
// avisa a equipe quando aparece uma nova (o tecnico instalou e alguem precisa liberar). Nada aqui autoriza ou altera a OLT.
import { get, listaDe, texto } from "./oltCloudService.js";

const TTL_NOMES_OLT_MS = 3600_000;
let nomesOlt = { ate: 0, mapa: new Map() };
const nomeDasOlts = async () => {
    if (Date.now() < nomesOlt.ate) return nomesOlt.mapa;
    try {
        const r = await get("/api/v2/ftth/olts");
        const mapa = new Map(listaDe(r, ["olts", "results", "data"]).map((o) => [String(o.id), texto(o, ["name"])]));
        nomesOlt = { ate: Date.now() + TTL_NOMES_OLT_MS, mapa };
    } catch { /* sem o nome, mostra o numero da OLT */ }
    return nomesOlt.mapa;
};

/** Resposta da OLT Cloud -> lista simples. Ignora OLT com erro ou em quarentena (a leitura delas nao vale). */
export const normalizarNaoAutorizadas = (resposta, nomes = new Map()) => {
    const itens = [];
    for (const o of listaDe(resposta, ["results", "data"])) {
        if (o?.error === true || o?.quarantined === true) continue;
        const oltId = String(o?.olt_id ?? "");
        for (const u of Array.isArray(o?.unauth_list) ? o.unauth_list : []) {
            const serie = texto(u, ["serial_number"]);
            if (!serie) continue;
            itens.push({
                serie,
                modelo: texto(u, ["type"]),
                olt: nomes.get(oltId) || (oltId ? `OLT ${oltId}` : "OLT não informada"),
                oltId,
                slot: texto(u, ["slot"]),
                pon: texto(u, ["pon"]),
                temCliente: Boolean(u?.client),
            });
        }
    }
    return itens.sort((a, b) => a.olt.localeCompare(b.olt, "pt-BR") || Number(a.slot) - Number(b.slot) || Number(a.pon) - Number(b.pon));
};

/** Quais da leitura atual nao estavam na anterior. `anteriores` null = primeira leitura (nao avisa). */
export const selecionarNovas = (itens, anteriores) => (anteriores ? itens.filter((i) => !anteriores.has(i.serie)) : []);

const vistoPrimeiraVez = new Map(); // serie -> ISO (so em memoria)
export const listarNaoAutorizadas = async () => {
    const [resposta, nomes] = await Promise.all([get("/api/v2/ftth/equipment/list/unauth?page_size=50"), nomeDasOlts()]);
    const itens = normalizarNaoAutorizadas(resposta, nomes);
    const agora = new Date().toISOString();
    for (const i of itens) if (!vistoPrimeiraVez.has(i.serie)) vistoPrimeiraVez.set(i.serie, agora);
    for (const serie of [...vistoPrimeiraVez.keys()]) if (!itens.some((i) => i.serie === serie)) vistoPrimeiraVez.delete(serie);
    return { atualizadoEm: agora, total: itens.length, itens: itens.map((i) => ({ ...i, vistoDesde: vistoPrimeiraVez.get(i.serie) })) };
};

let temporizador;
let anteriores = null;
/** Consulta de tempos em tempos; `aoSurgir(novas)` so quando aparece ONU que nao estava antes. */
export const iniciarMonitorNaoAutorizadas = ({ aoSurgir, intervaloMs = 2 * 60_000 } = {}) => {
    if (temporizador) return;
    let ultimoErro = 0;
    const ciclo = async () => {
        try {
            const { itens } = await listarNaoAutorizadas();
            const novas = selecionarNovas(itens, anteriores);
            anteriores = new Set(itens.map((i) => i.serie));
            if (novas.length) aoSurgir?.(novas);
        } catch (erro) {
            if (Date.now() - ultimoErro > 10 * 60_000) {
                ultimoErro = Date.now();
                console.warn("[OLT] ONUs não autorizadas:", erro?.codigo || erro?.message);
            }
        }
    };
    void ciclo();
    temporizador = setInterval(ciclo, Math.max(30_000, intervaloMs));
    temporizador.unref?.();
};
export const pararMonitorNaoAutorizadas = () => {
    if (temporizador) clearInterval(temporizador);
    temporizador = undefined;
    anteriores = null;
};
