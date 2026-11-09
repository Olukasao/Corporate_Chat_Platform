// Integração SOMENTE LEITURA com a OLT Cloud (alertas de rede e equipamentos), portada do acessanet-lab.
// Credenciais só neste servidor (env): OLTCLOUD_BASE_URL e OLTCLOUD_TOKEN, ou OLTCLOUD_USERNAME + OLTCLOUD_PASSWORD.
// Nenhum método faz POST/PUT/DELETE na OLT Cloud (exceto o login/refresh de token), e nada que contenha
// credencial de cliente (pppoe, senha) é devolvido a quem chama.

const MARGEM_EXPIRACAO_MS = 30_000;
const TTL_TOKEN_PADRAO_MS = 5 * 60_000;
const PAGINAS_MAXIMAS = 200;
const TTL_INCIDENTES_MS = 25_000;
export const TIPOS_CONHECIDOS = ["pon_loss", "pon_down", "pon_no_power", "cto_loss", "cto_no_power", "no_power"];

const lerConfig = () => ({
    baseUrl: String(process.env.OLTCLOUD_BASE_URL || "").trim().replace(/\/+$/, ""),
    token: String(process.env.OLTCLOUD_TOKEN || "").trim(),
    usuario: String(process.env.OLTCLOUD_USERNAME || "").trim(),
    senha: String(process.env.OLTCLOUD_PASSWORD || ""),
    timeoutMs: Math.max(3000, Number(process.env.OLTCLOUD_TIMEOUT_MS) || 15_000),
});

export const oltCloudConfigurada = () => {
    const c = lerConfig();
    return Boolean(c.baseUrl && (c.token || (c.usuario && c.senha)));
};

export class OltCloudError extends Error {
    constructor(codigo, mensagem, status = 502) {
        super(mensagem);
        this.codigo = codigo;
        this.status = status;
    }
}

const expiracaoJwt = (token) => {
    try {
        const parte = String(token).split(".")[1];
        const normal = parte.replace(/-/g, "+").replace(/_/g, "/");
        const dados = JSON.parse(Buffer.from(normal + "=".repeat((4 - (normal.length % 4)) % 4), "base64").toString("utf8"));
        return typeof dados.exp === "number" ? dados.exp * 1000 : undefined;
    } catch {
        return undefined;
    }
};

const comTimeout = async (url, opcoes, timeoutMs) => {
    const controle = new AbortController();
    const timer = setTimeout(() => controle.abort(), timeoutMs);
    try {
        return await fetch(url, { ...opcoes, signal: controle.signal });
    } catch (erro) {
        throw new OltCloudError(
            erro?.name === "AbortError" ? "OLTCLOUD_TIMEOUT" : "OLTCLOUD_REQUEST_FAILED",
            erro?.name === "AbortError" ? "Tempo limite ao consultar a OLT Cloud." : "Não foi possível consultar a OLT Cloud agora."
        );
    } finally {
        clearTimeout(timer);
    }
};

// ---- autenticação (login/refresh JWT quando não há token fixo) ----
const sessao = { acesso: "", acessoAte: 0, refresh: "", refreshAte: 0, emAndamento: null };

const postarToken = async (c, caminho, corpo) => {
    const resposta = await comTimeout(`${c.baseUrl}${caminho}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(corpo),
    }, c.timeoutMs);
    if (!resposta.ok) throw new OltCloudError("OLTCLOUD_AUTH_FAILED", "Credenciais da OLT Cloud inválidas ou expiradas.");
    try {
        return await resposta.json();
    } catch {
        throw new OltCloudError("OLTCLOUD_AUTH_FAILED", "Resposta de autenticação inválida da OLT Cloud.");
    }
};

const renovarToken = async (c) => {
    if (sessao.refresh && Date.now() < sessao.refreshAte - MARGEM_EXPIRACAO_MS) {
        try {
            const corpo = await postarToken(c, "/api/token/refresh", { refresh: sessao.refresh });
            if (corpo.access) {
                sessao.acesso = corpo.access;
                sessao.acessoAte = expiracaoJwt(corpo.access) ?? Date.now() + TTL_TOKEN_PADRAO_MS;
                return sessao.acesso;
            }
        } catch { /* refresh revogado: cai para o login completo */ }
    }
    const corpo = await postarToken(c, "/api/token", { username: c.usuario, password: c.senha });
    if (!corpo.access || !corpo.refresh) throw new OltCloudError("OLTCLOUD_AUTH_FAILED", "Resposta de login inválida da OLT Cloud.");
    sessao.acesso = corpo.access;
    sessao.acessoAte = expiracaoJwt(corpo.access) ?? Date.now() + TTL_TOKEN_PADRAO_MS;
    sessao.refresh = corpo.refresh;
    sessao.refreshAte = expiracaoJwt(corpo.refresh) ?? Date.now() + TTL_TOKEN_PADRAO_MS;
    return sessao.acesso;
};

const obterToken = async (c, forcar) => {
    if (c.token) return c.token;
    if (forcar) sessao.acessoAte = 0;
    if (sessao.acesso && Date.now() < sessao.acessoAte - MARGEM_EXPIRACAO_MS) return sessao.acesso;
    sessao.emAndamento ??= renovarToken(c).finally(() => { sessao.emAndamento = null; });
    return sessao.emAndamento;
};

const get = async (urlOuCaminho, tentativa = 0) => {
    const c = lerConfig();
    if (!oltCloudConfigurada()) throw new OltCloudError("OLTCLOUD_NOT_CONFIGURED", "Integração com a OLT Cloud não configurada.", 503);
    const url = /^https?:\/\//i.test(urlOuCaminho) ? urlOuCaminho : `${c.baseUrl}${urlOuCaminho.startsWith("/") ? "" : "/"}${urlOuCaminho}`;
    // Segue só links da própria OLT Cloud (campo "next" da paginação).
    if (new URL(url).origin !== new URL(c.baseUrl).origin) throw new OltCloudError("OLTCLOUD_INVALID_RESPONSE", "Resposta inválida da OLT Cloud.");
    const resposta = await comTimeout(url, {
        method: "GET",
        headers: { Authorization: `Bearer ${await obterToken(c, tentativa > 0)}`, "Content-Type": "application/json" },
    }, c.timeoutMs);
    if (resposta.status === 401) {
        if (tentativa === 0 && !c.token) return get(urlOuCaminho, 1);
        throw new OltCloudError("OLTCLOUD_UNAUTHORIZED", "Token da OLT Cloud inválido ou expirado.");
    }
    if (resposta.status === 403) throw new OltCloudError("OLTCLOUD_FORBIDDEN", "Usuário da OLT Cloud sem permissão para este recurso.");
    if (!resposta.ok) throw new OltCloudError("OLTCLOUD_UPSTREAM_ERROR", "Erro na API da OLT Cloud.");
    try {
        return await resposta.json();
    } catch {
        throw new OltCloudError("OLTCLOUD_INVALID_RESPONSE", "Resposta inválida da OLT Cloud.");
    }
};

const listaDe = (resposta, chaves) => {
    if (Array.isArray(resposta)) return resposta;
    if (resposta && typeof resposta === "object") for (const k of chaves) if (Array.isArray(resposta[k])) return resposta[k];
    return [];
};
const proximo = (resposta) => {
    const n = resposta && typeof resposta === "object" && !Array.isArray(resposta) ? resposta.next : undefined;
    if (typeof n === "string" && n.trim()) return n.trim();
    if (typeof n === "number" && Number.isFinite(n)) return n;
    return undefined;
};
const parametros = (filtros) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries(filtros)) if (v !== undefined && v !== null && String(v) !== "") p.set(k, String(v));
    return p.toString();
};
// A API pode paginar: nunca assumir que a primeira página tem tudo.
const todasAsPaginas = async (caminho, filtros, chaves, tamanhoPagina) => {
    const resultado = [];
    let proximaUrl;
    let pagina = 1;
    for (let i = 0; i < PAGINAS_MAXIMAS; i++) {
        const resposta = proximaUrl
            ? await get(proximaUrl)
            : await get(`${caminho}?${parametros({ ...filtros, page_size: tamanhoPagina, page: pagina > 1 ? pagina : undefined })}`);
        resultado.push(...listaDe(resposta, chaves));
        const n = proximo(resposta);
        if (n === undefined) break;
        if (typeof n === "string") { proximaUrl = n; pagina += 1; }
        else { if (n === pagina) break; pagina = n; proximaUrl = undefined; }
    }
    return resultado;
};

const texto = (obj, campos) => {
    for (const c of campos) {
        const v = obj?.[c];
        if (v !== undefined && v !== null && String(v).trim()) return String(v).trim();
    }
    return "";
};
const numero = (obj, campo) => {
    const v = Number(obj?.[campo]);
    return obj?.[campo] === null || obj?.[campo] === undefined || obj?.[campo] === "" || !Number.isFinite(v) ? null : v;
};

export const normalizarAlerta = (bruto = {}) => ({
    id: texto(bruto, ["id"]),
    tipo: texto(bruto, ["alert_type"]),
    oltId: texto(bruto, ["olt_id"]),
    olt: texto(bruto, ["olt_name"]),
    inicio: texto(bruto, ["initial_date"]) || null,
    confirmadoEm: texto(bruto, ["confirm_date"]) || null,
    fim: texto(bruto, ["end_date"]) || null,
    ignorado: bruto.ignored === true || bruto.ignored === "true",
    descricao: texto(bruto, ["description"]),
    totalDispositivos: numero(bruto, "total_devices_count"),
    dispositivosAtivos: numero(bruto, "active_devices_count"),
    ponId: texto(bruto, ["pon_id"]),
    pon: texto(bruto, ["pon"]),
    slotPon: texto(bruto, ["slot_pon"]),
    ctoId: texto(bruto, ["cto_id"]),
    cto: texto(bruto, ["cto_name"]),
});

/**
 * Incidentes muito pequenos (ex.: uma PON com 1 cliente, 1 de 1) são ruído: ficam fora da lista e dos avisos.
 * Mínimo de clientes afetados configurável por OLT_MIN_CLIENTES_INCIDENTE (padrão 2). Sem contagem informada
 * pela OLT Cloud, o incidente é mantido (melhor ver demais do que perder uma queda real).
 */
export const minimoClientesIncidente = () => {
    const n = Number(process.env.OLT_MIN_CLIENTES_INCIDENTE);
    return Number.isInteger(n) && n >= 1 ? n : 2;
};
export const incidenteRelevante = (a) => a.dispositivosAtivos === null || a.dispositivosAtivos >= minimoClientesIncidente();

/**
 * Incidente "ativo": ainda sem data de fim, não ignorado pela operação e, se houver contagem,
 * com ao menos um dispositivo afetado (a OLT Cloud às vezes demora a preencher o fim).
 */
export const incidenteAtivo = (a) => !a.fim && !a.ignorado && !(a.dispositivosAtivos !== null && a.dispositivosAtivos <= 0);

const GRAVIDADE = { pon_loss: 0, pon_down: 0, pon_no_power: 1, cto_loss: 2, cto_no_power: 3, no_power: 3 };
const ordenar = (a, b) =>
    (GRAVIDADE[a.tipo] ?? 3) - (GRAVIDADE[b.tipo] ?? 3) ||
    (b.dispositivosAtivos ?? 0) - (a.dispositivosAtivos ?? 0) ||
    String(a.inicio || "").localeCompare(String(b.inicio || ""));

let cacheIncidentes = { ate: 0, valor: null, pendente: null };

const TAMANHO_PAGINA_ALERTAS = 500;
const PAGINAS_RECENTES = 2; // ~1000 alertas mais novos (cerca de 2 semanas): incidente aberto há mais que isso é raro
/**
 * A OLT Cloud lista os alertas do mais ANTIGO para o mais novo (hoje são ~28 mil). Ler só a primeira página
 * devolve alertas de anos atrás, todos encerrados. Por isso lê a contagem e busca as últimas páginas.
 */
const listarAlertasRecentes = async () => {
    const caminho = "/api/v2/ftth/alert/list";
    const sonda = await get(`${caminho}?page_size=1`);
    const total = sonda && typeof sonda === "object" && !Array.isArray(sonda) ? Number(sonda.count) : NaN;
    // Sem contagem (API sem paginação): a lista inteira já veio.
    if (!Number.isFinite(total) || total <= 0) return listaDe(sonda, ["data", "alerts", "items", "results"]);
    const ultima = Math.max(1, Math.ceil(total / TAMANHO_PAGINA_ALERTAS));
    const paginas = [];
    for (let n = Math.max(1, ultima - PAGINAS_RECENTES + 1); n <= ultima; n++) paginas.push(n);
    const respostas = await Promise.all(paginas.map((n) => get(`${caminho}?${parametros({ page_size: TAMANHO_PAGINA_ALERTAS, page: n })}`)));
    return respostas.flatMap((r) => listaDe(r, ["data", "alerts", "items", "results"]));
};

/** Incidentes de rede ativos (cache curto; várias pessoas consultando não multiplicam chamadas à OLT Cloud). */
export const listarIncidentesAtivos = async ({ forcar = false } = {}) => {
    if (!forcar && cacheIncidentes.valor && Date.now() < cacheIncidentes.ate) return cacheIncidentes.valor;
    cacheIncidentes.pendente ??= (async () => {
        const alertas = await listarAlertasRecentes();
        const incidentes = alertas.map(normalizarAlerta).filter((a) => a.id && incidenteAtivo(a) && incidenteRelevante(a)).sort(ordenar);
        const valor = { atualizadoEm: new Date().toISOString(), incidentes };
        cacheIncidentes = { ate: Date.now() + TTL_INCIDENTES_MS, valor, pendente: null };
        return valor;
    })().finally(() => { cacheIncidentes.pendente = null; });
    return cacheIncidentes.pendente;
};

/** "Online" é o único estado saudável; "Sem Energia", "LOSS" (e "Offline", se existir) contam como afetados. */
export const equipamentoAfetado = (status) => {
    const t = String(status || "").trim().toLowerCase();
    return t !== "" && t !== "online";
};

/** slot_pon vem como "6/14" (slot/PON); o filtro de equipamentos usa os dois separados. */
const slotEPon = (incidente) => {
    const [slot, pon] = String(incidente.slotPon || "").split("/").map((p) => p.trim());
    return { slot: slot || "", pon: pon || incidente.pon || "" };
};

/** Equipamentos cadastrados para um contrato (a OLT Cloud filtra por "contém": quem chama confere o contrato exato). */
export const equipamentosDoContrato = async (contrato) => {
    const id = String(contrato ?? "").replace(/\D/g, "").slice(0, 20);
    if (!id) return [];
    const resposta = await get(`/api/v2/ftth/equipment/list?${parametros({ external_client_contract_id: id, page_size: 50 })}`);
    return listaDe(resposta, ["data", "equipment", "items", "results"]);
};

/** Equipamentos afetados (sem energia / LOSS) de uma PON; nunca os online. */
export const listarEquipamentosOffline = async (incidente) => {
    const { slot, pon } = slotEPon(incidente);
    const filtros = slot && pon
        ? { olt_id: incidente.oltId, slot, pon }
        : { olt_id: incidente.oltId, pon_id: incidente.ponId || incidente.pon };
    const brutos = await todasAsPaginas("/api/v2/ftth/equipment/list", filtros, ["data", "equipment", "items", "results"], 1000);
    return brutos
        .map((e) => ({
            contrato: texto(e, ["external_client_contract_id"]),
            serie: texto(e, ["serial_number"]),
            status: texto(e, ["status"]),
            ultimaQueda: texto(e, ["last_disconnection"]) || null,
            ultimaAtualizacao: texto(e, ["last_status_update"]) || null,
        }))
        .filter((e) => equipamentoAfetado(e.status));
};

// ---- panorama: quantos clientes estão afetados AGORA (evento regional de energia, LOSS), por OLT e por PON ----
const TTL_PANORAMA_MS = 25_000;
let cachePanorama = { ate: 0, valor: null, pendente: null };
const contar = async (filtros) => {
    const r = await get(`/api/v2/ftth/equipment/list?${parametros({ ...filtros, page_size: 1 })}`);
    const n = r && typeof r === "object" && !Array.isArray(r) ? Number(r.count) : NaN;
    return Number.isFinite(n) ? n : listaDe(r, ["data", "results"]).length;
};
export const resumirEquipamentos = (semEnergia, loss) => {
    const porOlt = new Map();
    const porPon = new Map();
    const somar = (lista, campo) => {
        for (const e of lista) {
            const olt = texto(e, ["olt"]) || "OLT não informada";
            const o = porOlt.get(olt) ?? { olt, semEnergia: 0, loss: 0 };
            o[campo] += 1;
            porOlt.set(olt, o);
            const slot = texto(e, ["slot"]), pon = texto(e, ["pon"]);
            const chave = `${olt}|${slot}|${pon}`;
            const p = porPon.get(chave) ?? { olt, slot, pon, semEnergia: 0, loss: 0 };
            p[campo] += 1;
            porPon.set(chave, p);
        }
    };
    somar(semEnergia, "semEnergia");
    somar(loss, "loss");
    const soma = (x) => x.semEnergia + x.loss;
    return {
        porOlt: [...porOlt.values()].sort((a, b) => soma(b) - soma(a)),
        pons: [...porPon.values()].sort((a, b) => soma(b) - soma(a)),
    };
};
/** Visão geral da rede agora (sem dados de cliente): totais por estado, por OLT e as PONs mais afetadas. */
export const obterPanorama = async ({ forcar = false } = {}) => {
    if (!forcar && cachePanorama.valor && Date.now() < cachePanorama.ate) return cachePanorama.valor;
    cachePanorama.pendente ??= (async () => {
        const base = "/api/v2/ftth/equipment/list";
        const [total, online, semEnergia, loss] = await Promise.all([
            contar({}),
            contar({ status: "Online" }),
            todasAsPaginas(base, { status: "Sem Energia" }, ["data", "equipment", "items", "results"], 1000),
            todasAsPaginas(base, { status: "LOSS" }, ["data", "equipment", "items", "results"], 1000),
        ]);
        const { porOlt, pons } = resumirEquipamentos(semEnergia, loss);
        const valor = {
            atualizadoEm: new Date().toISOString(),
            total, online,
            semEnergia: semEnergia.length,
            loss: loss.length,
            porOlt,
            pons: pons.slice(0, 15),
            totalPons: pons.length,
        };
        cachePanorama = { ate: Date.now() + TTL_PANORAMA_MS, valor, pendente: null };
        return valor;
    })().finally(() => { cachePanorama.pendente = null; });
    return cachePanorama.pendente;
};

// ---- monitor: avisa quando surge um incidente novo ----
let temporizador;
const conhecidos = new Set();
let primeiraLeitura = true;
let ultimoErroLogado = 0;

const SALTO_MASSA = 150; // aumento de clientes afetados entre leituras para considerar evento em massa
const ESPERA_MASSA_MS = 15 * 60_000;
let ultimoTotalAfetado = null;
let ultimoAvisoMassa = 0;

export const iniciarMonitorOlt = ({ aoSurgir, aoEventoMassa, intervaloMs = 30_000 } = {}) => {
    if (temporizador || !oltCloudConfigurada()) return;
    const ciclo = async () => {
        try {
            const { incidentes } = await listarIncidentesAtivos({ forcar: true });
            const ids = new Set(incidentes.map((i) => i.id));
            if (!primeiraLeitura)
                for (const incidente of incidentes) if (!conhecidos.has(incidente.id)) aoSurgir?.(incidente);
            conhecidos.clear();
            ids.forEach((id) => conhecidos.add(id));
            primeiraLeitura = false;
            // Evento regional (ex.: falta de energia): o total de clientes afetados salta entre uma leitura e outra.
            if (aoEventoMassa) {
                const p = await obterPanorama({ forcar: true });
                const afetados = p.semEnergia + p.loss;
                if (ultimoTotalAfetado !== null && afetados - ultimoTotalAfetado >= SALTO_MASSA && Date.now() - ultimoAvisoMassa > ESPERA_MASSA_MS) {
                    ultimoAvisoMassa = Date.now();
                    aoEventoMassa({ ...p, aumento: afetados - ultimoTotalAfetado });
                }
                ultimoTotalAfetado = afetados;
            }
        } catch (erro) {
            // Falha momentânea não derruba o monitor; registra no máximo 1 vez por 10 min.
            if (Date.now() - ultimoErroLogado > 10 * 60_000) {
                ultimoErroLogado = Date.now();
                console.warn("[OLT] Monitor de incidentes:", erro?.codigo || erro?.message);
            }
        }
    };
    void ciclo();
    temporizador = setInterval(ciclo, intervaloMs);
    temporizador.unref?.();
};
export const pararMonitorOlt = () => {
    if (temporizador) clearInterval(temporizador);
    temporizador = undefined;
    conhecidos.clear();
    primeiraLeitura = true;
    ultimoTotalAfetado = null;
};
