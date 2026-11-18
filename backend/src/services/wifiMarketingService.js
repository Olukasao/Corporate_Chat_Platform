// Aviso à equipe quando o Wi-Fi público do site obtém dados de marketing (alguém se cadastrou e aceitou receber ofertas).
// Consulta o feed do site (/api/integracoes/wifi/marketing, mesmo token do feed de contratações; o token fica só aqui)
// e avisa a sala "wifi_marketing" (quem tem a área Marketing). O feed traz só nome abreviado e a rede: nada de e-mail ou telefone.
export const SALA_WIFI_MARKETING = "wifi_marketing";
const EVENTO = "wifi:marketing";

const texto = (v, n = 120) => String(v ?? "").trim().slice(0, n);

const lerConfig = (env) => ({
    url: (env.WIFI_MARKETING_FEED_URL || "https://acessanet.com.br/api/integracoes/wifi/marketing").trim(),
    token: (env.CONTRATACOES_FEED_TOKEN || "").trim(),
});

export function normalizarLeads(itens) {
    return (Array.isArray(itens) ? itens : [])
        .map((i) => ({
            id: texto(i?.id, 80),
            nome: texto(i?.name, 80),
            rede: texto(i?.establishment, 80),
            quando: texto(i?.marketingConsentAt, 40),
        }))
        .filter((i) => i.id);
}

/** Chave de um aceite: a mesma pessoa que revoga e aceita de novo conta como dado novo (o horário do aceite muda). */
export const chaveLead = (l) => `${l.id}|${l.quando}`;

/** O que chegou desde a leitura anterior. `vistos` null = primeira leitura (nunca avisa o que já existia). */
export function selecionarNovosLeads(leads, vistos) {
    if (!vistos) return [];
    return leads.filter((l) => !vistos.has(chaveLead(l)));
}

export function criarServicoWifiMarketing({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
    return {
        async listar() {
            const { url, token } = lerConfig(env);
            if (!token) throw new Error("integração com o site não configurada");
            const resposta = await fetchImpl(url, {
                headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
                signal: AbortSignal.timeout(12_000),
                redirect: "error",
            });
            if (!resposta.ok) throw new Error(`site respondeu ${resposta.status}`);
            return normalizarLeads((await resposta.json())?.items);
        },
    };
}

/** Consulta o site de tempos em tempos e avisa a sala quando chega um dado de marketing novo. */
export function iniciarWifiMarketing(io, { servico = criarServicoWifiMarketing(), env = process.env } = {}) {
    if (!(env.CONTRATACOES_FEED_TOKEN || "").trim()) return () => {};
    const intervalo = Math.max(30_000, Number(env.WIFI_MARKETING_POLL_MS || 45_000));
    let vistos = null;
    let parado = false;
    let timer;
    const ciclo = async () => {
        try {
            const leads = await servico.listar();
            const novos = selecionarNovosLeads(leads, vistos);
            vistos = new Set(leads.map(chaveLead));
            if (novos.length) io.to(SALA_WIFI_MARKETING).emit(EVENTO, { itens: novos.slice(0, 5), total: novos.length });
        } catch (e) {
            // o site pode ainda não ter o feed; só reclama se já tinha lido antes
            if (vistos) console.error("Marketing do Wi-Fi: site indisponível:", e?.message);
        }
        if (!parado) timer = setTimeout(ciclo, intervalo);
    };
    ciclo();
    return () => { parado = true; clearTimeout(timer); };
}
