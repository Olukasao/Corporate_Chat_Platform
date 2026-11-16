// Aviso à equipe quando um cliente troca a senha do Wi-Fi pela Central do Assinante.
// Consulta o feed do site (/api/integracoes/wifi/trocas, mesmo token do feed de contratações; o token fica só aqui)
// e avisa a sala "wifi_trocas" (quem tem a área Chamados). O feed não traz senha, IP nem CPF: só quem, qual roteador e o que aconteceu.
export const SALA_WIFI_TROCAS = "wifi_trocas";
const EVENTO = "wifi:troca";

const texto = (v, n = 160) => String(v ?? "").trim().slice(0, n);

const lerConfig = (env) => ({
    url: (env.WIFI_TROCAS_FEED_URL || "https://acessanet.com.br/api/integracoes/wifi/trocas").trim(),
    token: (env.CONTRATACOES_FEED_TOKEN || "").trim(),
});

export function normalizarTrocas(itens) {
    return (Array.isArray(itens) ? itens : [])
        .map((i) => ({
            id: texto(i?.id, 60),
            contrato: texto(i?.contractId, 40),
            cliente: texto(i?.customerName, 120),
            redes: (Array.isArray(i?.bands) ? i.bands : []).map((b) => texto(b, 8)).filter(Boolean),
            roteador: [texto(i?.vendor, 32), texto(i?.model, 64)].filter(Boolean).join(" "),
            confirmacao: i?.confirmation === "connected" || i?.confirmation === "not_connected" ? i.confirmation : null,
            chamado: texto(i?.ticketProtocol, 64),
            quando: texto(i?.confirmedAt || i?.finishedAt, 40),
        }))
        .filter((i) => i.id);
}

/** O que mudou desde a leitura anterior: troca nova, ou a mesma troca com resposta nova do cliente. `vistos` null = primeira leitura. */
export function selecionarNovasTrocas(trocas, vistos) {
    if (!vistos) return [];
    return trocas.filter((t) => !vistos.has(`${t.id}|${t.confirmacao ?? ""}`));
}

export function criarServicoTrocasWifi({ env = process.env, fetchImpl = globalThis.fetch, agora = () => Date.now() } = {}) {
    return {
        async listar() {
            const { url, token } = lerConfig(env);
            if (!token) throw new Error("integração com o site não configurada");
            const alvo = new URL(url);
            alvo.searchParams.set("desde", new Date(agora() - 36 * 3600000).toISOString());
            const resposta = await fetchImpl(alvo, {
                headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
                signal: AbortSignal.timeout(12_000),
                redirect: "error",
            });
            if (!resposta.ok) throw new Error(`site respondeu ${resposta.status}`);
            return normalizarTrocas((await resposta.json())?.items);
        },
    };
}

/** Consulta o site de tempos em tempos e avisa a sala quando o cliente troca a senha (ou diz que não conseguiu conectar). */
export function iniciarTrocasWifi(io, { servico = criarServicoTrocasWifi(), env = process.env } = {}) {
    if (!(env.CONTRATACOES_FEED_TOKEN || "").trim()) return () => {};
    const intervalo = Math.max(30_000, Number(env.WIFI_TROCAS_POLL_MS || 45_000));
    let vistos = null;
    let parado = false;
    let timer;
    const ciclo = async () => {
        try {
            const trocas = await servico.listar();
            const novas = selecionarNovasTrocas(trocas, vistos);
            vistos = new Set(trocas.map((t) => `${t.id}|${t.confirmacao ?? ""}`));
            if (novas.length) io.to(SALA_WIFI_TROCAS).emit(EVENTO, { itens: novas.slice(0, 5), total: novas.length });
        } catch (e) {
            // o site pode ainda nao ter o feed (ou a funcao estar desligada); so avisa se ja tinha lido antes
            if (vistos) console.error("Trocas de Wi-Fi: site indisponível:", e?.message);
            else vistos = vistos ?? null;
        }
        if (!parado) timer = setTimeout(ciclo, intervalo);
    };
    ciclo();
    return () => { parado = true; clearTimeout(timer); };
}
