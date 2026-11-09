// Avaliações do atendimento (nota 1-5 + comentário) respondidas no site/app, para a aba Avaliações do Workspace.
// Usa o feed do site (/api/integracoes/avaliacoes) com o mesmo token do feed de contratações; o token fica só aqui.
import { ErroMarketing } from "./marketingSiteService.js";

const CACHE_MS = 30_000;
const TIMEOUT_MS = 12_000;
const DIAS = { "7d": 7, "30d": 30, "90d": 90, "365d": 365 };

const lerConfig = (env) => ({
    url: (env.AVALIACOES_FEED_URL || "https://acessanet.com.br/api/integracoes/avaliacoes").trim(),
    token: (env.CONTRATACOES_FEED_TOKEN || "").trim(),
});
const texto = (v, n = 600) => String(v ?? "").trim().slice(0, n);
const arred = (n) => Math.round(n * 100) / 100;

export function montarRelatorio(itens) {
    const lista = itens
        .map((i) => ({
            protocolo: texto(i?.protocol, 40),
            nota: Number(i?.rating),
            comentario: texto(i?.comment),
            respondidoEm: texto(i?.answeredAt, 40),
            assunto: texto(i?.ticketTitle, 160),
            tecnico: texto(i?.technician, 120),
            contrato: texto(i?.contractId, 40),
        }))
        .filter((i) => Number.isInteger(i.nota) && i.nota >= 1 && i.nota <= 5)
        .sort((a, b) => b.respondidoEm.localeCompare(a.respondidoEm));
    const distribuicao = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
    const porTecnico = new Map();
    let soma = 0;
    let comComentario = 0;
    for (const a of lista) {
        distribuicao[a.nota] += 1;
        soma += a.nota;
        if (a.comentario) comComentario += 1;
        const nome = a.tecnico || "Sem técnico informado";
        const t = porTecnico.get(nome) || { tecnico: nome, avaliacoes: 0, soma: 0 };
        t.avaliacoes += 1;
        t.soma += a.nota;
        porTecnico.set(nome, t);
    }
    return {
        resumo: { total: lista.length, media: lista.length ? arred(soma / lista.length) : null, comComentario, distribuicao },
        tecnicos: [...porTecnico.values()]
            .map(({ soma: s, ...t }) => ({ ...t, media: arred(s / t.avaliacoes) }))
            .sort((a, b) => b.media - a.media || b.avaliacoes - a.avaliacoes),
        itens: lista.slice(0, 300),
    };
}

export function criarServicoAvaliacoes({ env = process.env, fetchImpl = globalThis.fetch, agora = () => Date.now() } = {}) {
    const cache = new Map();
    return {
        async listar(periodo = "30d") {
            const dias = DIAS[periodo] || 30;
            const { url, token } = lerConfig(env);
            if (!token) throw new ErroMarketing(503, "A integração com as avaliações do site ainda não foi configurada.");
            const desde = new Date(agora() - dias * 86400000 - 3 * 3600000).toISOString().slice(0, 10);
            const alvo = new URL(url);
            alvo.searchParams.set("desde", desde);
            const guardado = cache.get(alvo.href);
            if (guardado && agora() - guardado.em < CACHE_MS) return guardado.dados;
            let resposta;
            try {
                resposta = await fetchImpl(alvo, {
                    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
                    signal: AbortSignal.timeout(TIMEOUT_MS),
                    redirect: "error",
                });
            } catch {
                throw new ErroMarketing(502, "O site não respondeu. Tente novamente em instantes.");
            }
            if (resposta.status === 401) throw new ErroMarketing(502, "O site recusou o acesso: confira o token da integração.");
            if (!resposta.ok) throw new ErroMarketing(502, "O site não conseguiu responder agora.");
            const payload = await resposta.json();
            const dados = { periodo: `${dias}d`, ...montarRelatorio(Array.isArray(payload?.items) ? payload.items : []) };
            cache.set(alvo.href, { em: agora(), dados });
            if (cache.size > 10) cache.clear();
            return dados;
        },
    };
}

export const SALA_AVALIACOES = "avaliacoes";
const EVENTO_NOVA = "avaliacoes:nova";

/** Itens que ainda não estavam na leitura anterior; `vistos` null = primeira leitura (nada é "novo"). */
export function selecionarNovasAvaliacoes(itens, vistos) {
    if (!vistos) return [];
    return itens.filter((i) => !vistos.has(`${i.protocolo}|${i.respondidoEm}`));
}

/** Consulta o site de tempos em tempos e avisa a sala "avaliacoes" quando chega avaliação nova. */
export function iniciarAvaliacoesNovas(io, { servico = criarServicoAvaliacoes(), env = process.env } = {}) {
    if (!(env.CONTRATACOES_FEED_TOKEN || "").trim()) return () => {};
    const intervalo = Math.max(30_000, Number(env.AVALIACOES_POLL_MS || 60_000));
    let vistos = null;
    let parado = false;
    let timer;
    const ciclo = async () => {
        try {
            const { itens } = await servico.listar("7d");
            const novas = selecionarNovasAvaliacoes(itens, vistos);
            vistos = new Set(itens.map((i) => `${i.protocolo}|${i.respondidoEm}`));
            if (novas.length) io.to(SALA_AVALIACOES).emit(EVENTO_NOVA, { itens: novas.slice(0, 5), total: novas.length });
        } catch (e) {
            if (vistos) console.error("Avaliações: site indisponível:", e?.message);
        }
        if (!parado) timer = setTimeout(ciclo, intervalo);
    };
    ciclo();
    return () => { parado = true; clearTimeout(timer); };
}
