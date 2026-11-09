// Painel de saúde: confere se cada peça do Workspace está respondendo e quanto demora.
// Cada teste tem limite de tempo próprio e nunca derruba os outros.
import https from "node:https";
import net from "node:net";
import db from "../db/db.js";
import { consultarContratosUra } from "./sgpCustomerService.js";
import { indiceTelefones } from "./indiceTelefonesService.js";

const LENTO_MS = { indiceTelefones: 800, banco: 300, chat: 300, feedSite: 2500, sgp: 4000, atualizacoes: 1500, agenda: 1500, dashboard: 1500 };
const TIMEOUT_MS = 7000;

const com = (ms, promessa, rotulo) => Promise.race([
    promessa,
    new Promise((_, rej) => setTimeout(() => rej(new Error(`${rotulo} não respondeu em ${Math.round(ms / 1000)} s`)), ms)),
]);

/** Roda um teste e mede o tempo. `fn` devolve um texto de detalhe ou lança erro. */
export async function medir(id, nome, fn, { agora = () => Date.now() } = {}) {
    const ini = agora();
    try {
        const detalhe = await com(TIMEOUT_MS, Promise.resolve().then(fn), nome);
        const ms = agora() - ini;
        const limite = LENTO_MS[id];
        return { id, nome, estado: limite && ms > limite ? "lento" : "ok", ms, detalhe: detalhe || "" };
    } catch (e) {
        return { id, nome, estado: "falha", ms: agora() - ini, detalhe: String(e?.message || "Falhou").slice(0, 160) };
    }
}

function httpsInterno(url) {
    return new Promise((resolve, reject) => {
        const req = https.get(url, { rejectUnauthorized: false, timeout: TIMEOUT_MS - 500 }, (res) => {
            let corpo = "";
            res.on("data", (d) => { if (corpo.length < 4000) corpo += d; });
            res.on("end", () => resolve({ status: res.statusCode, corpo }));
        });
        req.on("timeout", () => req.destroy(new Error("sem resposta")));
        req.on("error", reject);
    });
}

const portaAberta = (host, porta) => new Promise((resolve, reject) => {
    const s = net.connect({ host, port: porta, timeout: TIMEOUT_MS - 500 });
    s.on("connect", () => { s.destroy(); resolve(`porta ${porta} aberta`); });
    s.on("timeout", () => { s.destroy(); reject(new Error(`porta ${porta} sem resposta`)); });
    s.on("error", (e) => reject(new Error(`porta ${porta}: ${e.code || e.message}`)));
});

export function criarServicoSaude({ env = process.env, banco = db, fetchImpl = globalThis.fetch, sgp = consultarContratosUra, agora = () => Date.now(), inicio = Date.now(), indice = indiceTelefones } = {}) {
    const testes = () => {
        const feedUrl = (env.AVALIACOES_FEED_URL || "https://acessanet.com.br/api/integracoes/avaliacoes").trim();
        const token = (env.CONTRATACOES_FEED_TOKEN || "").trim();
        const updatesUrl = (env.UPDATES_HEALTH_URL || "https://192.168.1.133:8643/windows/stable/latest.yml").trim();
        return [
            ["chat", "Servidor do chat", async () => {
                const mem = Math.round(process.memoryUsage().rss / 1048576);
                const min = Math.round((agora() - inicio) / 60000);
                return `no ar há ${min >= 120 ? `${Math.round(min / 60)} h` : `${min} min`} · ${mem} MB${env.AMBIENTE_TESTE === "1" ? " · AMBIENTE DE TESTES" : ""}`;
            }],
            ["banco", "Banco de dados", async () => {
                const [r] = await banco.query("SELECT DATABASE() AS banco, (SELECT COUNT(*) FROM usuarios WHERE deletado_em IS NULL) AS usuarios");
                return `${r[0].banco} · ${r[0].usuarios} usuários`;
            }],
            ["feedSite", "Site (avaliações e contratações)", async () => {
                if (!token) throw new Error("token do feed não configurado");
                const u = new URL(feedUrl); u.searchParams.set("desde", new Date().toISOString().slice(0, 10));
                const r = await fetchImpl(u, { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(TIMEOUT_MS - 500), redirect: "error" });
                if (r.status === 401) throw new Error("o site recusou o token");
                if (!r.ok) throw new Error(`o site respondeu HTTP ${r.status}`);
                return "feed respondendo";
            }],
            ["sgp", "SGP", async () => {
                const contratos = await sgp({ contrato: env.SAUDE_SGP_CONTRATO || "3005" });
                if (!Array.isArray(contratos)) throw new Error("resposta inesperada");
                return contratos.length ? "consulta de cliente respondendo" : "respondeu, mas sem o contrato de teste";
            }],
            ["atualizacoes", "Servidor de atualizações", async () => {
                const r = await httpsInterno(updatesUrl);
                if (r.status !== 200) throw new Error(`HTTP ${r.status}`);
                const v = /^version:\s*([\d.]+)/m.exec(r.corpo)?.[1];
                return v ? `versão publicada ${v}` : "respondendo";
            }],
            ["indiceTelefones", "Índice de telefones (SGP)", async () => {
                const e = await indice.estatisticas(env.EMPRESA_ID || 1);
                if (!e.total) throw new Error("vazio: a atualização noturna ainda não rodou");
                const h = e.atualizadoEm ? Math.round((agora() - new Date(e.atualizadoEm).getTime()) / 3600000) : null;
                if (h !== null && h > 48) throw new Error(`${e.total} números, mas sem atualizar há ${h} h`);
                return `${e.total.toLocaleString("pt-BR")} números${h !== null ? ` · atualizado há ${h} h` : ""}`;
            }],
            ["agenda", "Agenda de técnicos", () => portaAberta("192.168.1.133", 8500)],
            ["dashboard", "Painel NOC", () => portaAberta("192.168.1.133", 5000)],
        ];
    };
    return {
        async verificar() {
            const itens = await Promise.all(testes().map(([id, nome, fn]) => medir(id, nome, fn, { agora })));
            const falhas = itens.filter((i) => i.estado === "falha").length;
            const lentos = itens.filter((i) => i.estado === "lento").length;
            return { verificadoEm: new Date(agora()).toISOString(), geral: falhas ? "falha" : lentos ? "lento" : "ok", falhas, lentos, ambienteTeste: env.AMBIENTE_TESTE === "1", itens };
        },
    };
}
