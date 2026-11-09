// Relatório semanal da gestão, entregue pelo chat (Assistente Acessa): nota média, chamados sem atendimento,
// massivos e contratações da semana. Texto montado a partir dos números, sem IA (barato e sempre igual).
import https from "node:https";
import db from "../db/db.js";
import { criarServicoAvaliacoes } from "./avaliacoesSiteService.js";
import { criarServicoMarketing } from "./marketingSiteService.js";
import { ocorrenciasNoPeriodo } from "./massivosHistoricoService.js";
import { BOT_NOME, destinatarios, entregar, garantirBot, relogioSaoPaulo } from "./briefingService.js";
import { garantirTabelasIa, gravarConfig, lerConfig } from "./iaAdminService.js";

const AGENDA_URL = (process.env.AGENDA_TECNICOS_URL || "https://192.168.1.133:8500").replace(/\/+$/, "");
const PADRAO = { ativo: "0", dia: "1", hora: "08:30" };
const DIA_MS = 86_400_000;

export const configDoRelatorio = (cfg = {}) => ({
    ativo: (cfg.relatorio_ativo ?? PADRAO.ativo) === "1",
    dia: Math.min(6, Math.max(0, Number(cfg.relatorio_dia ?? PADRAO.dia) || 0)),
    hora: /^([01]\d|2[0-3]):[0-5]\d$/.test(cfg.relatorio_hora || "") ? cfg.relatorio_hora : PADRAO.hora,
});

/** É o dia combinado e já passou da hora? (Vale o dia todo: se o servidor estava fora às 8h30, envia ao voltar.) */
export function deveEnviarRelatorio(config, agora = new Date()) {
    if (!config.ativo) return false;
    const { dia, hora } = relogioSaoPaulo(agora);
    return dia === config.dia ? hora >= config.hora : false;
}

const iso = (d) => d.toISOString().slice(0, 10);
const br = (s) => `${s.slice(8, 10)}/${s.slice(5, 7)}`;
const semana = (d) => ({ de: iso(d), ate: iso(new Date(d.getTime() + 6 * DIA_MS)) });

/** Semana fechada mais recente: segunda a domingo antes de `agora` (horário de Brasília). */
export function semanaAnterior(agora = new Date()) {
    const hoje = new Date(`${new Intl.DateTimeFormat("en-CA", { timeZone: "America/Sao_Paulo" }).format(agora)}T00:00:00Z`);
    const diaSemana = hoje.getUTCDay(); // 0 = domingo
    const segundaDestaSemana = new Date(hoje.getTime() - ((diaSemana + 6) % 7) * DIA_MS);
    const inicio = new Date(segundaDestaSemana.getTime() - 7 * DIA_MS);
    return { ...semana(inicio), anterior: semana(new Date(inicio.getTime() - 7 * DIA_MS)) };
}

const casas = (n) => (n == null ? "—" : Number(n).toLocaleString("pt-BR", { minimumFractionDigits: 1, maximumFractionDigits: 1 }));
const duracao = (min) => (min < 60 ? `${min} min` : `${Math.floor(min / 60)} h${min % 60 ? ` ${String(min % 60).padStart(2, "0")}` : ""}`);
const plural = (n, um, varios) => `${n} ${n === 1 ? um : varios}`;

/** Média e totais das avaliações respondidas entre duas datas (AAAA-MM-DD, inclusive). */
export function resumirAvaliacoes(itens, de, ate) {
    const na = itens.filter((i) => { const d = String(i.respondidoEm).slice(0, 10); return d >= de && d <= ate; });
    const soma = na.reduce((s, i) => s + i.nota, 0);
    const porTec = new Map();
    for (const i of na) { if (!i.tecnico) continue; const t = porTec.get(i.tecnico) || { tecnico: i.tecnico, n: 0, soma: 0 }; t.n += 1; t.soma += i.nota; porTec.set(i.tecnico, t); }
    return {
        total: na.length, media: na.length ? soma / na.length : null,
        baixas: na.filter((i) => i.nota <= 2).length,
        tecnicos: [...porTec.values()].map((t) => ({ tecnico: t.tecnico, n: t.n, media: t.soma / t.n })).sort((a, b) => b.media - a.media),
        piorComentario: na.filter((i) => i.nota <= 2 && i.comentario)[0]?.comentario || "",
    };
}

/** Texto final. Cada bloco que não teve dado diz isso em vez de sumir, para ninguém achar que esqueceram. */
export function montarRelatorio({ periodo, avaliacoes, anterior, agenda, massivos, contratacoes }) {
    const L = [`📊 Resumo da semana, de ${br(periodo.de)} a ${br(periodo.ate)}`, ""];

    if (avaliacoes?.total) {
        const var_ = anterior?.media != null ? avaliacoes.media - anterior.media : null;
        const seta = var_ == null ? "" : Math.abs(var_) < 0.05 ? " (igual à semana anterior)" : ` (${var_ > 0 ? "subiu" : "caiu"} ${casas(Math.abs(var_))} desde a semana anterior)`;
        L.push(`⭐ Atendimento: nota média ${casas(avaliacoes.media)} em ${plural(avaliacoes.total, "avaliação", "avaliações")}${seta}.`);
        if (avaliacoes.baixas) L.push(`   ${plural(avaliacoes.baixas, "nota baixa (1 ou 2)", "notas baixas (1 ou 2)")}${avaliacoes.piorComentario ? `. Um cliente disse: “${avaliacoes.piorComentario.slice(0, 140)}”` : ""}.`);
        const comNome = avaliacoes.tecnicos.filter((t) => t.n >= 2);
        if (comNome.length) L.push(`   Melhor nota: ${comNome[0].tecnico} (${casas(comNome[0].media)}, ${comNome[0].n} avaliações).`);
    } else L.push("⭐ Atendimento: nenhuma avaliação respondida nessa semana.");

    if (agenda?.totais) {
        const t = agenda.totais;
        L.push(`🛠️ Visitas técnicas: ${t.total} agendadas, ${t.atendidos} atendidas${t.taxa != null ? ` (${casas(t.taxa)}%)` : ""}, ${t.adiados} adiadas.`);
        L.push(t.naoAtendidos ? `   ⚠️ ${plural(t.naoAtendidos, "chamado ficou sem atendimento", "chamados ficaram sem atendimento")} (atrasados).` : "   Nenhum chamado atrasado.");
    } else L.push("🛠️ Visitas técnicas: não consegui ler a Agenda de Técnicos agora.");

    if (massivos) {
        const desde = massivos.registradoDesde ? String(massivos.registradoDesde).slice(0, 10) : null;
        const incompleto = !desde || desde > periodo.de;
        if (!massivos.ocorrencias.length) {
            L.push(incompleto
                ? `📡 Massivos: o histórico só começou a ser guardado ${desde ? `em ${br(desde)}` : "agora"}, então esta semana não tem como ser contada. A partir da próxima, este item mostra as ocorrências.`
                : "📡 Massivos: nenhum registrado na semana.");
        } else {
            L.push(`📡 Massivos: ${plural(massivos.ocorrencias.length, "ocorrência", "ocorrências")}${incompleto ? ` (o histórico começou em ${desde ? br(desde) : "agora"}; a semana pode estar incompleta)` : ""}.`);
            for (const o of massivos.ocorrencias.slice(0, 6)) L.push(`   ${o.backbone}: ${new Date(o.inicio).toLocaleString("pt-BR", { timeZone: "America/Sao_Paulo", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}, cerca de ${duracao(o.minutos)}, até ${o.pico} clientes.`);
            if (massivos.ocorrencias.length > 6) L.push(`   e mais ${massivos.ocorrencias.length - 6}.`);
        }
    } else L.push("📡 Massivos: histórico indisponível.");

    if (contratacoes) {
        const planos = (contratacoes.byPlan || []).slice(0, 3).map((p) => `${p.label} (${p.value})`).join(", ");
        L.push(`📝 Contratações pelo site: ${contratacoes.total} ${contratacoes.total === 1 ? "pedido" : "pedidos"}${planos ? `, ${planos}` : ""}.`);
    } else L.push("📝 Contratações pelo site: não consegui ler o site agora.");
    return L.join("\n");
}

function buscarAgenda(de, ate) {
    return new Promise((resolve, reject) => {
        const req = https.get(`${AGENDA_URL}/api/agenda-tecnicos/indicadores?de=${de}&ate=${ate}`, { rejectUnauthorized: false, timeout: 60_000 }, (res) => {
            let corpo = ""; res.setEncoding("utf8");
            res.on("data", (c) => { corpo += c; if (corpo.length > 4_000_000) req.destroy(new Error("resposta grande demais")); });
            res.on("end", () => { try { resolve(res.statusCode === 200 ? JSON.parse(corpo) : null); } catch (e) { reject(e); } });
        });
        req.on("timeout", () => req.destroy(new Error("tempo esgotado")));
        req.on("error", reject);
    });
}

export async function coletarSemana(empresaId, agora = new Date(), deps = {}) {
    const { avaliacoes = criarServicoAvaliacoes(), marketing = criarServicoMarketing(), agenda = buscarAgenda, massivos = ocorrenciasNoPeriodo } = deps;
    const p = semanaAnterior(agora);
    const limiteIso = (d) => new Date(new Date(`${d}T00:00:00-03:00`).getTime()).toISOString();
    const depoisIso = (d) => new Date(new Date(`${d}T00:00:00-03:00`).getTime() + DIA_MS).toISOString();
    const [av, ag, ms, ct] = await Promise.allSettled([
        avaliacoes.listar("30d"),
        agenda(p.de, p.ate),
        massivos(empresaId, limiteIso(p.de), depoisIso(p.ate)),
        marketing.resumo({ periodo: "custom", de: p.de, ate: p.ate }),
    ]);
    const itens = av.status === "fulfilled" ? av.value.itens : [];
    return {
        periodo: p,
        avaliacoes: av.status === "fulfilled" ? resumirAvaliacoes(itens, p.de, p.ate) : null,
        anterior: av.status === "fulfilled" ? resumirAvaliacoes(itens, p.anterior.de, p.anterior.ate) : null,
        agenda: ag.status === "fulfilled" ? ag.value : null,
        massivos: ms.status === "fulfilled" ? ms.value : null,
        contratacoes: ct.status === "fulfilled" ? ct.value.contracts ?? null : null,
    };
}

export async function enviarRelatorio({ io, empresaId, para = null, agora = new Date(), deps = {} }) {
    const texto = montarRelatorio(await coletarSemana(empresaId, agora, deps));
    const lista = para ? [{ id: para }] : await destinatarios(empresaId);
    if (!lista.length) return { enviados: 0, texto };
    const botId = await garantirBot(empresaId);
    let enviados = 0;
    for (const d of lista) { try { await entregar({ io, botId, para: d.id, texto }); enviados += 1; } catch (e) { console.error("[relatorio] entrega falhou:", e?.message); } }
    return { enviados, texto };
}

/** Confere a cada minuto; INSERT IGNORE garante um único envio por semana, mesmo com reinício. */
export function iniciarRelatorioSemanal(io, { empresaId = 1, intervaloMs = 60_000 } = {}) {
    const tick = async () => {
        try {
            await garantirTabelasIa();
            const config = configDoRelatorio(await lerConfig(empresaId));
            const agora = new Date();
            if (!deveEnviarRelatorio(config, agora)) return;
            await db.query("CREATE TABLE IF NOT EXISTS relatorio_envios (empresa_id INT NOT NULL, semana VARCHAR(10) NOT NULL, quantidade INT NOT NULL DEFAULT 0, PRIMARY KEY (empresa_id, semana))");
            const { de } = semanaAnterior(agora);
            const [r] = await db.query("INSERT IGNORE INTO relatorio_envios (empresa_id, semana, quantidade) VALUES (?, ?, 0)", [empresaId, de]);
            if (!r.affectedRows) return;
            const { enviados } = await enviarRelatorio({ io, empresaId, agora });
            await db.query("UPDATE relatorio_envios SET quantidade = ? WHERE empresa_id = ? AND semana = ?", [enviados, empresaId, de]);
        } catch (e) { console.error("[relatorio] falhou:", e?.message); }
    };
    const timer = setInterval(tick, intervaloMs);
    timer.unref?.();
    return () => clearInterval(timer);
}

export { BOT_NOME, gravarConfig };
