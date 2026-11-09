import test from "node:test";
import assert from "node:assert/strict";
import { configDoRelatorio, deveEnviarRelatorio, montarRelatorio, resumirAvaliacoes, semanaAnterior } from "./relatorioSemanalService.js";
import { agruparOcorrencias, massivosDoPainel } from "./massivosHistoricoService.js";

test("semana anterior é segunda a domingo, em qualquer dia da semana seguinte", () => {
    // segunda 09/11/2026 08:30 (Brasília)
    const seg = semanaAnterior(new Date("2026-11-09T11:30:00Z"));
    assert.deepEqual([seg.de, seg.ate], ["2026-11-02", "2026-11-08"]);
    assert.deepEqual([seg.anterior.de, seg.anterior.ate], ["2026-10-26", "2026-11-01"]);
    // domingo 15/11 ainda é da semana 09–15 em andamento: a fechada é 02–08
    assert.equal(semanaAnterior(new Date("2026-11-15T15:00:00Z")).de, "2026-11-02");
    // quarta 11/11
    assert.equal(semanaAnterior(new Date("2026-11-11T15:00:00Z")).de, "2026-11-02");
});

test("só envia no dia e depois da hora combinada", () => {
    const c = configDoRelatorio({ relatorio_ativo: "1", relatorio_dia: "1", relatorio_hora: "08:30" });
    assert.equal(deveEnviarRelatorio(c, new Date("2026-11-09T11:00:00Z")), false); // 08:00
    assert.equal(deveEnviarRelatorio(c, new Date("2026-11-09T12:00:00Z")), true); // 09:00
    assert.equal(deveEnviarRelatorio(c, new Date("2026-11-10T12:00:00Z")), false); // terça
    assert.equal(deveEnviarRelatorio({ ...c, ativo: false }, new Date("2026-11-09T12:00:00Z")), false);
});

test("resume avaliações por semana e por técnico", () => {
    const itens = [
        { nota: 5, respondidoEm: "2026-11-03T10:00:00Z", tecnico: "Ana", comentario: "" },
        { nota: 4, respondidoEm: "2026-11-04T10:00:00Z", tecnico: "Ana", comentario: "" },
        { nota: 1, respondidoEm: "2026-11-05T10:00:00Z", tecnico: "", comentario: "demorou" },
        { nota: 3, respondidoEm: "2026-10-29T10:00:00Z", tecnico: "Bia", comentario: "" },
    ];
    const r = resumirAvaliacoes(itens, "2026-11-02", "2026-11-08");
    assert.equal(r.total, 3);
    assert.equal(Math.round(r.media * 100) / 100, 3.33);
    assert.equal(r.baixas, 1);
    assert.equal(r.piorComentario, "demorou");
    assert.equal(r.tecnicos[0].tecnico, "Ana");
});

test("junta retratos de massivo em ocorrências", () => {
    const t = (min) => new Date(Date.UTC(2026, 10, 3, 12, min)).toISOString();
    const o = agruparOcorrencias([
        { momento: t(0), backbone: "MRT", total: 30 }, { momento: t(5), backbone: "MRT", total: 80 }, { momento: t(10), backbone: "MRT", total: 20 },
        { momento: t(120), backbone: "MRT", total: 15 }, { momento: t(0), backbone: "DAS", total: 9 },
    ]);
    assert.equal(o.length, 3);
    const mrt = o.filter((x) => x.backbone === "MRT");
    assert.equal(mrt[0].minutos, 15);
    assert.equal(mrt[0].pico, 80);
    assert.deepEqual(massivosDoPainel({ "BACKBONE GPON ACESSANET | PV": 4, "BACKBONE GPON ACESSANET | LRJ": 0, X: 9 }), [{ backbone: "PV", total: 4 }]);
});

test("relatório mostra cada bloco e avisa quando falta dado", () => {
    const base = { periodo: { de: "2026-11-02", ate: "2026-11-08" } };
    const completo = montarRelatorio({ ...base,
        avaliacoes: { total: 15, media: 4.27, baixas: 2, tecnicos: [{ tecnico: "Ana", n: 3, media: 5 }], piorComentario: "demorou" },
        anterior: { media: 4.6 },
        agenda: { totais: { total: 321, atendidos: 308, adiados: 10, naoAtendidos: 3, taxa: 99.1 } },
        massivos: { ocorrencias: [{ backbone: "MRT", inicio: "2026-11-03T15:00:00.000Z", minutos: 80, pico: 120 }], registradoDesde: "2026-10-01T00:00:00Z" },
        contratacoes: { total: 2, byPlan: [{ label: "Plano 700 Mega", value: 2 }] } });
    assert.match(completo, /02\/11 a 08\/11/);
    assert.match(completo, /nota média 4,3 em 15 avaliações \(caiu 0,3/);
    assert.match(completo, /2 notas baixas/);
    assert.match(completo, /3 chamados ficaram sem atendimento/);
    assert.match(completo, /1 ocorrência/);
    assert.match(completo, /1 h 20/);
    assert.match(completo, /2 pedidos, Plano 700 Mega \(2\)/);
    const vazio = montarRelatorio({ ...base, avaliacoes: { total: 0 }, agenda: null, massivos: { ocorrencias: [], registradoDesde: null }, contratacoes: null });
    assert.match(vazio, /nenhuma avaliação/);
    assert.match(vazio, /não consegui ler a Agenda/);
    assert.match(vazio, /só começou a ser guardado agora/);
    const aposSemana = montarRelatorio({ ...base, avaliacoes: { total: 0 }, agenda: null, massivos: { ocorrencias: [], registradoDesde: "2026-11-09T10:00:00Z" }, contratacoes: null });
    assert.match(aposSemana, /só começou a ser guardado em 09\/11/);
    const completa = montarRelatorio({ ...base, avaliacoes: { total: 0 }, agenda: null, massivos: { ocorrencias: [], registradoDesde: "2026-10-01T10:00:00Z" }, contratacoes: null });
    assert.match(completa, /nenhum registrado na semana/);
    assert.match(vazio, /não consegui ler o site/);
});
