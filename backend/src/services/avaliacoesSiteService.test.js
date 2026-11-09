import test from "node:test";
import assert from "node:assert/strict";
import { montarRelatorio, selecionarNovasAvaliacoes } from "./avaliacoesSiteService.js";

const item = (protocol, rating, extra = {}) => ({ protocol, rating, comment: "", answeredAt: `2026-11-0${rating}T10:00:00Z`, ticketTitle: "Sem internet", technician: "", ...extra });

test("relatório calcula média, distribuição e média por técnico", () => {
    const r = montarRelatorio([item("1", 5, { technician: "Ana" }), item("2", 3, { technician: "Ana", comment: "ok" }), item("3", 1), item("4", 9)]);
    assert.equal(r.resumo.total, 3);
    assert.equal(r.resumo.media, 3);
    assert.equal(r.resumo.comComentario, 1);
    assert.deepEqual(r.resumo.distribuicao, { 1: 1, 2: 0, 3: 1, 4: 0, 5: 1 });
    assert.equal(r.tecnicos.find((t) => t.tecnico === "Ana").media, 4);
    assert.equal(r.itens[0].protocolo, "1"); // mais recente primeiro
});

test("primeira leitura não avisa; depois só o que chegou", () => {
    const lista = montarRelatorio([item("1", 5), item("2", 4)]).itens;
    assert.deepEqual(selecionarNovasAvaliacoes(lista, null), []);
    const vistos = new Set(["1|2026-11-05T10:00:00Z"]);
    assert.deepEqual(selecionarNovasAvaliacoes(lista, vistos).map((i) => i.protocolo), ["2"]);
});
