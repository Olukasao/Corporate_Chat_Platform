import test from "node:test";
import assert from "node:assert/strict";
import db from "../db/db.js";
import { compararVersao, limparDispositivosAntigos, situacaoDaVersao } from "./workspaceDispositivosService.js";

const comBanco = async (respostas, fn) => {
    const original = db.query;
    db.query = async (sql, params) => respostas(String(sql), params);
    try { return await fn(); } finally { db.query = original; }
};

test("compararVersao e situacaoDaVersao", () => {
    assert.equal(compararVersao("0.6.71", "0.6.71"), 0);
    assert.ok(compararVersao("0.6.9", "0.6.10") < 0); // não é comparação de texto
    assert.equal(situacaoDaVersao("0.6.70", "0.6.71"), "desatualizado");
    assert.equal(situacaoDaVersao("0.6.71", "0.6.71"), "atualizado");
    assert.equal(situacaoDaVersao("0.6.72", "0.6.71"), "atualizado");
    assert.equal(situacaoDaVersao(null, "0.6.71"), "desconhecida");
    assert.equal(situacaoDaVersao("0.6.71", "lixo"), "desconhecida");
});

test("limparDispositivosAntigos: apaga por inatividade (padrão 30 dias) e devolve quantos", async () => {
    let executado = null;
    const linhas = await comBanco((sql, params) => {
        if (sql.includes("CREATE TABLE")) return [[]];
        if (sql.includes("ALTER TABLE")) return [[]];
        if (sql.includes("DELETE FROM workspace_dispositivos")) {
            executado = { sql, params };
            return [{ affectedRows: 4 }];
        }
        return [[]];
    }, () => limparDispositivosAntigos());
    assert.equal(linhas, 4);
    assert.match(executado.sql, /ultimo_visto < \(NOW\(\) - INTERVAL \? DAY\)/);
    assert.deepEqual(executado.params, [30]);
});

test("limparDispositivosAntigos aceita um prazo diferente do padrão", async () => {
    let executado = null;
    await comBanco((sql, params) => {
        if (sql.includes("DELETE FROM workspace_dispositivos")) { executado = params; return [{ affectedRows: 0 }]; }
        return [[]];
    }, () => limparDispositivosAntigos(7));
    assert.deepEqual(executado, [7]);
});
