import test from "node:test";
import assert from "node:assert/strict";
import db from "../db/db.js";
import { definirSonsEscondidosEfeitosSonoros, filtrarSonsVisiveis, obterPermissaoEfeitosSonoros } from "./soundEffectPermissionsService.js";

const lucas = { id: 3, nome: "Lucas", email: "lucas@acessanet.com", empresa_id: 1 };
const pedro = { id: 36, nome: "Pedro", email: "pedro@acessanet.com", empresa_id: 1 };
const sons = [{ key: "bruh" }, { key: "faaaa" }, { key: "vine_boom" }];

const comBanco = async (respostas, fn) => {
    const original = db.query;
    db.query = async (sql, params) => respostas(String(sql), params);
    try { return await fn(); } finally { db.query = original; }
};

test("filtrar: quem gerencia vê tudo; os outros não veem os sons escondidos deles", () => {
    assert.deepEqual(filtrarSonsVisiveis(sons, { can_manage: true, hidden_sounds: ["bruh"] }).map((s) => s.key), ["bruh", "faaaa", "vine_boom"]);
    assert.deepEqual(filtrarSonsVisiveis(sons, { can_manage: false, hidden_sounds: ["bruh", "vine_boom"] }).map((s) => s.key), ["faaaa"]);
    assert.deepEqual(filtrarSonsVisiveis(sons, { can_manage: false }).map((s) => s.key), ["bruh", "faaaa", "vine_boom"]);
});

test("permissão: o Lucas nunca tem sons escondidos; a lista do Pedro vem do banco", async () => {
    const responder = (sql) => {
        if (sql.includes("SELECT can_use, can_manage")) return [[{ can_use: 1, can_manage: 0, max_volume_percent: 70, no_time_limit: 0, hidden_sounds: JSON.stringify(["bruh", "BRUH", "x"]) }]];
        return [[]];
    };
    const doPedro = await comBanco(responder, () => obterPermissaoEfeitosSonoros(pedro));
    assert.deepEqual(doPedro.hidden_sounds, ["bruh", "x"]);
    const doLucas = await comBanco(responder, () => obterPermissaoEfeitosSonoros(lucas));
    assert.deepEqual(doLucas.hidden_sounds, []);
});

test("esconder: só chaves de sons que existem, e não vale para o dono dos efeitos", async () => {
    let gravado = null;
    const responder = (sql, params) => {
        if (sql.includes("FROM usuarios")) return [[params[0] === 3 ? lucas : pedro]];
        if (sql.includes("INSERT INTO sound_effect_permissions")) { gravado = params; return [{}]; }
        return [[]];
    };
    const lista = await comBanco(responder, () => definirSonsEscondidosEfeitosSonoros({ usuario: lucas, targetUserId: 36, hidden: ["bruh", "nao_existe", "BRUH"] }));
    assert.deepEqual(lista, ["bruh"]);
    assert.equal(gravado[2], JSON.stringify(["bruh"]));
    await assert.rejects(comBanco(responder, () => definirSonsEscondidosEfeitosSonoros({ usuario: lucas, targetUserId: 3, hidden: ["bruh"] })), /quem gerencia/);
    await assert.rejects(comBanco(responder, () => definirSonsEscondidosEfeitosSonoros({ usuario: lucas, targetUserId: 36, hidden: "bruh" })), /Informe/);
});

test("apagar áudios: só o Lucas (dono dos efeitos) recebe can_delete", async () => {
    const responder = (sql) => {
        if (sql.includes("SELECT can_use, can_manage")) return [[{ can_use: 1, can_manage: 1, max_volume_percent: 70, no_time_limit: 0, hidden_sounds: null }]];
        return [[]];
    };
    assert.equal((await comBanco(responder, () => obterPermissaoEfeitosSonoros(lucas))).can_delete, true);
    assert.equal((await comBanco(responder, () => obterPermissaoEfeitosSonoros(pedro))).can_delete, false);
});
