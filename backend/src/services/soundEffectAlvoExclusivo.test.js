import test from "node:test";
import assert from "node:assert/strict";
import db from "../db/db.js";
import { alvoExclusivoDoDono, buscarUsuarioAlvoEfeitoSonoro, listarUsuariosAlvoEfeitosSonoros, usuarioEhDonoDosEfeitosSonoros } from "./soundEffectPermissionsService.js";

const lucas = { id: 3, nome: "Lucas", email: "lucas@acessanet.com", empresa_id: 1 };
const pedro = { id: 36, nome: "Pedro", email: "pedro@acessanet.com", empresa_id: 1 };
const noc = { id: 51, nome: "NOC", email: "noc@acessanet.com", empresa_id: 1, status: "online" };
const rafa = { id: 10, nome: "Rafa", email: "rafa@acessanet.com", empresa_id: 1, status: "online" };

delete process.env.SOUND_EFFECT_OWNER_ONLY_TARGET_USER_IDS;
delete process.env.SOUND_EFFECT_OWNER_ONLY_TARGET_NAMES;
delete process.env.SOUND_EFFECT_OWNER_USER_IDS;
delete process.env.SOUND_EFFECT_OWNER_MATCH;

test("a conta NOC é destino exclusivo do dono; ninguém mais é", () => {
    assert.equal(alvoExclusivoDoDono(noc), true);
    assert.equal(alvoExclusivoDoDono({ id: 99, nome: "  noc " }), true);
    assert.equal(alvoExclusivoDoDono({ id: 99, nome: "Noc Equipe" }), false); // nome completo, não "contém"
    assert.equal(alvoExclusivoDoDono(rafa), false);
    assert.equal(alvoExclusivoDoDono(null), false);
});

test("o dono é o Lucas; os outros não", () => {
    assert.equal(usuarioEhDonoDosEfeitosSonoros(lucas), true);
    assert.equal(usuarioEhDonoDosEfeitosSonoros(pedro), false);
});

const comBanco = async (respostas, fn) => {
    const original = db.query;
    db.query = async (sql, params) => respostas(String(sql), params);
    try { return await fn(); } finally { db.query = original; }
};

test("buscar alvo: o dono alcança a conta NOC mesmo fora do grupo; os outros não, nem se ela estiver no grupo", async () => {
    // Lucas: a consulta do grupo não acha ninguém, a consulta direta acha o NOC
    const doLucas = await comBanco((sql) => (sql.includes("grupo_membros") ? [[]] : [[noc]]), () => buscarUsuarioAlvoEfeitoSonoro(lucas, 51));
    assert.equal(doLucas?.id, 51);
    // Pedro: mesmo que a conta NOC estivesse no grupo-alvo, é recusada
    const doPedro = await comBanco((sql) => (sql.includes("grupo_membros") ? [[noc]] : [[noc]]), () => buscarUsuarioAlvoEfeitoSonoro(pedro, 51));
    assert.equal(doPedro, null);
    // Pedro continua alcançando quem é do grupo e não é exclusivo
    const rafaDoPedro = await comBanco(() => [[rafa]], () => buscarUsuarioAlvoEfeitoSonoro(pedro, 10));
    assert.equal(rafaDoPedro?.id, 10);
    // o dono não vira "porta aberta": alvo comum fora do grupo continua recusado
    const comum = await comBanco((sql) => (sql.includes("grupo_membros") ? [[]] : [[rafa]]), () => buscarUsuarioAlvoEfeitoSonoro(lucas, 10));
    assert.equal(comum, null);
});

test("lista de alvos: a conta NOC só aparece para o dono", async () => {
    const responder = (sql) => (sql.includes("grupo_membros") ? [[rafa, noc]] : [[noc]]);
    const paraLucas = await comBanco(responder, () => listarUsuariosAlvoEfeitosSonoros(lucas));
    assert.deepEqual(paraLucas.map((u) => u.id).sort(), [10, 51]);
    const paraPedro = await comBanco(responder, () => listarUsuariosAlvoEfeitosSonoros(pedro));
    assert.deepEqual(paraPedro.map((u) => u.id), [10]);
});
