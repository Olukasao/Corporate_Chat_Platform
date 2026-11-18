import test from "node:test";
import assert from "node:assert/strict";
import db from "../db/db.js";
import { alvoExclusivoDoDono, buscarUsuarioAlvoEfeitoSonoro, listarUsuariosAlvoEfeitosSonoros, usuarioEhDonoDosEfeitosSonoros } from "./soundEffectPermissionsService.js";

const lucas = { id: 3, nome: "Lucas", email: "lucas@acessanet.com", empresa_id: 1 };
const pedro = { id: 36, nome: "Pedro", email: "pedro@acessanet.com", empresa_id: 1 };
const noc = { id: 51, nome: "NOC", email: "noc@acessanet.com", empresa_id: 1, status: "online" };
const rafa = { id: 10, nome: "Rafa", email: "rafa@acessanet.com", empresa_id: 1, status: "online" };

delete process.env.SOUND_EFFECT_OWNER_ONLY_TARGET_USER_IDS;
delete process.env.SOUND_EFFECT_OWNER_ALLOWED_TARGET_USER_IDS;
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

const samuel = { id: 23, nome: "Samuel", email: "samuel@acessanet.com", empresa_id: 1, status: "online" };
const leonardo = { id: 31, nome: "Leonardo Silva", email: "leonardo@acessanet.com", empresa_id: 1, status: "online" };
const diego = { id: 33, nome: "Diego", email: "diego@acessanet.com", empresa_id: 1, status: "online" };
const dalton = { id: 35, nome: "Dalton", email: "dalton@acessanet.com", empresa_id: 1, status: "online" };

test("Samuel, Leonardo e Diego: o Lucas alcança (Diego mesmo fora do grupo); os outros continuam bloqueados", async () => {
    for (const alvo of [samuel, leonardo]) {
        const doLucas = await comBanco(() => [[alvo]], () => buscarUsuarioAlvoEfeitoSonoro(lucas, alvo.id));
        assert.equal(doLucas?.id, alvo.id, `${alvo.nome} deveria ser alcançável pelo Lucas`);
        const doPedro = await comBanco(() => [[alvo]], () => buscarUsuarioAlvoEfeitoSonoro(pedro, alvo.id));
        assert.equal(doPedro, null, `${alvo.nome} continua bloqueado para os outros`);
    }
    // Diego não está no grupo-alvo: a consulta do grupo vem vazia e a direta acha ele
    const diegoDoLucas = await comBanco((sql) => (sql.includes("grupo_membros") ? [[]] : [[diego]]), () => buscarUsuarioAlvoEfeitoSonoro(lucas, 33));
    assert.equal(diegoDoLucas?.id, 33);
    const diegoDoPedro = await comBanco((sql) => (sql.includes("grupo_membros") ? [[]] : [[diego]]), () => buscarUsuarioAlvoEfeitoSonoro(pedro, 33));
    assert.equal(diegoDoPedro, null);
});

test("Dalton e Carlos continuam bloqueados até para o Lucas (não foram liberados)", async () => {
    assert.equal(await comBanco(() => [[dalton]], () => buscarUsuarioAlvoEfeitoSonoro(lucas, 35)), null);
    const carlos = { id: 24, nome: "Carlos Lacerda", email: "carlos@acessanet.com", empresa_id: 1 };
    assert.equal(await comBanco(() => [[carlos]], () => buscarUsuarioAlvoEfeitoSonoro(lucas, 24)), null);
});

test("lista de alvos do Lucas inclui Samuel, Leonardo, Diego e NOC; a do Pedro não inclui nenhum deles", async () => {
    const responder = (sql) => (sql.includes("grupo_membros") ? [[rafa, samuel, leonardo, dalton]] : [[noc, diego, samuel, leonardo]]);
    const paraLucas = await comBanco(responder, () => listarUsuariosAlvoEfeitosSonoros(lucas));
    assert.deepEqual(paraLucas.map((u) => u.id).sort((a, b) => a - b), [10, 23, 31, 33, 51]);
    const paraPedro = await comBanco(responder, () => listarUsuariosAlvoEfeitosSonoros(pedro));
    assert.deepEqual(paraPedro.map((u) => u.id), [10]);
});
