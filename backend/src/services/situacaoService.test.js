import test from "node:test";
import assert from "node:assert/strict";
import { criarServicoSituacao, situacaoEfetiva, LIGACAO_MAX_MS } from "./situacaoService.js";

test("ligação vale mais que a situação manual; manual vencida some", () => {
    const agora = 1_000_000_000_000;
    assert.equal(situacaoEfetiva({ manual: "almoco", ligacaoDesde: agora - 1000 }, agora).situacao, "ligacao");
    assert.equal(situacaoEfetiva({ manual: "almoco", ate: new Date(agora + 60_000) }, agora).situacao, "almoco");
    assert.equal(situacaoEfetiva({ manual: "almoco", ate: new Date(agora - 60_000) }, agora).situacao, null);
    assert.equal(situacaoEfetiva({ manual: "inexistente" }, agora).situacao, null);
    assert.equal(situacaoEfetiva({ ligacaoDesde: agora - LIGACAO_MAX_MS - 1 }, agora).situacao, null);
});

function bancoFalso() {
    const linhas = new Map();
    return {
        query: async (sql, p = []) => {
            if (/CREATE TABLE/i.test(sql)) return [[]];
            if (/^\s*DELETE/i.test(sql)) { linhas.delete(`${p[0]}:${p[1]}`); return [[]]; }
            if (/INSERT INTO/i.test(sql)) { linhas.set(`${p[0]}:${p[1]}`, { usuario_id: p[1], situacao: p[2], ate: p[3] }); return [[]]; }
            if (/WHERE empresa_id = \? AND usuario_id/.test(sql)) return [[linhas.get(`${p[0]}:${p[1]}`)].filter(Boolean)];
            return [[...linhas.entries()].filter(([k]) => k.startsWith(`${p[0]}:`)).map(([, v]) => v)];
        },
    };
}

test("define, lista e limpa a situação; ligação aparece e some", async () => {
    let t = 1_000_000_000_000;
    const s = criarServicoSituacao({ banco: bancoFalso(), agora: () => t });
    assert.equal((await s.definir(1, 7, "visita", 30)).situacao, "visita");
    assert.deepEqual((await s.listar(1)).map((i) => [i.usuario_id, i.situacao]), [[7, "visita"]]);
    assert.equal((await s.marcarLigacao(1, 7, true)).situacao, "ligacao");
    assert.equal((await s.marcarLigacao(1, 8, true)).situacao, "ligacao");
    assert.equal((await s.listar(1)).length, 2);
    await s.marcarLigacao(1, 7, false);
    assert.equal((await s.efetiva(1, 7)).situacao, "visita");
    t += 31 * 60_000;
    assert.equal((await s.efetiva(1, 7)).situacao, null);
    assert.equal((await s.definir(1, 7, null)).situacao, null);
    await assert.rejects(() => s.definir(1, 7, "folga"), /inválida/);
});
