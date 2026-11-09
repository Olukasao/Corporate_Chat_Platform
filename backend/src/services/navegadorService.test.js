import test from "node:test";
import assert from "node:assert/strict";
import { criarServicoNavegador, validarNome, validarUrl } from "./navegadorService.js";

test("valida endereço e nome", () => {
    assert.equal(validarUrl("meusite.com.br/painel"), "https://meusite.com.br/painel");
    assert.equal(validarUrl("http://192.168.1.50:3000/x"), "http://192.168.1.50:3000/x");
    for (const ruim of ["", "javascript:alert(1)", "file:///etc/passwd", "https://user:senha@a.com", "https://semponto", "ftp://a.com"]) assert.throws(() => validarUrl(ruim), ruim);
    assert.equal(validarNome("  Portal   X "), "Portal X");
    assert.throws(() => validarNome("a"));
    assert.throws(() => validarNome("x".repeat(31)));
});

function bancoFalso() {
    const sites = []; let seq = 0; const acesso = new Map(); const setores = [{ id: 9, nome: "Atendimento", empresa_id: 1 }];
    return {
        query: async (sql, p = []) => {
            if (/CREATE TABLE/i.test(sql)) return [[]];
            if (/SELECT id, nome, url FROM navegador_sites/.test(sql)) return [sites.filter((s) => s.empresa_id === p[0])];
            if (/SELECT COUNT/.test(sql)) return [[{ total: sites.length }]];
            if (/INSERT INTO navegador_sites/.test(sql)) { sites.push({ id: ++seq, empresa_id: p[0], nome: p[1], url: p[2] }); return [{ insertId: seq }]; }
            if (/DELETE FROM navegador_sites/.test(sql)) { const i = sites.findIndex((s) => s.id === p[0]); if (i >= 0) sites.splice(i, 1); return [{ affectedRows: i >= 0 ? 1 : 0 }]; }
            if (/SELECT sites FROM navegador_acesso/.test(sql)) return [acesso.has(`${p[0]}:${p[1]}`) ? [{ sites: acesso.get(`${p[0]}:${p[1]}`) }] : []];
            if (/SELECT setor_id, sites FROM navegador_acesso/.test(sql)) return [[...acesso.entries()].map(([k, v]) => ({ setor_id: Number(k.split(":")[1]), sites: v }))];
            if (/UPDATE navegador_acesso/.test(sql)) { acesso.set(`${p[1]}:${p[2]}`, p[0]); return [{ affectedRows: 1 }]; }
            if (/SELECT id FROM setores/.test(sql)) return [setores.filter((s) => s.id === p[0] && s.empresa_id === p[1])];
            if (/SELECT id, nome FROM setores/.test(sql)) return [setores];
            if (/DELETE FROM navegador_acesso/.test(sql)) { acesso.delete(`${p[0]}:${p[1]}`); return [{}]; }
            if (/INSERT INTO navegador_acesso/.test(sql)) { acesso.set(`${p[0]}:${p[1]}`, p[2]); return [{}]; }
            throw new Error("SQL não previsto: " + sql);
        },
    };
}

test("setor sem lista vê tudo; com lista vê só os marcados; admin vê tudo", async () => {
    const s = criarServicoNavegador({ banco: bancoFalso() });
    const novo = await s.criarSite(1, { nome: "Portal X", url: "portal.exemplo.com.br" });
    assert.equal(novo.id, "site-1");
    const atend = { empresa_id: 1, setor_id: 9, perfil: "usuario" };
    assert.equal((await s.paraUsuario(atend)).length, 8);
    await s.salvarAcesso(1, 9, ["sgp", "site-1", "inexistente", "sgp"]);
    assert.deepEqual((await s.paraUsuario(atend)).map((x) => x.id), ["sgp", "site-1"]);
    assert.equal((await s.paraUsuario({ ...atend, perfil: "admin" })).length, 8);
    assert.equal((await s.paraUsuario({ empresa_id: 1, setor_id: null, perfil: "usuario" })).length, 8);
    await s.removerSite(1, "site-1");
    assert.deepEqual((await s.paraUsuario(atend)).map((x) => x.id), ["sgp"]);
    await s.salvarAcesso(1, 9, null);
    assert.equal((await s.paraUsuario(atend)).length, 7);
    await assert.rejects(() => s.removerSite(1, "sgp"), /extras/);
    await assert.rejects(() => s.salvarAcesso(1, 777, []), /Setor/);
});
