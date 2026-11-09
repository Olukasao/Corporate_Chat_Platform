import test from "node:test";
import assert from "node:assert/strict";
import { criarServicoSaude, medir } from "./saudeService.js";

test("medir classifica ok, lento e falha sem lançar erro", async () => {
    let t = 0;
    const agora = () => t;
    assert.equal((await medir("banco", "Banco", async () => { t += 50; return "x"; }, { agora })).estado, "ok");
    assert.equal((await medir("banco", "Banco", async () => { t += 900; }, { agora })).estado, "lento");
    const f = await medir("sgp", "SGP", async () => { throw new Error("HTTP 503"); }, { agora });
    assert.equal(f.estado, "falha");
    assert.match(f.detalhe, /503/);
});

test("uma peça fora do ar não derruba as outras", async () => {
    const s = criarServicoSaude({
        env: { CONTRATACOES_FEED_TOKEN: "t", UPDATES_HEALTH_URL: "https://127.0.0.1:1/x" },
        banco: { query: async () => [[{ banco: "chat_interno_teste", usuarios: 53 }]] },
        fetchImpl: async () => ({ status: 401, ok: false }),
        sgp: async () => [{ contrato: 3005 }],
        indice: { estatisticas: async () => ({ total: 12000, atualizadoEm: new Date().toISOString() }) },
    });
    const r = await s.verificar();
    const por = Object.fromEntries(r.itens.map((i) => [i.id, i]));
    assert.equal(por.banco.estado, "ok");
    assert.match(por.banco.detalhe, /53 usuários/);
    assert.equal(por.feedSite.estado, "falha");
    assert.match(por.feedSite.detalhe, /recusou o token/);
    assert.equal(por.sgp.estado, "ok");
    assert.equal(por.atualizacoes.estado, "falha");
    assert.equal(r.geral, "falha");
    assert.ok(r.falhas >= 2);
});
