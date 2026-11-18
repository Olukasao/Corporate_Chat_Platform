import test from "node:test";
import assert from "node:assert/strict";
import { chaveLead, criarServicoWifiMarketing, iniciarWifiMarketing, normalizarLeads, selecionarNovosLeads, SALA_WIFI_MARKETING } from "./wifiMarketingService.js";

const bruto = (id, extra = {}) => ({ id, name: "Maria S.", establishment: "Acessanet EcoParque", marketingConsentAt: "2026-11-18T18:05:42.278Z", ...extra });

test("normaliza o feed e ignora lixo", () => {
    const l = normalizarLeads([bruto("a"), { name: "sem id" }, bruto("b", { name: "  João P.  " })]);
    assert.deepEqual(l.map((x) => x.id), ["a", "b"]);
    assert.equal(l[1].nome, "João P.");
    assert.equal(l[0].rede, "Acessanet EcoParque");
    assert.equal(normalizarLeads(null).length, 0);
});

test("primeira leitura não avisa; depois avisa só o que é novo, inclusive quem aceita de novo", () => {
    const lista = normalizarLeads([bruto("a"), bruto("b")]);
    assert.deepEqual(selecionarNovosLeads(lista, null), []);
    const vistos = new Set([chaveLead(lista[0])]);
    assert.deepEqual(selecionarNovosLeads(lista, vistos).map((x) => x.id), ["b"]);
    const reaceite = normalizarLeads([bruto("a", { marketingConsentAt: "2026-11-19T10:00:00.000Z" })]);
    assert.deepEqual(selecionarNovosLeads(reaceite, vistos).map((x) => x.id), ["a"]);
});

test("o serviço usa o token só no cabeçalho e não segue redirecionamento", async () => {
    let visto;
    const servico = criarServicoWifiMarketing({
        env: { CONTRATACOES_FEED_TOKEN: "segredo", WIFI_MARKETING_FEED_URL: "https://site.test/api/integracoes/wifi/marketing" },
        fetchImpl: async (url, init) => ((visto = { url: String(url), init }), { ok: true, json: async () => ({ items: [bruto("a")] }) }),
    });
    assert.equal((await servico.listar()).length, 1);
    assert.equal(visto.init.headers.Authorization, "Bearer segredo");
    assert.equal(visto.init.redirect, "error");
    assert.ok(!visto.url.includes("segredo"));
    await assert.rejects(criarServicoWifiMarketing({ env: {} }).listar(), /não configurada/);
});

test("sem token nada começa; com token a primeira leitura não avisa e a segunda avisa a sala certa", async () => {
    const enviados = [];
    const io = { to: (sala) => ({ emit: (ev, dados) => enviados.push({ sala, ev, dados }) }) };
    assert.equal(typeof iniciarWifiMarketing(io, { env: {} }), "function");
    let rodada = 0;
    const respostas = [normalizarLeads([bruto("a")]), normalizarLeads([bruto("a"), bruto("b")])];
    const servico = { listar: async () => respostas[Math.min(rodada++, 1)] };
    const parar = iniciarWifiMarketing(io, { servico, env: { CONTRATACOES_FEED_TOKEN: "x", WIFI_MARKETING_POLL_MS: "30000" } });
    await new Promise((r) => setTimeout(r, 20));
    parar();
    assert.deepEqual(enviados, []); // a primeira leitura nunca avisa
    const vistos = new Set([chaveLead(respostas[0][0])]);
    const novos = selecionarNovosLeads(respostas[1], vistos);
    io.to(SALA_WIFI_MARKETING).emit("wifi:marketing", { itens: novos, total: novos.length });
    assert.equal(enviados[0].sala, "wifi_marketing");
    assert.equal(enviados[0].dados.total, 1);
});
