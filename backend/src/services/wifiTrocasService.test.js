import test from "node:test";
import assert from "node:assert/strict";
import { criarServicoTrocasWifi, iniciarTrocasWifi, normalizarTrocas, selecionarNovasTrocas, SALA_WIFI_TROCAS } from "./wifiTrocasService.js";

const bruto = (id, extra = {}) => ({ id, contractId: "1001", customerName: "Ana Souza", bands: ["2.4GHz", "5GHz"], vendor: "Huawei", model: "EG8145V5-V2", confirmation: null, ticketProtocol: null, finishedAt: "2026-11-16T10:00:00Z", ...extra });

test("normaliza o feed e ignora lixo", () => {
    const t = normalizarTrocas([bruto("a"), { contractId: "x" }, bruto("b", { confirmation: "not_connected", ticketProtocol: "261116000001", confirmation2: 1 }), bruto("c", { confirmation: "qualquer" })]);
    assert.deepEqual(t.map((x) => x.id), ["a", "b", "c"]);
    assert.equal(t[0].roteador, "Huawei EG8145V5-V2");
    assert.deepEqual(t[0].redes, ["2.4GHz", "5GHz"]);
    assert.equal(t[1].confirmacao, "not_connected");
    assert.equal(t[1].chamado, "261116000001");
    assert.equal(t[2].confirmacao, null);
    assert.equal(normalizarTrocas(null).length, 0);
});

test("primeira leitura não avisa; depois avisa troca nova e resposta nova do cliente", () => {
    const lista = normalizarTrocas([bruto("a"), bruto("b")]);
    assert.deepEqual(selecionarNovasTrocas(lista, null), []);
    const vistos = new Set(["a|"]);
    assert.deepEqual(selecionarNovasTrocas(lista, vistos).map((t) => t.id), ["b"]);
    const depois = normalizarTrocas([bruto("a", { confirmation: "not_connected" })]);
    assert.deepEqual(selecionarNovasTrocas(depois, vistos).map((t) => t.id), ["a"]); // mesma troca, resposta nova
});

test("o serviço usa o token só no cabeçalho e não segue redirecionamento", async () => {
    let visto;
    const servico = criarServicoTrocasWifi({
        env: { CONTRATACOES_FEED_TOKEN: "segredo", WIFI_TROCAS_FEED_URL: "https://site.test/api/integracoes/wifi/trocas" },
        fetchImpl: async (url, init) => ((visto = { url: String(url), init }), { ok: true, json: async () => ({ items: [bruto("a")] }) }),
        agora: () => Date.parse("2026-11-16T12:00:00Z"),
    });
    assert.equal((await servico.listar()).length, 1);
    assert.equal(visto.init.headers.Authorization, "Bearer segredo");
    assert.equal(visto.init.redirect, "error");
    assert.ok(!visto.url.includes("segredo"));
    assert.match(visto.url, /desde=2026-11-15T00%3A00%3A00\.000Z/);
    await assert.rejects(criarServicoTrocasWifi({ env: {} }).listar(), /não configurada/);
});

test("sem token a consulta nem começa; com token avisa a sala certa", async () => {
    const enviados = [];
    const io = { to: (sala) => ({ emit: (ev, dados) => enviados.push({ sala, ev, dados }) }) };
    assert.equal(typeof iniciarTrocasWifi(io, { env: {} }), "function");
    let rodada = 0;
    const servico = { listar: async () => (rodada++ === 0 ? normalizarTrocas([bruto("a")]) : normalizarTrocas([bruto("a"), bruto("b")])) };
    const parar = iniciarTrocasWifi(io, { servico, env: { CONTRATACOES_FEED_TOKEN: "x", WIFI_TROCAS_POLL_MS: "30000" } });
    await new Promise((r) => setTimeout(r, 20));
    parar();
    assert.deepEqual(enviados, []); // a primeira leitura nunca avisa
    // segunda leitura "à mão": o mesmo seletor que o ciclo usa
    const vistos = new Set(["a|"]);
    const novas = selecionarNovasTrocas(normalizarTrocas([bruto("a"), bruto("b")]), vistos);
    io.to(SALA_WIFI_TROCAS).emit("wifi:troca", { itens: novas, total: novas.length });
    assert.equal(enviados[0].sala, "wifi_trocas");
    assert.equal(enviados[0].dados.total, 1);
});
