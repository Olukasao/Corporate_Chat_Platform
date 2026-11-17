import test from "node:test";
import assert from "node:assert/strict";

process.env.OLTCLOUD_BASE_URL = "https://olt.example.test";
process.env.OLTCLOUD_TOKEN = "token-fixo";
const { normalizarNaoAutorizadas, selecionarNovas } = await import("../src/services/oltNaoAutorizadasService.js");

const resposta = { return: true, results: [
    { olt_id: 1, error: false, quarantined: false, unauth_list: [{ serial_number: "HWTC0002", type: "EG8145X6-10", slot: 3, pon: 14, client: null }, { serial_number: "HWTC0001", type: "EG8145V5", slot: 1, pon: 2, client: { id: 9 } }] },
    { olt_id: 2, error: false, quarantined: false, unauth_list: [] },
    { olt_id: 3, error: true, quarantined: false, unauth_list: [{ serial_number: "X", type: "t", slot: 1, pon: 1 }] }, // leitura com erro: ignora
    { olt_id: 4, error: false, quarantined: true, unauth_list: [{ serial_number: "Y", type: "t", slot: 1, pon: 1 }] }, // em quarentena: ignora
    { olt_id: 5, error: false, quarantined: false, unauth_list: [{ type: "sem serie" }] }, // sem serie: ignora
] };

test("ONUs não autorizadas: nome da OLT, ordem por OLT/slot/PON, e ignora OLT com erro ou em quarentena", () => {
    const itens = normalizarNaoAutorizadas(resposta, new Map([["1", "GPON-OLT-DAS-001"]]));
    assert.deepEqual(itens.map((i) => [i.serie, i.olt, i.slot, i.pon, i.temCliente]), [["HWTC0001", "GPON-OLT-DAS-001", "1", "2", true], ["HWTC0002", "GPON-OLT-DAS-001", "3", "14", false]]);
    assert.equal(normalizarNaoAutorizadas(resposta)[0].olt, "OLT 1"); // sem o nome, mostra o numero
    assert.deepEqual(normalizarNaoAutorizadas({ results: [] }), []);
    assert.deepEqual(normalizarNaoAutorizadas(null), []);
});

test("só avisa o que é novo, e nunca na primeira leitura", () => {
    const itens = [{ serie: "A" }, { serie: "B" }];
    assert.deepEqual(selecionarNovas(itens, null), []);
    assert.deepEqual(selecionarNovas(itens, new Set(["A"])).map((i) => i.serie), ["B"]);
    assert.deepEqual(selecionarNovas(itens, new Set(["A", "B"])), []);
});
