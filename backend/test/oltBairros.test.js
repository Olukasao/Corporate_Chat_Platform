import test from "node:test";
import assert from "node:assert/strict";
const { agruparPorBairro, bairroBonito, bairrosDosAfetados, leituraDaQueda, estadoDoEquipamento } = await import("../src/services/oltBairrosService.js");

test("bairro: maiúsculas viram iniciais maiúsculas e o mesmo bairro com grafia diferente conta junto", () => {
    assert.equal(bairroBonito("  JARDIM  DAS  FLORES "), "Jardim das Flores");
    assert.equal(bairroBonito("Centro"), "Centro");
    const g = agruparPorBairro([
        { bairro: "CENTRO", cidade: "Mairinque", estado: "semEnergia" },
        { bairro: "Centro ", cidade: "MAIRINQUE", estado: "semEnergia" },
        { bairro: "Vila Nova", cidade: "Mairinque", estado: "loss" },
        { bairro: "", cidade: "", estado: "loss" },
    ]);
    assert.deepEqual(g.map((x) => [x.bairro, x.clientes, x.semEnergia, x.loss, x.pct]), [["Centro", 2, 2, 0, 50], ["Sem bairro", 1, 0, 1, 25], ["Vila Nova", 1, 0, 1, 25]]);
});

test("leitura da queda: energia x fibra", () => {
    assert.match(leituraDaQueda(9, 1), /energia/i);
    assert.match(leituraDaQueda(1, 9), /fibra/i);
    assert.match(leituraDaQueda(5, 5), /Mistura/);
    assert.equal(leituraDaQueda(0, 0), "");
    assert.equal(estadoDoEquipamento("Sem Energia"), "semEnergia");
    assert.equal(estadoDoEquipamento("LOSS"), "loss");
});

test("afetados: conta cada contrato uma vez, separa sem contrato e usa o bairro do SGP", async () => {
    const chamadas = [];
    const consultar = async ({ contrato }) => (chamadas.push(contrato), [{ contratoId: contrato, endereco_bairro: contrato === "3" ? "VILA NOVA" : "CENTRO", endereco_cidade: "X" }]);
    const r = await bairrosDosAfetados([
        { contrato: "1", status: "Sem Energia" }, { contrato: "1", status: "Sem Energia" }, // mesmo cliente com 2 ONUs
        { contrato: "2", status: "Sem Energia" }, { contrato: "3", status: "LOSS" },
        { contrato: "", status: "LOSS" }, { contrato: "  ", status: "Sem Energia" },
    ], { consultar });
    assert.deepEqual([r.total, r.consultados, r.semContrato, r.semEnergia, r.loss], [3, 3, 2, 2, 1]);
    assert.deepEqual(chamadas.sort(), ["1", "2", "3"]);
    assert.deepEqual(r.bairros.map((b) => [b.bairro, b.clientes]), [["Centro", 2], ["Vila Nova", 1]]);
});

test("afetados: SGP fora do ar não derruba (clientes entram em 'Sem bairro') e respeita o limite", async () => {
    const r = await bairrosDosAfetados(Array.from({ length: 10 }, (_, k) => ({ contrato: String(100 + k), status: "LOSS" })), { consultar: async () => { throw new Error("fora"); }, limite: 4 });
    assert.equal(r.total, 10);
    assert.equal(r.consultados, 4);
    assert.deepEqual(r.bairros.map((b) => [b.bairro, b.clientes]), [["Sem bairro", 4]]);
});
