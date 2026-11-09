import test from "node:test";
import assert from "node:assert/strict";
import { analisarChamados, conexaoDoContrato, dadosDoCadastro, dataIso, mascararDocumento, mediaDeAvaliacoes } from "./fichaClienteDados.js";

test("dataIso entende o formato do SGP e o ISO", () => {
    assert.equal(dataIso("25/08/2026 10:49:12"), "2026-08-25");
    assert.equal(dataIso("2026-11-09"), "2026-11-09");
    assert.equal(dataIso("lixo"), "");
});

test("documento sai mascarado e nunca inteiro", () => {
    assert.equal(mascararDocumento("391.138.358-40"), "•••.138.358-••");
    assert.equal(mascararDocumento("12345678000199"), "••.345.678/••••-••");
    assert.equal(mascararDocumento("123"), "");
});

test("cadastro: monta endereço e financeiro, e NÃO devolve login nem senha da central", () => {
    const r = dadosDoCadastro({
        endereco_logradouro: "ESTRADA DO ALTO", endereco_numero: 83, endereco_bairro: "CHÁCARAS", endereco_cidade: "FRANCO DA ROCHA", endereco_uf: "SP", endereco_cep: "07863-290",
        endereco_complemento: null, endereco_ll: "-23.31,-46.72", contratoValorAberto: 129.9, contratoTitulosAReceber: 2, cobVencimento: 25, dataCadastro: "25/08/2026 10:49:12",
        contratoCentralLogin: "x@y.com", contratoCentralSenha: "segredo123", cpfCnpj: "391.138.358-40",
        telefones: [{ contato: "11990211587" }], emails: [{ contato: "a@b.com" }], anotacoes: ["não ligar à noite"], tags: [{ nome: "VIP" }],
    });
    assert.equal(r.endereco.linha, "ESTRADA DO ALTO, 83");
    assert.deepEqual(r.endereco.coordenadas, { lat: -23.31, lng: -46.72 });
    assert.equal(r.financeiro.emAberto, 129.9);
    assert.equal(r.financeiro.titulosAReceber, 2);
    assert.equal(r.clienteDesde, "2026-08-25");
    assert.deepEqual(r.etiquetas, ["VIP"]);
    assert.deepEqual(r.anotacoes, ["não ligar à noite"]);
    assert.equal(r.contatos.length, 2);
    const json = JSON.stringify(r);
    assert.ok(!json.includes("segredo123") && !json.includes("x@y.com") && !json.includes("391.138.358-40"));
});

test("cadastro vazio ou nulo não quebra", () => {
    assert.deepEqual(dadosDoCadastro(null), {});
    assert.equal(dadosDoCadastro({}).endereco.coordenadas, null);
});

const HOJE = Date.parse("2026-11-09T15:00:00Z");
test("chamados: reincidência, tempo médio, assunto repetido e visita marcada", () => {
    const o = [
        { numero: "1", tipo: "Suporte", data_cadastro: "2026-11-08", data_finalizacao: "", data_agendamento: "2026-11-11" },
        { numero: "2", tipo: "Suporte", data_cadastro: "2026-10-20", data_finalizacao: "2026-10-22", data_agendamento: "" },
        { numero: "3", tipo: "Financeiro", data_cadastro: "2026-06-01", data_finalizacao: "2026-06-01", data_agendamento: "" },
    ];
    const r = analisarChamados(o, HOJE);
    assert.equal(r.ultimos30Dias, 2);
    assert.equal(r.abertos, 1);
    assert.equal(r.tempoMedioDias, 1);
    assert.deepEqual(r.assuntoMaisComum, { tipo: "Suporte", vezes: 2 });
    assert.deepEqual(r.visitaAgendada, { data: "2026-11-11", protocolo: "1", tipo: "Suporte" });
});

test("visita no passado ou de chamado encerrado não conta; sem lista devolve null", () => {
    const r = analisarChamados([{ numero: "1", tipo: "A", data_cadastro: "2026-11-01", data_finalizacao: "", data_agendamento: "2026-11-05" }, { numero: "2", tipo: "B", data_cadastro: "2026-11-01", data_finalizacao: "2026-11-02", data_agendamento: "2026-11-20" }], HOJE);
    assert.equal(r.visitaAgendada, null);
    assert.equal(analisarChamados(null), null);
});

test("média das avaliações ignora notas inválidas", () => {
    assert.deepEqual(mediaDeAvaliacoes([{ nota: 5 }, { nota: 2 }, { nota: 0 }, { nota: "x" }]), { media: 3.5, total: 2 });
    assert.equal(mediaDeAvaliacoes([]), null);
});

test("conexão: só vale o equipamento do contrato EXATO (a OLT Cloud também devolve 33005 para 3005)", () => {
    const eq = [{ external_client_contract_id: "33005", status: "Online", device_rx: -20 }, { external_client_contract_id: "3005", status: "Offline", device_rx: -31.2, olt_rx: -27, slot: 11, pon: 3, onu_id: 32, model: "EG8145", olt: "OLT-1", last_disconnection: "2026-11-07 16:01:19" }];
    const r = conexaoDoContrato(eq, "3005");
    assert.equal(r.online, false);
    assert.equal(r.status, "Offline");
    assert.equal(r.sinalOnuDbm, -31.2);
    assert.equal(r.porta, "11/3/32");
    assert.equal(conexaoDoContrato([eq[0]], "3005"), null);
    assert.equal(conexaoDoContrato([], "3005"), null);
});
