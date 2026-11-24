import test from "node:test";
import assert from "node:assert/strict";
import { interpretarBusca, resumirContrato, criarServicoRoteadorCliente } from "./roteadorClienteService.js";
import { modulosDoUsuario } from "./funcoesService.js";

test("interpreta a busca: CPF, CNPJ, contrato ou nome", () => {
    assert.deepEqual(interpretarBusca("123.456.789-09"), { campo: "cpfcnpj", valor: "12345678909", tipo: "cpf" });
    assert.equal(interpretarBusca("12.345.678/0001-90").campo, "cpfcnpj");
    assert.deepEqual(interpretarBusca(" 3005 "), { campo: "contrato", valor: "3005", tipo: "contrato" });
    assert.deepEqual(interpretarBusca("Maria  da Silva"), { campo: "nome", valor: "Maria da Silva", tipo: "nome" });
    assert.throws(() => interpretarBusca(""), /Digite/);
    assert.throws(() => interpretarBusca("ab"), /3 letras/);
    assert.throws(() => interpretarBusca("1234567890"), /11 ou 14/);
});

test("a lista traz só o necessário: sem senha, login PPPoE, MAC nem CPF inteiro", () => {
    const r = resumirContrato({ contratoId: 3005, razaoSocial: "JOAO DA SILVA", cpfCnpj: "12345678909", contratoStatusDisplay: "Ativo", endereco_bairro: "Centro", endereco_cidade: "Cidade", servico_plano: "500 MEGA", servico_senha: "segredo", servico_login: "pppoe1", servico_mac: "aa:bb", servico_wifi_password: "wifi" });
    assert.deepEqual(r, { contrato: "3005", nome: "Joao da Silva", documento: "•••.456.789-••", situacao: "ativo", local: "Centro · Cidade", plano: "500 MEGA" });
    assert.doesNotMatch(JSON.stringify(r), /segredo|pppoe1|aa:bb|wifi|12345678909/);
    assert.equal(resumirContrato({ contratoId: 1, contratoStatusDisplay: "Suspenso" }).situacao, "suspenso");
});

test("busca: tira repetidos e põe ativos na frente", async () => {
    let campos;
    const servico = criarServicoRoteadorCliente({ sgp: { consultarContratosUra: async (c) => { campos = c; return [{ contratoId: 1, razaoSocial: "A", contratoStatusDisplay: "Cancelado" }, { contratoId: 2, razaoSocial: "A", contratoStatusDisplay: "Ativo" }, { contratoId: 2, razaoSocial: "A" }]; } } });
    const r = await servico.buscar("111.222.333-44");
    assert.deepEqual(campos, { cpfcnpj: "11122233344" });
    assert.deepEqual(r.clientes.map((c) => c.contrato), ["2", "1"]);
    await assert.rejects(criarServicoRoteadorCliente({ sgp: { consultarContratosUra: async () => { throw new Error("x"); } } }).buscar("Maria"), /SGP não respondeu/);
});

const montar = (resposta, extra = {}) => {
    const chamadas = [];
    const auditorias = [];
    const servico = criarServicoRoteadorCliente({
        fetchImpl: async (url, init) => { chamadas.push({ url, init }); return { ok: true, json: async () => resposta }; },
        auditar: async (a) => { auditorias.push(a); },
        agente: { url: () => "http://127.0.0.1:8796", token: () => "t".repeat(40), publica: () => "http://192.168.1.133:8796" },
        ...extra,
    });
    return { servico, chamadas, auditorias };
};

test("abrir: chama o agente, registra quem abriu e devolve só a URL da janela", async () => {
    const { servico, chamadas, auditorias } = montar({ ok: true, token: "ab".repeat(24), vendor: "Huawei", model: "EG8145V5-V2" });
    const r = await servico.abrir({ id: 7, nome: "Ana" }, "3005", { nome: "Fulano" });
    assert.deepEqual(r, { ok: true, url: `http://192.168.1.133:8796/v/${"ab".repeat(24)}`, contrato: "3005", vendor: "Huawei", model: "EG8145V5-V2" });
    assert.equal(chamadas[0].url, "http://127.0.0.1:8796/panel/open");
    assert.equal(chamadas[0].init.headers.Authorization, `Bearer ${"t".repeat(40)}`);
    assert.deepEqual(JSON.parse(chamadas[0].init.body), { contractId: "3005", operator: "Ana", label: "Fulano · contrato 3005" });
    assert.equal(auditorias[0].acao, "roteador.painel_aberto");
    assert.equal(auditorias[0].entidadeId, "3005");
    assert.doesNotMatch(JSON.stringify(auditorias), /abab/); // o token da sessão não vai para a auditoria
});

test("abrir: recusa do agente vira mensagem e também é registrada", async () => {
    const { servico, auditorias } = montar({ ok: false, code: "ROUTER_OFFLINE", message: "Cliente sem conexão agora (offline)." });
    const r = await servico.abrir({ id: 7, nome: "Ana" }, "3005");
    assert.equal(r.ok, false);
    assert.equal(r.code, "ROUTER_OFFLINE");
    assert.equal(auditorias[0].acao, "roteador.painel_negado");
});

test("abrir: contrato inválido, sem token do agente e limite por minuto", async () => {
    const { servico } = montar({ ok: true, token: "x" });
    await assert.rejects(servico.abrir({ id: 1 }, "30 05"), /inválido/);
    await assert.rejects(servico.abrir({ id: 1 }, "../etc"), /inválido/);
    await assert.rejects(montar({}, { agente: { url: () => "", token: () => "", publica: () => "" } }).servico.abrir({ id: 1 }, "1"), /não está ligado/);
    await assert.rejects(montar({}, { fetchImpl: async () => { throw new Error("ECONNREFUSED"); } }).servico.abrir({ id: 1 }, "1"), /agente de roteadores não respondeu/);
    let t = 1000;
    const m = montar({ ok: false, code: "ROUTER_OFFLINE" }, { agora: () => t });
    for (let i = 0; i < 12; i++) await m.servico.abrir({ id: 9, nome: "B" }, "1");
    await assert.rejects(m.servico.abrir({ id: 9, nome: "B" }, "1"), /Muitas aberturas/);
    t += 61_000;
    await m.servico.abrir({ id: 9, nome: "B" }, "1"); // passou um minuto
});

test("módulo roteador é fechado: só admin, ou setor que foi marcado", async () => {
    assert.equal(await modulosDoUsuario({ perfil: "admin" }), null);
    const aberto = await modulosDoUsuario({ perfil: "user", setor_id: null, empresa_id: 1 });
    assert.ok(aberto.includes("chamados"));
    assert.ok(!aberto.includes("roteador"));
});
