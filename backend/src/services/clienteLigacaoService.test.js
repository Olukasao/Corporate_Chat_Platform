import test from "node:test";
import assert from "node:assert/strict";
import { faltaDdd, mesmoTelefone, normalizarTelefone, telefonesDoContrato, criarServicoClienteLigacao } from "./clienteLigacaoService.js";

test("normaliza telefones brasileiros e recusa ramais", () => {
    assert.equal(normalizarTelefone("+55 (24) 99999-1234"), "24999991234");
    assert.equal(normalizarTelefone("024999991234"), "24999991234");
    assert.equal(normalizarTelefone("(24) 3333-1234"), "2433331234");
    assert.equal(normalizarTelefone("1003"), null);
    // sem DDD: nunca presume (fica null; a ficha pede o DDD)
    for (const semDdd of ["990211587", "33331234", "12345678"]) assert.equal(normalizarTelefone(semDdd), null);
    assert.equal(normalizarTelefone(""), null);
});

test("compara pelos 8 últimos dígitos, ignorando DDD e 9º dígito", () => {
    assert.ok(mesmoTelefone("(24) 99999-1234", "2499991234"));
    assert.ok(!mesmoTelefone("24999991234", "24999995678"));
    assert.ok(!mesmoTelefone("123", "123"));
});

test("acha telefones em campos aninhados do contrato", () => {
    const t = telefonesDoContrato({ nome: "A", celular: "24999991234", contatos: { telefones: ["2433331234"], emails: ["a@b.c"] }, cliente_celular2: "24988887777" });
    assert.deepEqual(t.sort(), ["24988887777", "24999991234", "2433331234"].sort());
});

const banco = (linhas = []) => ({ query: async (sql) => (/^\s*SELECT/i.test(sql) ? [linhas] : [[]]) });
const sgpBase = (extra = {}) => ({
    consultarContratosUra: async () => [],
    getCustomerDetails: async (c) => ({ customer: { name: "Maria", planName: "300 Mega", city: "Franco" } }),
    listarOcorrenciasUra: async () => [
        { id: 1, numero: "A1", data_cadastro: "2026-10-01", status: "Encerrada", tipo: "Suporte", conteudo: "sem net", contrato_status: "Ativo" },
        { id: 2, numero: "A2", data_cadastro: "2026-11-02", status: "Aberta", tipo: "Financeiro", conteudo: "boleto" },
    ],
    ...extra,
});
const avaliacoes = { listar: async () => ({ itens: [{ contrato: "3005", nota: 5, comentario: "ótimo", respondidoEm: "2026-11-03", tecnico: "Ana" }] }) };

test("sem vínculo e sem retorno do SGP, não encontra", async () => {
    const s = criarServicoClienteLigacao({ sgp: sgpBase(), avaliacoes, banco: banco() });
    const r = await s.porTelefone(1, "24999991234");
    assert.equal(r.encontrado, false);
    assert.equal((await s.porTelefone(1, "1003")).valido, false);
});

test("vínculo aprendido traz chamados (mais novo primeiro) e a última avaliação", async () => {
    const s = criarServicoClienteLigacao({ sgp: sgpBase(), avaliacoes, banco: banco([{ contrato: "3005", nome: "Maria" }]) });
    const r = await s.porTelefone(1, "(24) 99999-1234");
    assert.equal(r.encontrado, true);
    assert.equal(r.origem, "vinculo");
    assert.equal(r.cliente.chamados[0].protocolo, "A2");
    assert.equal(r.cliente.totalChamados, 2);
    assert.equal(r.cliente.ultimaAvaliacao.nota, 5);
    assert.equal(r.cliente.nome, "Maria");
});

test("SGP só vale se o telefone do cadastro bater com o número", async () => {
    const falso = sgpBase({ consultarContratosUra: async () => [{ contratoId: 111, clienteId: 1, celular: "21977776666" }] });
    assert.equal((await criarServicoClienteLigacao({ sgp: falso, avaliacoes, banco: banco() }).porTelefone(1, "24999991234")).encontrado, false);
    const certo = sgpBase({ consultarContratosUra: async () => [{ contratoId: 3005, clienteId: 1, celular1: "24999991234" }] });
    const r = await criarServicoClienteLigacao({ sgp: certo, avaliacoes, banco: banco() }).porTelefone(1, "24999991234");
    assert.equal(r.encontrado, true);
    assert.equal(r.origem, "sgp");
});

test("número sem DDD não é adivinhado: pede o DDD e não consulta o SGP", async () => {
    const consultas = [];
    const sgp = sgpBase({ consultarContratosUra: async (c) => { consultas.push(c); return []; } });
    const s = criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco() });
    const r = await s.porTelefone(1, "990211587");
    assert.deepEqual([r.valido, r.semDdd, r.encontrado], [true, true, false]);
    assert.equal(consultas.length, 0);
});

test("com o DDD informado pela pessoa, busca no SGP com o campo telefone", async () => {
    const consultas = [];
    const sgp = sgpBase({ consultarContratosUra: async (campos) => { consultas.push(campos); return campos.telefone === "11990211587" ? [{ contratoId: 41694, clienteId: 7, telefones: ["11990211587"], contratoStatusDisplay: "Ativo", dataCadastro: "25/08/2026 10:49:12" }] : []; } });
    const s = criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco() });
    const r = await s.porTelefone(1, "990211587", "11");
    assert.equal(r.encontrado, true);
    assert.equal(r.telefone, "11990211587");
    assert.deepEqual(consultas.filter((c) => c.telefone), [{ telefone: "11990211587" }]);
    assert.equal((await s.porTelefone(1, "990211587", "ab")).semDdd, true); // DDD inválido não vale
});

test("vários contratos do mesmo cliente viram uma ficha só, com os chamados juntos", async () => {
    const sgp = sgpBase({
        consultarContratosUra: async () => [
            { contratoId: 41692, clienteId: 7, telefones: ["11990211587"], contratoStatusDisplay: "Ativo", dataCadastro: "25/08/2026 10:29:55" },
            { contratoId: 41694, clienteId: 7, telefones: ["11990211587"], contratoStatusDisplay: "Ativo", dataCadastro: "25/08/2026 10:49:12" },
        ],
        listarOcorrenciasUra: async (c) => [{ id: Number(c), numero: `P${c}`, data_cadastro: c === "41694" ? "2026-11-02" : "2026-10-01", status: "Aberta", tipo: "Suporte", conteudo: "x", contrato_status: "Ativo" }],
    });
    const r = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco() }).porTelefone(1, "11990211587");
    assert.equal(r.cliente.contrato, "41694"); // o mais novo entre os ativos
    assert.deepEqual(r.cliente.contratos, ["41694", "41692"]);
    assert.deepEqual(r.cliente.chamados.map((c) => c.protocolo), ["P41694", "P41692"]);
    assert.equal(r.cliente.totalChamados, 2);
    assert.equal(r.outrosContratos, undefined);
});

test("clientes diferentes com o mesmo telefone pedem confirmação", async () => {
    const sgp = sgpBase({ consultarContratosUra: async () => [
        { contratoId: 1, clienteId: 1, telefones: ["11990211587"], contratoStatusDisplay: "Ativo", dataCadastro: "01/01/2026" },
        { contratoId: 2, clienteId: 2, telefones: ["11990211587"], contratoStatusDisplay: "Ativo", dataCadastro: "02/01/2026" },
    ] });
    const r = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco() }).porTelefone(1, "11990211587");
    assert.equal(r.outrosContratos.length, 2);
});

test("chamados indisponíveis não derrubam o cartão", async () => {
    const s = criarServicoClienteLigacao({ sgp: sgpBase({ listarOcorrenciasUra: async () => { throw new Error("timeout"); } }), avaliacoes, banco: banco([{ contrato: "3005", nome: "" }]) });
    const r = await s.porTelefone(1, "24999991234");
    assert.equal(r.encontrado, true);
    assert.equal(r.cliente.chamados, null);
});

test("com DDD faz uma consulta só e o DDD informado é ignorado", async () => {
    assert.ok(faltaDdd("990211587") && faltaDdd("33331234"));
    assert.ok(!faltaDdd("11990211587") && !faltaDdd("(24) 99021-1587") && !faltaDdd("1003"));
    const so = [];
    const sgp = sgpBase({ consultarContratosUra: async ({ telefone }) => { if (telefone) so.push(telefone); return []; } });
    assert.equal((await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco() }).porTelefone(1, "(11) 99021-1587", "24")).encontrado, false);
    assert.deepEqual(so, ["11990211587"]);
});

const indiceFalso = (lista = []) => { const aprendidos = []; return { aprendidos, candidatos: async (_e, local) => lista.filter((t) => t.endsWith(local)), aprender: async (_e, t) => { aprendidos.push(t); } }; };

test("sem DDD: o índice de telefones descobre o DDD (um candidato) e o número é aprendido", async () => {
    const indice = indiceFalso(["21990211587", "1133331234"]);
    const consultas = [];
    const sgp = sgpBase({ consultarContratosUra: async ({ telefone }) => { if (telefone) consultas.push(telefone); return telefone === "21990211587" ? [{ contratoId: 5, clienteId: 5, telefones: ["21990211587"], contratoStatusDisplay: "Ativo" }] : []; } });
    const r = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco(), indice }).porTelefone(1, "990211587");
    assert.equal(r.encontrado, true);
    assert.equal(r.telefone, "21990211587");
    assert.deepEqual(consultas, ["21990211587"]);
    assert.deepEqual(indice.aprendidos, ["21990211587"]);
});

test("sem DDD e com vários DDDs no índice: a pessoa escolhe; sem nenhum: pede o DDD", async () => {
    const consultas = [];
    const sgp = sgpBase({ consultarContratosUra: async (c) => { consultas.push(c); return []; } });
    const varios = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco(), indice: indiceFalso(["11990211587", "21990211587"]) }).porTelefone(1, "990211587");
    assert.deepEqual(varios.candidatos.map((c) => c.ddd).sort(), ["11", "21"]);
    assert.equal(varios.semDdd, true);
    const nenhum = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco(), indice: indiceFalso([]) }).porTelefone(1, "990211587");
    assert.equal(nenhum.candidatos, undefined);
    assert.equal(nenhum.semDdd, true);
    assert.equal(consultas.length, 0);
});

test("a ficha traz endereço, financeiro, histórico, média e conexão do contrato, sem senha da central", async () => {
    const cadastro = { contratoId: 5, clienteId: 5, telefones: [{ contato: "21990211587" }], contratoStatusDisplay: "Ativo", endereco_logradouro: "RUA A", endereco_numero: "10", endereco_cidade: "FRANCO", contratoValorAberto: 99.5, contratoTitulosAReceber: 1, contratoCentralSenha: "segredo123", dataCadastro: "25/08/2026 10:49:12" };
    const sgp = sgpBase({ consultarContratosUra: async () => [cadastro] });
    const olt = { configurada: () => true, equipamentosDoContrato: async () => [{ external_client_contract_id: "5", status: "Online", device_rx: -21 }, { external_client_contract_id: "55", status: "Offline" }] };
    const r = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco(), olt }).porTelefone(1, "21990211587");
    const c = r.cliente;
    assert.equal(c.endereco.linha, "RUA A, 10");
    assert.equal(c.financeiro.emAberto, 99.5);
    assert.equal(c.clienteDesde, "2026-08-25");
    assert.equal(c.historico.abertos, 1);
    assert.equal(c.conexao.online, true);
    assert.ok(!JSON.stringify(r).includes("segredo123"));
});

test("OLT Cloud fora do ar não derruba a ficha: conexão fica de fora", async () => {
    const sgp = sgpBase({ consultarContratosUra: async () => [{ contratoId: 5, clienteId: 5, telefones: [{ contato: "21990211587" }], contratoStatusDisplay: "Ativo" }] });
    const olt = { configurada: () => true, equipamentosDoContrato: async () => { throw new Error("fora"); } };
    const r = await criarServicoClienteLigacao({ sgp, avaliacoes, banco: banco(), olt }).porTelefone(1, "21990211587");
    assert.equal(r.encontrado, true);
    assert.equal(r.cliente.conexao, undefined);
});
