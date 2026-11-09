import test from "node:test";
import assert from "node:assert/strict";
import { baixarCsvPorAno, dividirCsv, parteLocal, telefonesDoCsv, criarIndiceTelefones } from "./indiceTelefonesService.js";

test("lê o CSV do SGP guardando só os telefones válidos (sem nomes)", () => {
    const csv = ['Nome,Celular,Tipo', '"SILVA, JOSE",11990211587,Celular Pessoal', 'MARIA,(21) 3333-1234,Telefone', 'X,5524999991234,Celular', 'Y,1003,Ramal', 'Z,,Celular', 'W,11990211587,WhatsApp'].join("\n");
    assert.deepEqual(telefonesDoCsv(csv).sort(), ["11990211587", "2133331234", "24999991234"].sort());
    assert.deepEqual(dividirCsv('"A ""B"", C",1,2'), ['A "B", C', "1", "2"]);
    assert.equal(parteLocal("990211587"), "990211587");
    assert.equal(parteLocal("11990211587"), null);
});

function bancoFalso() {
    const linhas = new Map();
    return {
        linhas,
        query: async (sql, p = []) => {
            if (/CREATE TABLE/i.test(sql)) return [[]];
            if (/RIGHT\(telefone/.test(sql)) return [[...linhas.values()].filter((l) => l.empresa === p[0] && l.telefone.endsWith(p[2])).map((l) => ({ telefone: l.telefone }))];
            if (/INSERT IGNORE/.test(sql)) { const k = `${p[0]}:${p[1]}`; if (!linhas.has(k)) linhas.set(k, { empresa: p[0], telefone: p[1], fonte: "aprendido", em: Math.floor(+p[2] / 1000) * 1000 }); return [{}]; }
            if (/SELECT COUNT\(\*\) AS n FROM telefone_indice/.test(sql)) return [[{ n: [...linhas.values()].filter((l) => l.fonte === "sgp").length }]];
            if (/SELECT COUNT\(\*\) AS total/.test(sql)) return [[{ total: linhas.size }]];
            if (/^\s*INSERT INTO telefone_indice/.test(sql)) { for (let i = 0; i < p.length; i += 3) { const k = `${p[i]}:${p[i + 1]}`; linhas.set(k, { empresa: p[i], telefone: p[i + 1], fonte: "sgp", em: Math.floor(+p[i + 2] / 1000) * 1000 }); } return [{}]; }
            if (/^\s*DELETE/.test(sql)) { let n = 0; for (const [k, l] of linhas) if (l.fonte === "sgp" && l.em < +p[1]) { linhas.delete(k); n++; } return [{ affectedRows: n }]; }
            if (/ia_config|SELECT chave/.test(sql)) return [[]];
            throw new Error("SQL não previsto: " + sql);
        },
    };
}
const csvCom = (n) => ["Nome,Celular,Tipo", ...Array.from({ length: n }, (_, i) => `P${i},119${String(10000000 + i)},Celular`)].join("\n");

test("candidatos achados pelo final do número, aprendizado e troca do índice", async () => {
    let t = 1500; // não múltiplo de 1000: o banco real corta os milissegundos
    const banco = bancoFalso();
    const idx = criarIndiceTelefones({ banco, baixarCsv: async () => csvCom(60), agora: () => (t += 1000), registrar: async () => {} });
    await idx.aprender(1, "21990211587");
    await idx.aprender(1, "123"); // inválido, ignorado
    assert.deepEqual(await idx.candidatos(1, "990211587"), ["21990211587"]);
    assert.deepEqual(await idx.candidatos(1, "1003"), []);
    const r = await idx.atualizar(1);
    assert.equal(r.removidos, 0, "a limpeza não pode apagar o que acabou de entrar");
    assert.ok([...banco.linhas.values()].filter((l) => l.fonte === "sgp").length >= 60);
    assert.ok(banco.linhas.has("1:21990211587"), "o número aprendido continua");
});

test("exportação pequena demais não apaga o índice", async () => {
    const banco = bancoFalso();
    const bom = criarIndiceTelefones({ banco, baixarCsv: async () => csvCom(200), registrar: async () => {} });
    await bom.atualizar(1);
    const antes = [...banco.linhas.values()].filter((l) => l.fonte === "sgp").length;
    const ruim = criarIndiceTelefones({ banco, baixarCsv: async () => csvCom(60), registrar: async () => {} });
    await assert.rejects(() => ruim.atualizar(1), /mantive o índice/);
    assert.equal([...banco.linhas.values()].filter((l) => l.fonte === "sgp").length, antes);
});

test("exporta ano a ano e junta num CSV só; falha em um ano derruba tudo", async () => {
    const pedidos = [];
    const ler = async (caminho) => { pedidos.push(caminho); return { status: 200, html: `Nome,Celular,Tipo\nA,119${String(10000000 + pedidos.length)},Celular` }; };
    const csv = await baixarCsvPorAno({ ler, anoFinal: 2013, pausa: 0 });
    assert.equal(pedidos.length, 2); // 2012 e 2013
    assert.match(pedidos[0], /data_cadastro_inicial=01\/01\/2012&data_cadastro_final=31\/12\/2012/);
    assert.equal(csv.split("\n").filter((l) => l.startsWith("Nome,")).length, 1); // um cabeçalho só
    assert.equal(telefonesDoCsv(csv).length, 2);
    // ano sem clientes: tela de busca = vazio (não é erro)
    const vazio = await baixarCsvPorAno({ ler: async () => ({ status: 200, html: '<html><form id="form"></form></html>' }), anoFinal: 2012, pausa: 0 });
    assert.equal(vazio, "");
    await assert.rejects(() => baixarCsvPorAno({ ler: async () => ({ status: 200, html: '<html><form id="form"></form><input id="id_username"></html>' }), anoFinal: 2012, pausa: 0 }), /não devolveu o CSV/);
    await assert.rejects(() => baixarCsvPorAno({ ler: async () => ({ status: 500, html: "erro" }), anoFinal: 2012, pausa: 0 }), /não devolveu o CSV/);
    await assert.rejects(() => baixarCsvPorAno({ ler: async () => ({ status: 200, html: "<html>login</html>" }), anoFinal: 2012, pausa: 0 }), /não devolveu o CSV/);
});

test("atualização em segundo plano: não duplica enquanto roda e guarda o erro", async () => {
    let solta; const trava = new Promise((r) => { solta = r; });
    const banco = bancoFalso();
    const idx = criarIndiceTelefones({ banco, baixarCsv: async () => { await trava; return csvCom(60); }, registrar: async () => {} });
    assert.equal(idx.iniciarAtualizacao(1), true);
    assert.equal(idx.iniciarAtualizacao(1), false); // já está rodando
    assert.equal((await idx.estatisticas(1)).atualizando, true);
    solta(); await new Promise((r) => setTimeout(r, 30));
    assert.equal((await idx.estatisticas(1)).atualizando, false);
    const ruim = criarIndiceTelefones({ banco, baixarCsv: async () => csvCom(3), registrar: async () => {} });
    ruim.iniciarAtualizacao(1); await new Promise((r) => setTimeout(r, 30));
    assert.match((await ruim.estatisticas(1)).erro, /mantive o índice|veio com/);
});
