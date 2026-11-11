import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { estaRegistrado, idsRegistrados, limparCacheRegistro } from "./remotoRegistro.js";

function criarBanco(ids) {
    const dir = mkdtempSync(path.join(tmpdir(), "hbbs-"));
    const arquivo = path.join(dir, "db_v2.sqlite3");
    const banco = new DatabaseSync(arquivo);
    banco.exec("CREATE TABLE peer (guid blob primary key, id varchar(100), uuid blob, pk blob, created_at datetime, user blob, status tinyint, note varchar(300), info text)");
    for (const id of ids) banco.prepare("INSERT INTO peer (guid, id) VALUES (?, ?)").run(Buffer.from(id), id);
    banco.close();
    return { arquivo, limpar: () => rmSync(dir, { recursive: true, force: true }) };
}

test("diz se um ID já falou com o servidor de suporte remoto", () => {
    limparCacheRegistro();
    const { arquivo, limpar } = criarBanco(["111222333", "444555666"]);
    try {
        assert.equal(estaRegistrado("111222333", { caminho: arquivo }), true);
        assert.equal(estaRegistrado("999999999", { caminho: arquivo }), false);
        assert.equal(idsRegistrados({ caminho: arquivo }).size, 2);
    } finally { limpar(); }
});

test("se o arquivo do servidor não pode ser lido, ninguém é marcado como não registrado (null)", () => {
    limparCacheRegistro();
    assert.equal(estaRegistrado("111222333", { caminho: "/nao/existe/db.sqlite3" }), null);
});

test("o resultado é guardado por poucos segundos e depois relido", () => {
    limparCacheRegistro();
    const { arquivo, limpar } = criarBanco(["111222333"]);
    try {
        const t0 = 1_000_000;
        assert.equal(estaRegistrado("777888999", { caminho: arquivo, agora: t0 }), false);
        const banco = new DatabaseSync(arquivo);
        banco.prepare("INSERT INTO peer (guid, id) VALUES (?, ?)").run(Buffer.from("777888999"), "777888999");
        banco.close();
        assert.equal(estaRegistrado("777888999", { caminho: arquivo, agora: t0 + 2_000 }), false); // ainda no cache
        assert.equal(estaRegistrado("777888999", { caminho: arquivo, agora: t0 + 11_000 }), true); // releu
    } finally { limpar(); }
});
