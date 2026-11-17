import test from "node:test";
import assert from "node:assert/strict";
import express from "express";

process.env.ESCRITORIO_URL = "http://127.0.0.1:9";
process.env.ESCRITORIO_PUBLIC_URL = "http://192.168.1.133:8790";
process.env.ESCRITORIO_TOKEN = "token-de-teste";
delete process.env.ESCRITORIO_USUARIOS;
delete process.env.AMBIENTE_TESTE;

const { usuarioPodeVerEscritorio } = await import("../src/services/escritorioService.js");
const { criarRotasEscritorio } = await import("../src/Routes/escritorioRoutes.js");

test("só quem está na lista ESCRITORIO_USUARIOS abre o Escritório", () => {
    const env = { ESCRITORIO_USUARIOS: "3, 7" };
    assert.equal(usuarioPodeVerEscritorio({ id: 3 }, env), true);
    assert.equal(usuarioPodeVerEscritorio({ id: "7" }, env), true);
    assert.equal(usuarioPodeVerEscritorio({ id: 4 }, env), false);
    assert.equal(usuarioPodeVerEscritorio({ id: 33 }, env), false); // "3" não vale para 33
    assert.equal(usuarioPodeVerEscritorio({}, env), false);
    assert.equal(usuarioPodeVerEscritorio(null, env), false);
});

test("sem a lista: produção fecha para todos; só o ambiente de testes libera", () => {
    assert.equal(usuarioPodeVerEscritorio({ id: 3 }, {}), false);
    assert.equal(usuarioPodeVerEscritorio({ id: 3 }, { ESCRITORIO_USUARIOS: "" }), false);
    assert.equal(usuarioPodeVerEscritorio({ id: 3 }, { AMBIENTE_TESTE: "1" }), true);
    assert.equal(usuarioPodeVerEscritorio({ id: 3 }, { AMBIENTE_TESTE: "1", ESCRITORIO_USUARIOS: "9" }), false); // a lista manda
});

async function chamar(usuario, caminho) {
    const app = express();
    app.use("/api/escritorio", criarRotasEscritorio({ auth: (req, _res, next) => { req.user = usuario; next(); } }));
    const servidor = await new Promise((ok) => { const s = app.listen(0, "127.0.0.1", () => ok(s)); });
    try {
        const r = await fetch(`http://127.0.0.1:${servidor.address().port}/api/escritorio${caminho}`);
        return r.json();
    } finally {
        servidor.close();
    }
}

test("rotas: o Lucas (id 3) vê e abre; outro usuário não vê nem recebe bilhete", async () => {
    process.env.ESCRITORIO_USUARIOS = "3";
    try {
        assert.deepEqual(await chamar({ id: 3, perfil: "admin" }, "/disponivel"), { disponivel: true });
        const sso = await chamar({ id: 3, perfil: "admin" }, "/sso");
        assert.equal(sso.ativo, true);
        assert.match(sso.url, /^http:\/\/192\.168\.1\.133:8790\/sso\?ticket=/);
        assert.deepEqual(await chamar({ id: 5, perfil: "admin" }, "/disponivel"), { disponivel: false });
        assert.deepEqual(await chamar({ id: 5, perfil: "operator" }, "/sso"), { ativo: false });
    } finally {
        delete process.env.ESCRITORIO_USUARIOS;
    }
});

test("rotas: sem ligação configurada (sem URL/token) ninguém vê, nem o Lucas", async () => {
    const url = process.env.ESCRITORIO_URL;
    process.env.ESCRITORIO_USUARIOS = "3";
    delete process.env.ESCRITORIO_URL;
    try {
        assert.deepEqual(await chamar({ id: 3, perfil: "admin" }, "/disponivel"), { disponivel: false });
        assert.deepEqual(await chamar({ id: 3, perfil: "admin" }, "/sso"), { ativo: false });
    } finally {
        process.env.ESCRITORIO_URL = url;
        delete process.env.ESCRITORIO_USUARIOS;
    }
});
