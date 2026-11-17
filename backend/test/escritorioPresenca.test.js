import test from "node:test";
import assert from "node:assert/strict";

process.env.ESCRITORIO_URL = "http://127.0.0.1:9";
process.env.ESCRITORIO_TOKEN = "token-de-teste";
process.env.ESCRITORIO_EMPRESA_ID = "1";

const { enviarPresenca, definirFonteOnline } = await import("../src/services/escritorioService.js");
const { registrarWorkspace, removerWorkspace } = await import("../src/services/workspacePresenceService.js");

async function capturar(fn) {
    const original = globalThis.fetch;
    let corpo = null;
    globalThis.fetch = async (_url, opcoes) => { corpo = JSON.parse(opcoes.body); return { ok: true, json: async () => ({ accepted: 1 }) }; };
    try { await fn(); } finally { globalThis.fetch = original; }
    return corpo;
}

test("presença do mapa = Workspace aberto + conectados ao chat, sem repetir ninguém", async () => {
    registrarWorkspace("s-ws-1", { usuarioId: 3, empresaId: 1, versao: "0.6.60" });
    registrarWorkspace("s-ws-2", { usuarioId: 3, empresaId: 1, versao: "0.6.60" }); // mesma pessoa, duas janelas
    registrarWorkspace("s-outra", { usuarioId: 99, empresaId: 2, versao: "0.6.60" }); // outra empresa: não entra
    definirFonteOnline((empresaId) => (String(empresaId) === "1" ? ["3", "22", "34"] : []));
    try {
        const corpo = await capturar(() => enviarPresenca());
        assert.equal(corpo.companyId, "co_acessanet");
        assert.deepEqual([...corpo.employeeIds].sort(), ["emp_chat_22", "emp_chat_3", "emp_chat_34"]);
    } finally {
        removerWorkspace("s-ws-1"); removerWorkspace("s-ws-2"); removerWorkspace("s-outra");
        definirFonteOnline(null);
    }
});

test("só conectado ao chat (sem sinal do Workspace) também conta como online", async () => {
    definirFonteOnline(() => ["7"]);
    try {
        assert.deepEqual((await capturar(() => enviarPresenca())).employeeIds, ["emp_chat_7"]);
    } finally { definirFonteOnline(null); }
});

test("se a fonte do chat falhar, segue só com o sinal do Workspace (não derruba)", async () => {
    registrarWorkspace("s-ws-9", { usuarioId: 5, empresaId: 1, versao: "0.6.60" });
    definirFonteOnline(() => { throw new Error("falhou"); });
    try {
        assert.deepEqual((await capturar(() => enviarPresenca())).employeeIds, ["emp_chat_5"]);
    } finally { removerWorkspace("s-ws-9"); definirFonteOnline(null); }
});
