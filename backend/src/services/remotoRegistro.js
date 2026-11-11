// Quais computadores já se registraram no servidor de suporte remoto (RustDesk, hbbs). O hbbs guarda cada ID que já falou com ele
// num SQLite; ler esse arquivo (só leitura) diz se um PC "existe" para o servidor. Não diz se está ligado agora, mas separa
// o computador que NUNCA se registrou (e que sempre vai dar "computador remoto offline") de um que só está desligado.
import { DatabaseSync } from "node:sqlite";

const CAMINHO = () => process.env.RUSTDESK_DB || "/home/noc/rustdesk-server/dados/db_v2.sqlite3";
const VALIDADE_MS = 10_000;
let cache = { ate: 0, ids: null };

/** Conjunto de IDs registrados, ou null se o arquivo do servidor não pôde ser lido (nesse caso ninguém é marcado como "não registrado"). */
export function idsRegistrados({ caminho = CAMINHO(), agora = Date.now() } = {}) {
    if (cache.ate > agora && cache.caminho === caminho) return cache.ids;
    let ids = null;
    try {
        const banco = new DatabaseSync(caminho, { readOnly: true });
        try { ids = new Set(banco.prepare("SELECT id FROM peer").all().map((l) => String(l.id))); } finally { banco.close(); }
    } catch { ids = null; }
    cache = { ate: agora + VALIDADE_MS, ids, caminho };
    return ids;
}

/** true/false quando dá para saber; null quando o servidor de suporte não pôde ser consultado. */
export function estaRegistrado(id, opcoes) {
    const ids = idsRegistrados(opcoes);
    return ids === null ? null : ids.has(String(id));
}

export function limparCacheRegistro() { cache = { ate: 0, ids: null }; }
