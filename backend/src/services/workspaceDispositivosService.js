// Computadores que usam o Acessa Workspace: o app se anuncia pelo socket (com um identificador do computador) e
// o servidor guarda quem, de onde, em qual versão e quando foi visto pela última vez. Também lê a versão publicada
// no servidor de atualizações e grava o sinal que manda os PCs atualizarem.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import db from "../db/db.js";

const PASTA_CANAL = () => process.env.WORKSPACE_UPDATES_DIR
    || "/home/noc/acessa-workspace-updates/public/windows/stable";

const ID_DISPOSITIVO = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const VERSAO = /^\d{1,3}\.\d{1,3}\.\d{1,4}$/;

export const dispositivoValido = (v) => (typeof v === "string" && ID_DISPOSITIVO.test(v) ? v.toLowerCase() : null);
export const versaoValida = (v) => (typeof v === "string" && VERSAO.test(v) ? v : null);
export const nomeComputador = (v) => String(v ?? "").replace(/[^\p{L}\p{N} ._-]/gu, "").trim().slice(0, 80);
export const limparIp = (ip) => String(ip ?? "").replace(/^::ffff:/, "").slice(0, 45);

export function compararVersao(a, b) {
    const pa = String(a).split(".").map(Number), pb = String(b).split(".").map(Number);
    for (let i = 0; i < 3; i++) if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) - (pb[i] || 0);
    return 0;
}

/** "atualizado", "desatualizado" ou "desconhecida" (app muito antigo, que nem informa a versão). */
export function situacaoDaVersao(versao, publicada) {
    if (!versaoValida(versao) || !versaoValida(publicada)) return "desconhecida";
    return compararVersao(versao, publicada) >= 0 ? "atualizado" : "desatualizado";
}

export function lerVersaoPublicada(pasta = PASTA_CANAL()) {
    try {
        return /^version:\s*(\S+)/m.exec(fs.readFileSync(path.join(pasta, "latest.yml"), "utf8"))?.[1] || null;
    } catch {
        return null;
    }
}

export function lerSinal(pasta = PASTA_CANAL()) {
    try {
        const s = JSON.parse(fs.readFileSync(path.join(pasta, "signal.json"), "utf8"));
        return s && typeof s === "object" ? s : null;
    } catch {
        return null;
    }
}

/** Mesmo formato do force-update.mjs do servidor de atualizações. */
export function montarSinal({ versao, obrigatoria = false, mensagem = "", ignorarRegra = false }, agora = new Date()) {
    const texto = String(mensagem ?? "").trim().slice(0, 200);
    return {
        id: `${agora.getTime().toString(36)}-${crypto.randomBytes(4).toString("hex")}`,
        versao,
        obrigatoria: Boolean(obrigatoria),
        ...(ignorarRegra === true ? { ignorarRegra: true } : {}),
        ...(texto ? { mensagem: texto } : {}),
        criadoEm: agora.toISOString(),
    };
}

/** Publica o sinal de forma atômica. Os apps consultam o sinal a cada ~30 s. */
export function gravarSinal(opcoes, pasta = PASTA_CANAL()) {
    const versao = lerVersaoPublicada(pasta);
    if (!versao) throw Object.assign(new Error("Nenhuma versão publicada no canal de atualizações."), { status: 409 });
    const sinal = montarSinal({ ...opcoes, versao });
    const alvo = path.join(pasta, "signal.json");
    fs.writeFileSync(`${alvo}.tmp`, JSON.stringify(sinal), { mode: 0o644 });
    fs.renameSync(`${alvo}.tmp`, alvo);
    return sinal;
}

let tabelaPronta = null;
export function garantirTabelaDispositivos() {
    tabelaPronta ??= db.query(`
        CREATE TABLE IF NOT EXISTS workspace_dispositivos (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            usuario_id INT NOT NULL,
            dispositivo CHAR(36) NOT NULL,
            computador VARCHAR(80) NOT NULL DEFAULT '',
            ip VARCHAR(45) NOT NULL DEFAULT '',
            versao VARCHAR(16) NULL,
            primeiro_visto TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            ultimo_visto TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_workspace_dispositivo (empresa_id, usuario_id, dispositivo),
            KEY idx_workspace_dispositivo_visto (empresa_id, ultimo_visto)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `).catch((e) => { tabelaPronta = null; throw e; });
    return tabelaPronta;
}

/** O app se anunciou: grava ou atualiza o computador. */
export async function registrarVisto({ empresaId, usuarioId, dispositivo, computador, ip, versao }) {
    const id = dispositivoValido(dispositivo);
    if (!id) return false;
    await garantirTabelaDispositivos();
    await db.query(`
        INSERT INTO workspace_dispositivos (empresa_id, usuario_id, dispositivo, computador, ip, versao)
        VALUES (?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE computador = VALUES(computador), ip = VALUES(ip), versao = VALUES(versao), ultimo_visto = NOW()
    `, [empresaId, usuarioId, id, nomeComputador(computador), limparIp(ip), versaoValida(versao)]);
    return true;
}

/** O app fechou (ou a conexão caiu): carimba a última vez visto. */
export async function marcarSaida({ empresaId, usuarioId, dispositivo }) {
    const id = dispositivoValido(dispositivo);
    if (!id) return;
    await garantirTabelaDispositivos();
    await db.query(
        "UPDATE workspace_dispositivos SET ultimo_visto = NOW() WHERE empresa_id = ? AND usuario_id = ? AND dispositivo = ?",
        [empresaId, usuarioId, id],
    );
}

export async function listarDispositivos(empresaId) {
    await garantirTabelaDispositivos();
    const [linhas] = await db.query(`
        SELECT d.id, d.usuario_id, d.dispositivo, d.computador, d.ip, d.versao, d.primeiro_visto, d.ultimo_visto,
               u.nome AS usuario_nome, u.email AS usuario_email, s.nome AS setor_nome
        FROM workspace_dispositivos d
        JOIN usuarios u ON u.id = d.usuario_id AND u.deletado_em IS NULL
        LEFT JOIN setores s ON s.id = u.setor_id
        WHERE d.empresa_id = ?
        ORDER BY d.ultimo_visto DESC
        LIMIT 500
    `, [empresaId]);
    return linhas;
}

export async function removerDispositivo(empresaId, id) {
    await garantirTabelaDispositivos();
    await db.query("DELETE FROM workspace_dispositivos WHERE empresa_id = ? AND id = ?", [empresaId, Number(id)]);
}
