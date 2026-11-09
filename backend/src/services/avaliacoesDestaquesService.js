// Avaliações do atendimento em destaque: o administrador escolhe quais aparecem no Início do Workspace.
// Guarda uma cópia da nota/comentário (sem nome do cliente) para o destaque não sumir quando o período do feed passar.
import db from "../db/db.js";

let pronta = null;
export const garantirTabelaDestaques = () => {
    pronta ??= db.query(`
        CREATE TABLE IF NOT EXISTS avaliacao_destaques (
            empresa_id INT NOT NULL,
            protocolo VARCHAR(40) NOT NULL,
            nota TINYINT NOT NULL,
            comentario TEXT NULL,
            tecnico VARCHAR(120) NOT NULL DEFAULT '',
            assunto VARCHAR(160) NOT NULL DEFAULT '',
            respondido_em VARCHAR(40) NOT NULL DEFAULT '',
            destacado_por INT NULL,
            criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (empresa_id, protocolo)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `).catch((e) => { pronta = null; throw e; });
    return pronta;
};

const linha = (r) => ({
    protocolo: r.protocolo, nota: Number(r.nota), comentario: r.comentario || "",
    tecnico: r.tecnico || "", assunto: r.assunto || "", respondidoEm: r.respondido_em || "",
    destacadoEm: r.criado_em,
});

export async function protocolosDestacados(empresaId) {
    await garantirTabelaDestaques();
    const [rows] = await db.query("SELECT protocolo FROM avaliacao_destaques WHERE empresa_id = ?", [empresaId]);
    return new Set(rows.map((r) => r.protocolo));
}

export async function listarDestaques(empresaId, limite = 12) {
    await garantirTabelaDestaques();
    const [rows] = await db.query(
        "SELECT * FROM avaliacao_destaques WHERE empresa_id = ? ORDER BY criado_em DESC LIMIT ?",
        [empresaId, limite],
    );
    return rows.map(linha);
}

export async function destacar(empresaId, avaliacao, adminId) {
    await garantirTabelaDestaques();
    await db.query(
        `INSERT INTO avaliacao_destaques (empresa_id, protocolo, nota, comentario, tecnico, assunto, respondido_em, destacado_por)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE nota = VALUES(nota), comentario = VALUES(comentario), tecnico = VALUES(tecnico),
           assunto = VALUES(assunto), respondido_em = VALUES(respondido_em)`,
        [empresaId, avaliacao.protocolo, avaliacao.nota, avaliacao.comentario || null, avaliacao.tecnico || "",
            avaliacao.assunto || "", avaliacao.respondidoEm || "", adminId ?? null],
    );
}

export async function removerDestaque(empresaId, protocolo) {
    await garantirTabelaDestaques();
    await db.query("DELETE FROM avaliacao_destaques WHERE empresa_id = ? AND protocolo = ?", [empresaId, protocolo]);
}
