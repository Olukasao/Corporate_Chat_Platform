// Situação de presença além de online/ausente: manual ("almoço", "em visita"…) e automática ("em ligação").
// A manual fica no banco (sobrevive a reinício) e pode ter hora para acabar; "em ligação" vive só na memória.
import db from "../db/db.js";

export const SITUACOES = {
    almoco: "Em almoço",
    visita: "Em visita",
    reuniao: "Em reunião",
    ocupado: "Ocupado",
};
export const LIGACAO_MAX_MS = 3 * 60 * 60_000; // se o app travar no meio da ligação, some sozinho

let pronta = null;
export const garantirTabelaSituacao = (banco = db) => {
    pronta ??= banco.query(`
        CREATE TABLE IF NOT EXISTS usuario_situacao (
            empresa_id INT NOT NULL,
            usuario_id INT NOT NULL,
            situacao VARCHAR(20) NOT NULL,
            ate DATETIME NULL,
            atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (empresa_id, usuario_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `).catch((e) => { pronta = null; throw e; });
    return pronta;
};

/** Situação que vale agora: ligação > manual (se não venceu) > nenhuma. */
export function situacaoEfetiva({ manual, ate, ligacaoDesde }, agora = Date.now()) {
    if (ligacaoDesde && agora - ligacaoDesde < LIGACAO_MAX_MS) return { situacao: "ligacao", ate: null };
    if (manual && SITUACOES[manual] && (!ate || new Date(ate).getTime() > agora)) return { situacao: manual, ate: ate ? new Date(ate).toISOString() : null };
    return { situacao: null, ate: null };
}

export function criarServicoSituacao({ banco = db, agora = () => Date.now() } = {}) {
    const emLigacao = new Map(); // "empresa:usuario" -> desde (ms)
    const chave = (e, u) => `${e}:${u}`;

    const linhaManual = async (empresaId, usuarioId) => {
        await garantirTabelaSituacao(banco);
        const [rows] = await banco.query("SELECT situacao, ate FROM usuario_situacao WHERE empresa_id = ? AND usuario_id = ?", [empresaId, usuarioId]);
        return rows[0] || null;
    };
    const efetivaDe = async (empresaId, usuarioId) => {
        const m = await linhaManual(empresaId, usuarioId);
        return situacaoEfetiva({ manual: m?.situacao, ate: m?.ate, ligacaoDesde: emLigacao.get(chave(empresaId, usuarioId)) }, agora());
    };

    return {
        async listar(empresaId) {
            await garantirTabelaSituacao(banco);
            const [rows] = await banco.query("SELECT usuario_id, situacao, ate FROM usuario_situacao WHERE empresa_id = ?", [empresaId]);
            const mapa = new Map(rows.map((r) => [Number(r.usuario_id), r]));
            for (const k of emLigacao.keys()) { const [e, u] = k.split(":"); if (Number(e) === Number(empresaId) && !mapa.has(Number(u))) mapa.set(Number(u), {}); }
            const itens = [];
            for (const [usuario_id, r] of mapa) {
                const ef = situacaoEfetiva({ manual: r.situacao, ate: r.ate, ligacaoDesde: emLigacao.get(chave(empresaId, usuario_id)) }, agora());
                if (ef.situacao) itens.push({ usuario_id, ...ef });
            }
            return itens;
        },

        /** minutos = null/0 fica até a pessoa mudar; situacao = null volta ao normal. */
        async definir(empresaId, usuarioId, situacao, minutos) {
            await garantirTabelaSituacao(banco);
            if (situacao === null) {
                await banco.query("DELETE FROM usuario_situacao WHERE empresa_id = ? AND usuario_id = ?", [empresaId, usuarioId]);
            } else {
                if (!SITUACOES[situacao]) { const e = new Error("Situação inválida."); e.status = 400; throw e; }
                const min = Math.min(12 * 60, Math.max(0, Math.floor(Number(minutos) || 0)));
                const ate = min ? new Date(agora() + min * 60_000) : null;
                await banco.query(
                    `INSERT INTO usuario_situacao (empresa_id, usuario_id, situacao, ate) VALUES (?, ?, ?, ?)
                     ON DUPLICATE KEY UPDATE situacao = VALUES(situacao), ate = VALUES(ate)`,
                    [empresaId, usuarioId, situacao, ate],
                );
            }
            return efetivaDe(empresaId, usuarioId);
        },

        async marcarLigacao(empresaId, usuarioId, ativa) {
            if (ativa) emLigacao.set(chave(empresaId, usuarioId), agora()); else emLigacao.delete(chave(empresaId, usuarioId));
            return efetivaDe(empresaId, usuarioId);
        },

        efetiva: efetivaDe,
    };
}

export const servicoSituacao = criarServicoSituacao();
