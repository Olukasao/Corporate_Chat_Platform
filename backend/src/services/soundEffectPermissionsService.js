import db from "../db/db.js";
import { VOLUME_PADRAO_USUARIO_PERCENT, VOLUME_ABSOLUTO_PERCENT, limitarVolumePercent } from "./soundEffectVolume.js";

let soundEffectPermissionsTabelaGarantida = false;
let soundEffectPermissionsTabelaGarantidaPromise = null;

const DEFAULT_OWNER_MATCH = "lucas";
// O dono padrão pode disparar com volume amplificado; os demais ficam no limite da coluna max_volume_percent.
// O dono padrão dispara sem espera entre os sons (desligue com SOUND_EFFECT_OWNER_NO_TIME_LIMIT=false).
const donoSemLimiteDeTempo = () => String(process.env.SOUND_EFFECT_OWNER_NO_TIME_LIMIT ?? "true").trim().toLowerCase() !== "false";
const obterVolumeMaximoDono = () => limitarVolumePercent(process.env.SOUND_EFFECT_OWNER_MAX_VOLUME_PERCENT, VOLUME_ABSOLUTO_PERCENT);
const DEFAULT_TARGET_GROUP_NAME = "NOC";
const BLOCKED_TARGET_FIRST_NAMES = ["samuel", "diego", "carlos", "dalton"];
const BLOCKED_TARGET_USER_IDS = new Set([31]); // Leonardo Silva

const normalizarTexto = (valor = "") => (
    String(valor || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .trim()
);

const obterIdsDonoPadrao = () => (
    String(process.env.SOUND_EFFECT_OWNER_USER_IDS || "")
        .split(",")
        .map((item) => Number(item.trim()))
        .filter((id) => Number.isInteger(id) && id > 0)
);

const obterMarcadoresDonoPadrao = () => {
    const marcadores = String(process.env.SOUND_EFFECT_OWNER_MATCH || DEFAULT_OWNER_MATCH)
        .split(",")
        .map(normalizarTexto)
        .filter(Boolean);

    return marcadores.length ? marcadores : [DEFAULT_OWNER_MATCH];
};

const usuarioCombinaComDonoPadrao = (usuario = {}) => {
    const userId = Number(usuario.id);
    const idsDono = obterIdsDonoPadrao();

    if (idsDono.includes(userId)) return true;

    const marcadores = obterMarcadoresDonoPadrao();
    const nome = normalizarTexto(usuario.nome);
    const primeiroNome = nome.split(/\s+/)[0] || "";
    const email = normalizarTexto(usuario.email);
    const emailLocal = email.split("@")[0] || "";

    return marcadores.some((marcador) => (
        primeiroNome === marcador ||
        emailLocal === marcador ||
        emailLocal.startsWith(`${marcador}.`) ||
        emailLocal.startsWith(`${marcador}_`) ||
        emailLocal.startsWith(`${marcador}-`)
    ));
};

// Contas bloqueadas para todo mundo, mas liberadas SÓ para o dono dos efeitos sonoros (o Lucas): Samuel (23), Leonardo Silva (31) e Diego (33).
// Ajustável por SOUND_EFFECT_OWNER_ALLOWED_TARGET_USER_IDS (ids separados por vírgula).
const obterAlvosLiberadosAoDono = () => new Set(
    String(process.env.SOUND_EFFECT_OWNER_ALLOWED_TARGET_USER_IDS ?? "23,31,33")
        .split(",")
        .map((item) => Number(item.trim()))
        .filter((id) => Number.isInteger(id) && id > 0),
);
export const alvoLiberadoAoDono = (alvo = {}) => Boolean(alvo) && obterAlvosLiberadosAoDono().has(Number(alvo.id));

const usuarioBloqueadoParaReceberEfeitoSonoro = (usuario = {}, remetente = null) => {
    if (!usuario) return false;
    // o dono pode enviar para as contas liberadas só a ele; para todos os outros o bloqueio continua
    if (remetente && alvoLiberadoAoDono(usuario) && usuarioCombinaComDonoPadrao(remetente)) return false;
    if (BLOCKED_TARGET_USER_IDS.has(Number(usuario.id))) return true;

    const primeiroNome = normalizarTexto(usuario.nome).split(/\s+/)[0] || "";
    return BLOCKED_TARGET_FIRST_NAMES.includes(primeiroNome);
};

// Destinos exclusivos do dono dos efeitos sonoros (por padrão o Lucas): contas que só ele pode alcançar, mesmo que estejam ou venham a
// entrar no grupo-alvo. Por padrão a conta "NOC" (a do monitor). Ajustável por SOUND_EFFECT_OWNER_ONLY_TARGET_USER_IDS (ids) e
// SOUND_EFFECT_OWNER_ONLY_TARGET_NAMES (nomes completos, separados por vírgula).
const obterAlvosSoDoDono = () => ({
    ids: new Set(
        String(process.env.SOUND_EFFECT_OWNER_ONLY_TARGET_USER_IDS || "")
            .split(",")
            .map((item) => Number(item.trim()))
            .filter((id) => Number.isInteger(id) && id > 0),
    ),
    nomes: new Set(
        String(process.env.SOUND_EFFECT_OWNER_ONLY_TARGET_NAMES ?? "noc")
            .split(",")
            .map(normalizarTexto)
            .filter(Boolean),
    ),
});

export const alvoExclusivoDoDono = (alvo = {}) => {
    if (!alvo) return false;
    const { ids, nomes } = obterAlvosSoDoDono();
    return ids.has(Number(alvo.id)) || nomes.has(normalizarTexto(alvo.nome));
};

/** Quem é o dono dos efeitos sonoros (o mesmo critério das permissões: por padrão o Lucas). */
export const usuarioEhDonoDosEfeitosSonoros = (usuario = {}) => usuarioCombinaComDonoPadrao(usuario);

export const obterNomeGrupoAlvoEfeitosSonoros = () => (
    String(process.env.SOUND_EFFECT_TARGET_GROUP_NAME || DEFAULT_TARGET_GROUP_NAME)
        .trim()
        || DEFAULT_TARGET_GROUP_NAME
);

export const garantirTabelaPermissoesEfeitosSonoros = async () => {
    if (soundEffectPermissionsTabelaGarantida) return;
    if (soundEffectPermissionsTabelaGarantidaPromise) {
        return soundEffectPermissionsTabelaGarantidaPromise;
    }

    soundEffectPermissionsTabelaGarantidaPromise = (async () => {
        await db.query(`
            CREATE TABLE IF NOT EXISTS sound_effect_permissions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                can_use TINYINT(1) NOT NULL DEFAULT 1,
                can_manage TINYINT(1) NOT NULL DEFAULT 0,
                granted_by INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                FOREIGN KEY (granted_by) REFERENCES usuarios(id) ON DELETE SET NULL,
                UNIQUE KEY unique_sound_effect_permission_user (user_id),
                INDEX idx_sound_effect_permissions_can_use (can_use),
                INDEX idx_sound_effect_permissions_can_manage (can_manage)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);

        await db.query(`
            ALTER TABLE sound_effect_permissions
            ADD COLUMN IF NOT EXISTS can_use TINYINT(1) NOT NULL DEFAULT 1
        `);

        await db.query(`
            ALTER TABLE sound_effect_permissions
            ADD COLUMN IF NOT EXISTS can_manage TINYINT(1) NOT NULL DEFAULT 0
        `);

        await db.query(`
            ALTER TABLE sound_effect_permissions
            ADD COLUMN IF NOT EXISTS granted_by INT NULL
        `);

        await db.query(`
            ALTER TABLE sound_effect_permissions
            ADD COLUMN IF NOT EXISTS max_volume_percent SMALLINT NOT NULL DEFAULT ${VOLUME_PADRAO_USUARIO_PERCENT}
        `);

        await db.query(`
            ALTER TABLE sound_effect_permissions
            ADD COLUMN IF NOT EXISTS no_time_limit TINYINT(1) NOT NULL DEFAULT 0
        `);

        soundEffectPermissionsTabelaGarantida = true;
    })();

    try {
        await soundEffectPermissionsTabelaGarantidaPromise;
    } finally {
        soundEffectPermissionsTabelaGarantidaPromise = null;
    }
};

export const garantirDonoPadraoEfeitosSonoros = async (empresaId = null) => {
    await garantirTabelaPermissoesEfeitosSonoros();

    const empresa = Number(empresaId);
    if (!Number.isInteger(empresa) || empresa <= 0) return;

    const [gerentes] = await db.query(`
        SELECT sep.user_id
        FROM sound_effect_permissions sep
        JOIN usuarios u ON u.id = sep.user_id
        WHERE u.empresa_id = ?
          AND u.deletado_em IS NULL
          AND sep.can_manage = 1
        LIMIT 1
    `, [empresa]);

    if (gerentes.length) return;

    const idsDono = obterIdsDonoPadrao();
    const marcadores = obterMarcadoresDonoPadrao();
    const params = [empresa];
    const criterios = [];

    if (idsDono.length) {
        criterios.push(`u.id IN (?)`);
        params.push(idsDono);
    }

    marcadores.forEach((marcador) => {
        criterios.push(`
            LOWER(u.nome) = ?
            OR LOWER(u.nome) LIKE ?
            OR LOWER(SUBSTRING_INDEX(u.email, '@', 1)) = ?
            OR LOWER(SUBSTRING_INDEX(u.email, '@', 1)) LIKE ?
            OR LOWER(SUBSTRING_INDEX(u.email, '@', 1)) LIKE ?
            OR LOWER(SUBSTRING_INDEX(u.email, '@', 1)) LIKE ?
        `);
        params.push(
            marcador,
            `${marcador} %`,
            marcador,
            `${marcador}.%`,
            `${marcador}_%`,
            `${marcador}-%`,
        );
    });

    if (!criterios.length) return;

    const [donos] = await db.query(`
        SELECT u.id
        FROM usuarios u
        WHERE u.empresa_id = ?
          AND u.deletado_em IS NULL
          AND (${criterios.map((criterio) => `(${criterio})`).join(" OR ")})
        ORDER BY u.id ASC
        LIMIT 1
    `, params);

    const dono = donos[0];
    if (!dono?.id) return;

    await db.query(`
        INSERT INTO sound_effect_permissions (user_id, can_use, can_manage, granted_by)
        VALUES (?, 1, 1, NULL)
        ON DUPLICATE KEY UPDATE
            can_use = 1,
            can_manage = 1
    `, [dono.id]);
};

export const obterPermissaoEfeitosSonoros = async (usuario = {}) => {
    await garantirTabelaPermissoesEfeitosSonoros();
    await garantirDonoPadraoEfeitosSonoros(usuario.empresa_id);

    if (usuarioCombinaComDonoPadrao(usuario)) {
        await db.query(`
            INSERT INTO sound_effect_permissions (user_id, can_use, can_manage, granted_by)
            VALUES (?, 1, 1, NULL)
            ON DUPLICATE KEY UPDATE
                can_use = 1,
                can_manage = 1
        `, [usuario.id]);
    }

    const [rows] = await db.query(`
        SELECT can_use, can_manage, max_volume_percent, no_time_limit
        FROM sound_effect_permissions
        WHERE user_id = ?
        LIMIT 1
    `, [usuario.id]);

    const permissao = rows[0] || {};
    const maxDaColuna = limitarVolumePercent(permissao.max_volume_percent);
    const maxVolume = usuarioCombinaComDonoPadrao(usuario) ? Math.max(maxDaColuna, obterVolumeMaximoDono()) : maxDaColuna;

    return {
        can_use: Boolean(permissao.can_use || permissao.can_manage),
        can_manage: Boolean(permissao.can_manage),
        max_volume_percent: maxVolume,
        no_time_limit: Boolean(permissao.no_time_limit) || (usuarioCombinaComDonoPadrao(usuario) && donoSemLimiteDeTempo()),
    };
};

export const usuarioPodeUsarEfeitosSonoros = async (usuario = {}) => {
    const permissao = await obterPermissaoEfeitosSonoros(usuario);
    return Boolean(permissao.can_use || permissao.can_manage);
};

export const usuarioPodeGerenciarEfeitosSonoros = async (usuario = {}) => {
    const permissao = await obterPermissaoEfeitosSonoros(usuario);
    return Boolean(permissao.can_manage);
};

export const listarUsuariosAlvoEfeitosSonoros = async (usuario = {}) => {
    const grupoAlvo = obterNomeGrupoAlvoEfeitosSonoros();

    const [usuarios] = await db.query(`
        SELECT DISTINCT
            u.id,
            u.nome,
            u.email,
            u.avatar,
            u.status,
            u.ultimo_acesso,
            s.nome AS setor_nome
        FROM usuarios u
        JOIN grupo_membros gm ON gm.usuario_id = u.id
        JOIN grupos g ON g.id = gm.grupo_id
        LEFT JOIN setores s ON u.setor_id = s.id
        WHERE u.empresa_id = ?
          AND u.id != ?
          AND u.deletado_em IS NULL
          AND g.empresa_id = u.empresa_id
          AND g.deletado_em IS NULL
          AND UPPER(TRIM(g.nome)) = UPPER(TRIM(?))
        ORDER BY u.status DESC, u.nome ASC
    `, [usuario.empresa_id, usuario.id, grupoAlvo]);

    const dono = usuarioEhDonoDosEfeitosSonoros(usuario);
    // quem não é o dono nunca vê nem alcança os destinos exclusivos dele
    const lista = usuarios.filter((usuarioAlvo) => !usuarioBloqueadoParaReceberEfeitoSonoro(usuarioAlvo, usuario) && (dono || !alvoExclusivoDoDono(usuarioAlvo)));
    if (!dono) return lista;

    // o dono também alcança os destinos exclusivos (ex.: a conta NOC), mesmo fora do grupo-alvo
    const { ids, nomes } = obterAlvosSoDoDono();
    const criterios = [];
    const params = [usuario.empresa_id, usuario.id];
    if (ids.size) { criterios.push("u.id IN (?)"); params.push([...ids]); }
    if (nomes.size) { criterios.push("LOWER(TRIM(u.nome)) IN (?)"); params.push([...nomes]); }
    const liberados = obterAlvosLiberadosAoDono();
    if (liberados.size) { criterios.push("u.id IN (?)"); params.push([...liberados]); }
    if (!criterios.length) return lista;
    const [exclusivos] = await db.query(`
        SELECT u.id, u.nome, u.email, u.avatar, u.status, u.ultimo_acesso, s.nome AS setor_nome
        FROM usuarios u
        LEFT JOIN setores s ON u.setor_id = s.id
        WHERE u.empresa_id = ?
          AND u.id != ?
          AND u.deletado_em IS NULL
          AND (${criterios.join(" OR ")})
        ORDER BY u.nome ASC
    `, params);
    const jaNaLista = new Set(lista.map((u) => Number(u.id)));
    return [...lista, ...exclusivos.filter((u) => !jaNaLista.has(Number(u.id)) && !usuarioBloqueadoParaReceberEfeitoSonoro(u, usuario))];
};

export const buscarUsuarioAlvoEfeitoSonoro = async (usuario = {}, targetUserId = null) => {
    const idAlvo = Number(targetUserId);

    if (!Number.isInteger(idAlvo) || idAlvo <= 0) return null;

    const grupoAlvo = obterNomeGrupoAlvoEfeitosSonoros();
    const [usuarios] = await db.query(`
        SELECT DISTINCT
            u.id,
            u.nome,
            u.email,
            u.empresa_id,
            u.status
        FROM usuarios u
        JOIN grupo_membros gm ON gm.usuario_id = u.id
        JOIN grupos g ON g.id = gm.grupo_id
        WHERE u.id = ?
          AND u.empresa_id = ?
          AND u.deletado_em IS NULL
          AND g.empresa_id = u.empresa_id
          AND g.deletado_em IS NULL
          AND UPPER(TRIM(g.nome)) = UPPER(TRIM(?))
        LIMIT 1
    `, [idAlvo, usuario.empresa_id, grupoAlvo]);

    let alvo = usuarios[0] || null;

    if (usuarioBloqueadoParaReceberEfeitoSonoro(alvo, usuario)) return null;

    // destinos exclusivos do dono (ex.: a conta NOC): só o dono alcança, esteja ou não no grupo-alvo
    if (alvo && alvoExclusivoDoDono(alvo) && !usuarioEhDonoDosEfeitosSonoros(usuario)) return null;
    if (!alvo && usuarioEhDonoDosEfeitosSonoros(usuario)) {
        const [diretos] = await db.query(`
            SELECT u.id, u.nome, u.email, u.empresa_id, u.status
            FROM usuarios u
            WHERE u.id = ? AND u.empresa_id = ? AND u.deletado_em IS NULL
            LIMIT 1
        `, [idAlvo, usuario.empresa_id]);
        const candidato = diretos[0] || null;
        if (candidato && (alvoExclusivoDoDono(candidato) || alvoLiberadoAoDono(candidato)) && !usuarioBloqueadoParaReceberEfeitoSonoro(candidato, usuario)) alvo = candidato;
    }

    return alvo;
};

export const listarPermissoesEfeitosSonoros = async (usuario = {}) => {
    await garantirDonoPadraoEfeitosSonoros(usuario.empresa_id);

    const [rows] = await db.query(`
        SELECT
            u.id,
            u.nome,
            u.email,
            u.status,
            u.ultimo_acesso,
            s.nome AS setor_nome,
            COALESCE(sep.can_use, 0) AS can_use,
            COALESCE(sep.can_manage, 0) AS can_manage,
            COALESCE(sep.max_volume_percent, ${VOLUME_PADRAO_USUARIO_PERCENT}) AS max_volume_percent,
            COALESCE(sep.no_time_limit, 0) AS no_time_limit,
            sep.granted_by,
            sep.updated_at
        FROM usuarios u
        LEFT JOIN setores s ON s.id = u.setor_id
        LEFT JOIN sound_effect_permissions sep ON sep.user_id = u.id
        WHERE u.empresa_id = ?
          AND u.deletado_em IS NULL
        ORDER BY u.nome ASC
    `, [usuario.empresa_id]);

    return rows.map((row) => ({
        ...row,
        can_use: Boolean(row.can_use || row.can_manage),
        can_manage: Boolean(row.can_manage),
        max_volume_percent: usuarioCombinaComDonoPadrao(row)
            ? Math.max(limitarVolumePercent(row.max_volume_percent), obterVolumeMaximoDono())
            : limitarVolumePercent(row.max_volume_percent),
        no_time_limit: Boolean(row.no_time_limit) || (usuarioCombinaComDonoPadrao(row) && donoSemLimiteDeTempo()),
    }));
};

export const definirPermissaoUsoEfeitosSonoros = async ({
    usuario,
    targetUserId,
    enabled,
} = {}) => {
    await garantirTabelaPermissoesEfeitosSonoros();

    const idAlvo = Number(targetUserId);
    if (!Number.isInteger(idAlvo) || idAlvo <= 0) {
        const error = new Error("Usuário inválido.");
        error.status = 400;
        throw error;
    }

    const [usuarios] = await db.query(`
        SELECT id, nome, email, empresa_id
        FROM usuarios
        WHERE id = ?
          AND empresa_id = ?
          AND deletado_em IS NULL
        LIMIT 1
    `, [idAlvo, usuario.empresa_id]);

    const alvo = usuarios[0];
    if (!alvo) {
        const error = new Error("Usuário não encontrado.");
        error.status = 404;
        throw error;
    }

    if (enabled) {
        await db.query(`
            INSERT INTO sound_effect_permissions (user_id, can_use, can_manage, granted_by)
            VALUES (?, 1, 0, ?)
            ON DUPLICATE KEY UPDATE
                can_use = 1,
                granted_by = VALUES(granted_by)
        `, [idAlvo, usuario.id]);
    } else {
        await db.query(`
            UPDATE sound_effect_permissions
            SET can_use = 0,
                granted_by = ?
            WHERE user_id = ?
              AND can_manage = 0
        `, [usuario.id, idAlvo]);
    }

    return alvo;
};

/** Define até quantos % de volume uma pessoa pode usar ao disparar (0 a 200). Só quem gerencia os efeitos. */
export const definirVolumeMaximoEfeitosSonoros = async ({ usuario, targetUserId, percent } = {}) => {
    await garantirTabelaPermissoesEfeitosSonoros();

    const idAlvo = Number(targetUserId);
    const maximo = Number(percent);
    if (!Number.isInteger(idAlvo) || idAlvo <= 0 || !Number.isFinite(maximo)) {
        const error = new Error("Informe o usuário e um volume de 0 a 200.");
        error.status = 400;
        throw error;
    }

    const [usuarios] = await db.query(`
        SELECT id FROM usuarios WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL LIMIT 1
    `, [idAlvo, usuario.empresa_id]);
    if (!usuarios[0]) {
        const error = new Error("Usuário não encontrado.");
        error.status = 404;
        throw error;
    }

    const valor = limitarVolumePercent(maximo);
    await db.query(`
        INSERT INTO sound_effect_permissions (user_id, can_use, can_manage, granted_by, max_volume_percent)
        VALUES (?, 0, 0, ?, ?)
        ON DUPLICATE KEY UPDATE
            max_volume_percent = VALUES(max_volume_percent),
            granted_by = VALUES(granted_by)
    `, [idAlvo, usuario.id, valor]);

    return valor;
};

/** Liga ou desliga a dispensa dos tempos de espera (limite por minuto e espera por funcionário). Só quem gerencia. */
export const definirSemLimiteDeTempoEfeitosSonoros = async ({ usuario, targetUserId, enabled } = {}) => {
    await garantirTabelaPermissoesEfeitosSonoros();

    const idAlvo = Number(targetUserId);
    if (!Number.isInteger(idAlvo) || idAlvo <= 0) {
        const error = new Error("Usuário inválido.");
        error.status = 400;
        throw error;
    }

    const [usuarios] = await db.query(`
        SELECT id FROM usuarios WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL LIMIT 1
    `, [idAlvo, usuario.empresa_id]);
    if (!usuarios[0]) {
        const error = new Error("Usuário não encontrado.");
        error.status = 404;
        throw error;
    }

    await db.query(`
        INSERT INTO sound_effect_permissions (user_id, can_use, can_manage, granted_by, no_time_limit)
        VALUES (?, 0, 0, ?, ?)
        ON DUPLICATE KEY UPDATE
            no_time_limit = VALUES(no_time_limit),
            granted_by = VALUES(granted_by)
    `, [idAlvo, usuario.id, enabled ? 1 : 0]);
};
