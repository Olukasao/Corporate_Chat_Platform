import { Router } from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import dns from "dns/promises";
import os from "node:os";
import jwt from "jsonwebtoken";
import fs from "fs";
import net from "net";
import path from "path";
import { fileURLToPath } from "url";
import { execFile } from "child_process";
import { promisify } from "util";
import multer from "multer";
import sharp from "sharp";
import db from "../db/db.js";
import authMiddleware from "../middlewares/middleware.js";
import { registerDashboardRelayRoute } from "../services/dashboardRelayService.js";
import { maximoDeDias, montarPayloadRenovado, podeRenovar } from "../services/sessaoRenovacaoService.js";
import { dispositivosOnline, listarWorkspace } from "../services/workspacePresenceService.js";
import {
    gravarSinal, lerSinal, lerVersaoPublicada, listarDispositivos, removerDispositivo, situacaoDaVersao,
} from "../services/workspaceDispositivosService.js";
import { AGENDA_SESSION_COOKIE, definirSessaoAgenda, validarSessaoAgenda } from "../services/agendaSessionService.js";
import { obterResumoAgendaTecnicos } from "../services/agendaTecnicosResumoService.js";
import purchaseModuleRoutes, { userHasPurchasePermission } from "./purchaseModule.js";
import networkDiagnosticsRoutes from "./networkDiagnosticsRoutes.js";
import oltRoutes from "./oltRoutes.js";
import bmpRoutes from "./bmpRoutes.js";
import rouletteRoutes from "./rouletteRoutes.js";
import cursosRoutes from "./cursosRoutes.js";
import lembretesRoutes from "./lembretesRoutes.js";
import marketingRoutes from "./marketingRoutes.js";
import iaResumoRoutes from "./iaResumoRoutes.js";
import assistenteRoutes from "./assistenteRoutes.js";
import phoneRoutes, { criarPhoneAdminRoutes } from "./phoneRoutes.js";
import remotoRoutes, { criarRemotoAdminRoutes } from "./remotoRoutes.js";
import criarIaAdminRoutes from "./iaAdminRoutes.js";
import { listarFuncoes, modulosDoUsuario, salvarFuncao } from "../services/funcoesService.js";
import chamadosRoutes from "./chamadosRoutes.js";
import clienteLigacaoRoutes from "./clienteLigacaoRoutes.js";
import presencaRoutes from "./presencaRoutes.js";
import navegadorRoutes, { criarRotasNavegadorAdmin } from "./navegadorRoutes.js";
import { criarServicoSaude } from "../services/saudeService.js";
import { indiceTelefones } from "../services/indiceTelefonesService.js";
import { configDoRelatorio, enviarRelatorio } from "../services/relatorioSemanalService.js";
import { gravarConfig as gravarConfigIa, lerConfig as lerConfigIa } from "../services/iaAdminService.js";
import { destinatarios as destinatariosDoBriefing } from "../services/briefingService.js";
import { userHasNetworkDiagnosticPermission } from "../services/networkDiagnosticPermissionsService.js";
import {
    AUDIT_LEVELS,
    AUDIT_TYPES,
    listarAuditLogs,
    obterAuditLogPorId,
    obterResumoOperacional,
    registrarAuditoria,
} from "../services/auditService.js";
import { getJwtSecret } from "../config/authSecrets.js";
import { criarLimitadorLogin } from "../security/loginRateLimit.js";
import { lerExtensoesPermitidas, validarArquivoChat } from "../security/uploadSecurity.js";
import {
    CUSTOM_SOUNDS_ROOT,
    SOUND_EFFECT_UPLOAD_MAX_SIZE_BYTES,
    createSoundUploadFilename,
    isAllowedSoundUploadMime,
    listAllowedSoundEffects,
    normalizeSoundUploadExtension,
    registerUploadedSoundEffect,
    removeUploadedSoundFile,
    validateUploadedAudioFile,
} from "../services/soundEffectsService.js";
import {
    definirPermissaoUsoEfeitosSonoros,
    definirSemLimiteDeTempoEfeitosSonoros,
    definirVolumeMaximoEfeitosSonoros,
    listarPermissoesEfeitosSonoros,
    listarUsuariosAlvoEfeitosSonoros,
    obterNomeGrupoAlvoEfeitosSonoros,
    obterPermissaoEfeitosSonoros,
    usuarioPodeGerenciarEfeitosSonoros,
    usuarioPodeUsarEfeitosSonoros,
} from "../services/soundEffectPermissionsService.js";

const route = Router();
registerDashboardRelayRoute(route, authMiddleware);

route.post("/integrations/agenda/session", authMiddleware, (req, res) => {
    const sessaoToken = definirSessaoAgenda(req, res);
    res.set("Cache-Control", "no-store").json({ identificado: Boolean(sessaoToken), sessaoToken });
});

route.delete("/integrations/agenda/session", (_req, res) => {
    res.clearCookie(AGENDA_SESSION_COOKIE, { httpOnly: true, sameSite: "lax", path: "/" });
    res.set("Cache-Control", "no-store").json({ identificado: false });
});

route.post("/integrations/agenda/session/verify", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const sessao = validarSessaoAgenda(String(req.headers.authorization || "").replace(/^Bearer /, ""));
    if (!sessao) return res.status(401).json({ erro: "Sessão do chat expirada ou inválida." });
    try {
        const [rows] = await db.query("SELECT id, nome, perfil FROM usuarios WHERE id = ? AND deletado_em IS NULL LIMIT 1", [sessao.id]);
        if (!rows.length) return res.status(401).json({ erro: "Usuário do chat não encontrado." });
        res.json({ usuario: rows[0], sessaoId: sessao.sid, exp: sessao.exp });
    } catch {
        res.status(503).json({ erro: "Não foi possível validar a sessão do chat." });
    }
});

const getSecret = () => getJwtSecret();
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const CONTROLE_OPERACIONAL_ENABLED = process.env.CONTROLE_OPERACIONAL_ENABLED === "true";
const ATENDIMENTO_INTEGRATION_TOKEN = process.env.ATENDIMENTO_INTEGRATION_TOKEN || "";
const ATENDIMENTO_SSO_CLIENT_ID = "acessanet-atendimento";
const ATENDIMENTO_SSO_CODE_TTL_MS = Number(process.env.ATENDIMENTO_SSO_CODE_TTL_MS || 60_000);
const ATENDIMENTO_SSO_DEFAULT_REDIRECT_ORIGINS = [
    "https://atendimento.acessanet.com.br",
    "http://192.168.1.133:9520",
    "http://localhost:9520",
    "http://127.0.0.1:9520",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
];
const ATENDIMENTO_SSO_REDIRECT_ORIGINS = (process.env.ATENDIMENTO_SSO_REDIRECT_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
const atendimentoSsoCodes = new Map();

const PERFIL_ADMIN = "admin";
const PERFIL_ADMIN_COMERCIAL = "admin_comercial";
const PERFIL_USUARIO = "usuario";
const PERFIS_VALIDOS = [PERFIL_ADMIN, PERFIL_ADMIN_COMERCIAL, PERFIL_USUARIO];
const PERFIS_EDITOR_AVISOS_INTERNOS = [PERFIL_ADMIN, PERFIL_ADMIN_COMERCIAL];
const PERFIS_EDITOR_BIBLIOTECA_ATENDIMENTO = [PERFIL_ADMIN, PERFIL_ADMIN_COMERCIAL];

const obterBearerToken = (req) => {
    const authorization = req.headers.authorization || "";

    if (authorization.startsWith("Bearer ")) {
        return authorization.slice("Bearer ".length).trim();
    }

    return String(req.headers["x-atendimento-integration-token"] || "").trim();
};

const tokensIguais = (left, right) => {
    if (!left || !right) return false;

    const leftBuffer = Buffer.from(left);
    const rightBuffer = Buffer.from(right);

    return (
        leftBuffer.length === rightBuffer.length &&
        crypto.timingSafeEqual(leftBuffer, rightBuffer)
    );
};

const requireAtendimentoIntegration = (req, res, next) => {
    if (!ATENDIMENTO_INTEGRATION_TOKEN) {
        return res.status(503).json({ error: "Integração do atendimento não configurada" });
    }

    if (!tokensIguais(obterBearerToken(req), ATENDIMENTO_INTEGRATION_TOKEN)) {
        return res.status(401).json({ error: "Token de integração inválido" });
    }

    return next();
};

const limparCodigosSsoExpirados = () => {
    const agora = Date.now();

    for (const [hash, registro] of atendimentoSsoCodes.entries()) {
        if (registro.expiresAt <= agora) {
            atendimentoSsoCodes.delete(hash);
        }
    }
};

const hashCodigoSso = (codigo) => crypto.createHash("sha256").update(String(codigo)).digest("hex");

const gerarCodigoSso = () => crypto.randomBytes(32).toString("base64url");

const obterOrigensAtendimentoPermitidas = () => (
    new Set([
        ...ATENDIMENTO_SSO_DEFAULT_REDIRECT_ORIGINS,
        ...ATENDIMENTO_SSO_REDIRECT_ORIGINS,
    ])
);

const normalizarRedirectUriAtendimento = (redirectUri) => {
    if (typeof redirectUri !== "string" || redirectUri.length > 500) {
        return null;
    }

    try {
        const url = new URL(redirectUri);

        if (!["http:", "https:"].includes(url.protocol)) {
            return null;
        }

        if (!obterOrigensAtendimentoPermitidas().has(url.origin)) {
            return null;
        }

        return url.toString();
    } catch {
        return null;
    }
};

const normalizarStateSso = (state) => {
    if (typeof state !== "string") {
        return null;
    }

    const normalizado = state.trim();

    return /^[a-zA-Z0-9._~-]{16,256}$/.test(normalizado) ? normalizado : null;
};

const buscarUsuarioSsoAtendimento = async (usuarioId) => {
    const [rows] = await db.query(`
        SELECT
            u.id,
            u.nome,
            u.email,
            u.avatar,
            u.status,
            u.ultimo_acesso,
            u.perfil,
            u.empresa_id,
            s.nome AS setor_nome
        FROM usuarios u
        LEFT JOIN setores s ON u.setor_id = s.id
        WHERE u.id = ? AND u.deletado_em IS NULL
        LIMIT 1
    `, [usuarioId]);

    return rows[0] || null;
};

const MAX_UPLOAD_SIZE_MB = 500;
const MAX_UPLOAD_SIZE_BYTES = MAX_UPLOAD_SIZE_MB * 1024 * 1024;
const MAX_UPLOAD_DATA_URL_LENGTH = Math.ceil(MAX_UPLOAD_SIZE_MB * 1024 * 1024 * 4 / 3) + 2048;
const MAX_IMAGE_DATA_URL_LENGTH = MAX_UPLOAD_DATA_URL_LENGTH;
const IMAGE_DATA_URL_REGEX = /^data:image\/[a-z0-9.+-]+(?:;[^;,=]+=[^;,]+)*;base64,/i;
const MAX_AUDIO_DATA_URL_LENGTH = MAX_UPLOAD_DATA_URL_LENGTH;
const AUDIO_DATA_URL_REGEX = /^data:audio\/[a-z0-9.+-]+(?:;[^;,=]+=[^;,]+)*;base64,/i;
const MAX_FILE_DATA_URL_LENGTH = MAX_UPLOAD_DATA_URL_LENGTH;
const FILE_DATA_URL_REGEX = /^data:[^,]*;base64,/i;
const CHAT_UPLOAD_URL_REGEX = /^\/uploads\/chat\/[^\s?#]+$/i;
const STICKER_UPLOAD_URL_REGEX = /^\/uploads\/stickers\/[^\s?#]+\.webp$/i;
const DEFAULT_FILE_MIME = "application/octet-stream";
const CHAT_FILE_MIME_BY_EXTENSION = {
    ".zip": "application/zip",
};
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CHAT_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/chat");
const STICKER_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/stickers");
const WIKI_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/wiki");
const INTERNAL_REQUEST_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/solicitacoes");
const SALES_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/vendas");
const CCNA_COMPETITION_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/ccna-competition");
const BANNER_HOME_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/banner-home");
const AVISO_GERAL_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/avisos");
const IMAGENS_GALERIA_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/imagens");
const WALLPAPER_UPLOAD_ROOT = path.resolve(__dirname, "../../../uploads/wallpapers");
const WALLPAPER_UPLOAD_URL_REGEX = /^\/uploads\/wallpapers\/[^\s?#]+\.webp$/i;
const WALLPAPER_MAX_UPLOAD_SIZE_MB = 5;
const WALLPAPER_MAX_UPLOAD_SIZE_BYTES = WALLPAPER_MAX_UPLOAD_SIZE_MB * 1024 * 1024;
const WALLPAPER_ALLOWED_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"];
const WALLPAPER_MAX_DIMENSION = 2048;
const execFileAsync = promisify(execFile);
let indicesChatPerformanceGarantidos = false;
let salesMaterialsTabelaGarantida = false;

const normalizarSegmentoUpload = (valor = "geral") => (
    String(valor || "geral")
        .replace(/[^a-zA-Z0-9_-]/g, "_")
        .slice(0, 80)
        || "geral"
);

const normalizarNomeArquivoUpload = (nome = "arquivo") => {
    const nomeBase = path.basename(String(nome || "arquivo"));
    const extensao = path.extname(nomeBase).replace(/[^a-zA-Z0-9.]/g, "").slice(0, 24);
    const base = path.basename(nomeBase, path.extname(nomeBase))
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .replace(/[^a-zA-Z0-9_-]/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "")
        .slice(0, 90)
        || "arquivo";

    return `${base}${extensao}`;
};

const AVISO_GERAL_IMAGE_MAX_SIZE_MB = 3;
const AVISO_GERAL_IMAGE_MAX_SIZE_BYTES = AVISO_GERAL_IMAGE_MAX_SIZE_MB * 1024 * 1024;
const AVISO_GERAL_IMAGE_EXTENSIONS = [".jpg", ".jpeg", ".png", ".webp"];

const avisoGeralImageUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.admin?.empresa_id || req.user?.empresa_id);
        const destino = path.join(AVISO_GERAL_UPLOAD_ROOT, empresaDiretorio);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname || "aviso.png");
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const detectarExtensaoRealImagemAviso = (filePath) => {
    let fd = null;

    try {
        fd = fs.openSync(filePath, "r");
        const buffer = Buffer.alloc(12);
        const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);

        if (
            bytesRead >= 8
            && buffer[0] === 0x89
            && buffer[1] === 0x50
            && buffer[2] === 0x4e
            && buffer[3] === 0x47
            && buffer[4] === 0x0d
            && buffer[5] === 0x0a
            && buffer[6] === 0x1a
            && buffer[7] === 0x0a
        ) {
            return ".png";
        }

        if (bytesRead >= 3 && buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
            return ".jpg";
        }

        if (
            bytesRead >= 12
            && buffer.toString("ascii", 0, 4) === "RIFF"
            && buffer.toString("ascii", 8, 12) === "WEBP"
        ) {
            return ".webp";
        }
    } catch (err) {
        console.error("Erro ao validar assinatura da imagem do aviso:", err);
    } finally {
        if (fd !== null) {
            fs.closeSync(fd);
        }
    }

    return "";
};

const validarArquivoImagemAvisoGeral = (file) => {
    if (!file?.path) return false;

    const extensaoOriginal = path.extname(file.originalname || file.filename || "").toLowerCase();
    const extensaoReal = detectarExtensaoRealImagemAviso(file.path);

    if (!AVISO_GERAL_IMAGE_EXTENSIONS.includes(extensaoOriginal) || !extensaoReal) {
        return false;
    }

    if (extensaoReal === ".jpg") {
        return extensaoOriginal === ".jpg" || extensaoOriginal === ".jpeg";
    }

    return extensaoOriginal === extensaoReal;
};

const avisoGeralImageUpload = multer({
    storage: avisoGeralImageUploadStorage,
    limits: {
        fileSize: AVISO_GERAL_IMAGE_MAX_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = path.extname(file.originalname || "").toLowerCase();

        if (/^image\/(png|jpe?g|webp)$/i.test(file.mimetype || "") && AVISO_GERAL_IMAGE_EXTENSIONS.includes(extensao)) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie uma imagem JPG, PNG ou WEBP."));
    },
});

const uploadAvisoGeralImagemMiddleware = (req, res, next) => {
    avisoGeralImageUpload.single("imagem")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Imagem muito grande. Envie arquivos de até ${AVISO_GERAL_IMAGE_MAX_SIZE_MB} MB.`,
            });
        }

        if (err) {
            console.error("Erro ao processar imagem do aviso:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar a imagem do aviso.",
            });
        }

        if (req.file && !validarArquivoImagemAvisoGeral(req.file)) {
            fs.rmSync(req.file.path, { force: true });
            return res.status(400).json({
                error: "Arquivo inválido. Envie uma imagem JPG, PNG ou WEBP.",
            });
        }

        return next();
    });
};

const removerUploadTemporarioAvisoGeral = (req) => {
    if (req.file?.path) {
        fs.rmSync(req.file.path, { force: true });
    }
};

const ccnaProofUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.user?.empresa_id);
        const usuarioDiretorio = normalizarSegmentoUpload(req.user?.id);
        const destino = path.join(CCNA_COMPETITION_UPLOAD_ROOT, empresaDiretorio, usuarioDiretorio);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (req, file, callback) => {
        const moduleId = normalizarSegmentoUpload(req.params?.moduleId || "modulo");
        const nome = normalizarNomeArquivoUpload(file.originalname || "comprovacao.png");
        callback(null, `${Date.now()}-${moduleId}-${nome}`);
    },
});

const ccnaProofUpload = multer({
    storage: ccnaProofUploadStorage,
    limits: { fileSize: 20 * 1024 * 1024 },
    fileFilter: (_req, file, callback) => {
        if (/^image\/(png|jpe?g|webp|gif)$/i.test(file.mimetype || "")) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie uma imagem PNG, JPG, WEBP ou GIF."));
    },
});

const ccnaProofUploadMiddleware = (req, res, next) => {
    ccnaProofUpload.single("proof_image")(req, res, (err) => {
        if (!err) {
            next();
            return;
        }

        const mensagem = err.code === "LIMIT_FILE_SIZE"
            ? "A imagem deve ter no máximo 20MB."
            : err.message || "Não foi possível enviar a imagem.";

        res.status(400).json({ error: mensagem });
    });
};

const BANNER_HOME_IMAGE_MAX_SIZE_MB = 20;
const BANNER_HOME_IMAGE_MAX_SIZE_BYTES = BANNER_HOME_IMAGE_MAX_SIZE_MB * 1024 * 1024;
const BANNER_HOME_IMAGE_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp", ".gif"];

const bannerHomeUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.admin?.empresa_id || req.user?.empresa_id);
        const destino = path.join(BANNER_HOME_UPLOAD_ROOT, empresaDiretorio);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname || "banner-home.png");
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const bannerHomeUpload = multer({
    storage: bannerHomeUploadStorage,
    limits: {
        fileSize: BANNER_HOME_IMAGE_MAX_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = path.extname(file.originalname || "").toLowerCase();

        if (/^image\//i.test(file.mimetype || "") && BANNER_HOME_IMAGE_EXTENSIONS.includes(extensao)) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie uma imagem PNG, JPG, WEBP ou GIF."));
    },
});

const uploadBannerHomeMiddleware = (req, res, next) => {
    bannerHomeUpload.single("imagem")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Imagem muito grande. Envie arquivos de até ${BANNER_HOME_IMAGE_MAX_SIZE_MB} MB.`,
            });
        }

        if (err) {
            console.error("Erro ao processar imagem do banner da home:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar a imagem do banner.",
            });
        }

        return next();
    });
};

const IMAGENS_GALERIA_MAX_SIZE_MB = 20;
const IMAGENS_GALERIA_MAX_SIZE_BYTES = IMAGENS_GALERIA_MAX_SIZE_MB * 1024 * 1024;
const IMAGENS_GALERIA_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp", ".gif"];
const IMAGENS_GALERIA_URL_REGEX = /^\/uploads\/imagens\/[^\s?#]+$/i;

const imagensGaleriaUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.admin?.empresa_id || req.user?.empresa_id);
        const destino = path.join(IMAGENS_GALERIA_UPLOAD_ROOT, empresaDiretorio);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname || "imagem.png");
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const imagensGaleriaUpload = multer({
    storage: imagensGaleriaUploadStorage,
    limits: {
        fileSize: IMAGENS_GALERIA_MAX_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = path.extname(file.originalname || "").toLowerCase();

        if (/^image\//i.test(file.mimetype || "") && IMAGENS_GALERIA_EXTENSIONS.includes(extensao)) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie uma imagem PNG, JPG, WEBP ou GIF."));
    },
});

const uploadImagemGaleriaMiddleware = (req, res, next) => {
    imagensGaleriaUpload.single("imagem")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Imagem muito grande. Envie arquivos de até ${IMAGENS_GALERIA_MAX_SIZE_MB} MB.`,
            });
        }

        if (err) {
            console.error("Erro ao processar imagem da galeria:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar a imagem.",
            });
        }

        return next();
    });
};

const obterMimeArquivoChat = (file = {}) => {
    const mime = String(file.mimetype || "").trim();
    const extensao = path.extname(file.originalname || "").toLowerCase();
    const mimePorExtensao = CHAT_FILE_MIME_BY_EXTENSION[extensao];

    if ((!mime || mime === DEFAULT_FILE_MIME) && mimePorExtensao) {
        return mimePorExtensao;
    }

    return mime || DEFAULT_FILE_MIME;
};

const chatUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.user?.empresa_id);
        const destino = path.join(CHAT_UPLOAD_ROOT, empresaDiretorio);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname);
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const CHAT_UPLOAD_EXTENSOES_PERMITIDAS = lerExtensoesPermitidas();

const chatUpload = multer({
    storage: chatUploadStorage,
    limits: {
        fileSize: MAX_UPLOAD_SIZE_BYTES,
        files: 1,
    },
    // Allowlist de extensão + bloqueio de MIME ativo (html/svg/js). Ver src/security/uploadSecurity.js.
    fileFilter: (_req, file, callback) => {
        const motivo = validarArquivoChat(file, CHAT_UPLOAD_EXTENSOES_PERMITIDAS);
        if (motivo) {
            callback(Object.assign(new Error(motivo), { codigoUpload: "TIPO_NAO_PERMITIDO" }));
            return;
        }
        callback(null, true);
    },
});

const uploadChatMiddleware = (req, res, next) => {
    chatUpload.single("arquivo")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Arquivo muito grande. Envie arquivos de até ${MAX_UPLOAD_SIZE_MB} MB`,
            });
        }

        if (err?.codigoUpload === "TIPO_NAO_PERMITIDO") {
            return res.status(415).json({ error: err.message });
        }

        if (err) {
            console.error("Erro ao processar upload do chat:", err);
            return res.status(400).json({ error: "Não foi possível anexar o arquivo." });
        }

        return next();
    });
};

const soundEffectUploadStorage = multer.diskStorage({
    destination: (_req, _file, callback) => {
        fs.mkdirSync(CUSTOM_SOUNDS_ROOT, { recursive: true });
        callback(null, CUSTOM_SOUNDS_ROOT);
    },
    filename: (_req, file, callback) => {
        callback(null, createSoundUploadFilename(file.originalname || "audio.wav"));
    },
});

const soundEffectUpload = multer({
    storage: soundEffectUploadStorage,
    limits: {
        fileSize: SOUND_EFFECT_UPLOAD_MAX_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = normalizeSoundUploadExtension(file.originalname || "");

        if (extensao && isAllowedSoundUploadMime(file.mimetype)) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie um áudio MP3, WAV, OGG, OPUS, WEBM, M4A/AAC ou FLAC."));
    },
});

const uploadSoundEffectMiddleware = (req, res, next) => {
    soundEffectUpload.single("audio")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: "Áudio muito grande. Envie arquivos de até 8 MB.",
            });
        }

        if (err) {
            console.error("Erro ao processar upload de efeito sonoro:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar o áudio.",
            });
        }

        return next();
    });
};

const CHAT_STICKER_MAX_UPLOAD_SIZE_MB = Number(process.env.CHAT_STICKER_MAX_UPLOAD_SIZE_MB || 8);
const CHAT_STICKER_MAX_UPLOAD_SIZE_BYTES = CHAT_STICKER_MAX_UPLOAD_SIZE_MB * 1024 * 1024;
const CHAT_STICKER_SIZE = 512;
const CHAT_STICKER_MAX_PER_USER = Number(process.env.CHAT_STICKER_MAX_PER_USER || 500);
const CHAT_STICKER_RECENTS_LIMIT = Number(process.env.CHAT_STICKER_RECENTS_LIMIT || 30);
const CHAT_STICKER_MAX_FRAMES = Number(process.env.CHAT_STICKER_MAX_FRAMES || 120);
const CHAT_STICKER_ALLOWED_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp", ".gif"];

const detectarTipoImagemSticker = (buffer) => {
    if (!Buffer.isBuffer(buffer) || buffer.length < 12) return null;

    if (
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47 &&
        buffer[4] === 0x0d &&
        buffer[5] === 0x0a &&
        buffer[6] === 0x1a &&
        buffer[7] === 0x0a
    ) {
        return "image/png";
    }

    if (buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff) {
        return "image/jpeg";
    }

    if (buffer.toString("ascii", 0, 6) === "GIF87a" || buffer.toString("ascii", 0, 6) === "GIF89a") {
        return "image/gif";
    }

    if (
        buffer.toString("ascii", 0, 4) === "RIFF" &&
        buffer.toString("ascii", 8, 12) === "WEBP"
    ) {
        return "image/webp";
    }

    return null;
};

const stickerUpload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: CHAT_STICKER_MAX_UPLOAD_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = path.extname(file.originalname || "").toLowerCase();
        const mime = String(file.mimetype || "").toLowerCase();

        if (
            /^image\/(png|jpe?g|webp|gif)$/i.test(mime) &&
            CHAT_STICKER_ALLOWED_EXTENSIONS.includes(extensao)
        ) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie uma imagem PNG, JPG, JPEG, WEBP ou GIF."));
    },
});

const uploadStickerMiddleware = (req, res, next) => {
    stickerUpload.single("sticker")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Imagem muito grande. Envie figurinhas de até ${CHAT_STICKER_MAX_UPLOAD_SIZE_MB} MB.`,
            });
        }

        if (err) {
            console.error("Erro ao processar figurinha:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar a figurinha.",
            });
        }

        return next();
    });
};

const wallpaperUpload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: WALLPAPER_MAX_UPLOAD_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = path.extname(file.originalname || "").toLowerCase();
        const mime = String(file.mimetype || "").toLowerCase();

        if (
            /^image\/(png|jpe?g|webp)$/i.test(mime) &&
            WALLPAPER_ALLOWED_EXTENSIONS.includes(extensao)
        ) {
            callback(null, true);
            return;
        }

        callback(new Error("Envie uma imagem PNG, JPG, JPEG ou WEBP."));
    },
});

const uploadWallpaperMiddleware = (req, res, next) => {
    wallpaperUpload.single("wallpaper")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Imagem muito grande. Envie papéis de parede de até ${WALLPAPER_MAX_UPLOAD_SIZE_MB} MB.`,
            });
        }

        if (err) {
            console.error("Erro ao processar wallpaper:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar o papel de parede.",
            });
        }

        return next();
    });
};

const criarWallpaperAPartirDeUpload = async ({ file, usuario }) => {
    if (!file?.buffer?.length) {
        const erro = new Error("Envie uma imagem para o papel de parede.");
        erro.status = 400;
        throw erro;
    }

    const empresaDiretorio = normalizarSegmentoUpload(usuario.empresa_id);
    const usuarioDiretorio = normalizarSegmentoUpload(usuario.id);
    const destinoDiretorio = path.join(WALLPAPER_UPLOAD_ROOT, empresaDiretorio, usuarioDiretorio);
    const filename = `${crypto.randomUUID()}.webp`;
    const storagePath = path.join(destinoDiretorio, filename);
    const fileUrl = `/uploads/wallpapers/${empresaDiretorio}/${usuarioDiretorio}/${filename}`;

    fs.mkdirSync(destinoDiretorio, { recursive: true });

    let processed;

    try {
        processed = await sharp(file.buffer, {
            failOn: "warning",
            limitInputPixels: 32_000_000,
        })
            .rotate()
            .resize({
                width: WALLPAPER_MAX_DIMENSION,
                height: WALLPAPER_MAX_DIMENSION,
                fit: "inside",
                withoutEnlargement: true,
            })
            .webp({ quality: 82 })
            .toBuffer();
    } catch (err) {
        const erro = new Error("Arquivo inválido. Envie uma imagem PNG, JPG, JPEG ou WEBP.");
        erro.status = 400;
        throw erro;
    }

    await fs.promises.writeFile(storagePath, processed);

    return { url: fileUrl };
};

const INTERNAL_REQUEST_UPLOAD_MAX_SIZE_MB = 50;
const INTERNAL_REQUEST_UPLOAD_MAX_SIZE_BYTES = INTERNAL_REQUEST_UPLOAD_MAX_SIZE_MB * 1024 * 1024;

const internalRequestUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.user?.empresa_id);
        const destino = path.join(INTERNAL_REQUEST_UPLOAD_ROOT, empresaDiretorio);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname);
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const internalRequestUpload = multer({
    storage: internalRequestUploadStorage,
    limits: {
        fileSize: INTERNAL_REQUEST_UPLOAD_MAX_SIZE_BYTES,
        files: 1,
    },
});

const uploadInternalRequestMiddleware = (req, res, next) => {
    internalRequestUpload.single("anexo")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Arquivo muito grande. Envie anexos de até ${INTERNAL_REQUEST_UPLOAD_MAX_SIZE_MB} MB`,
            });
        }

        if (err) {
            console.error("Erro ao processar anexo da solicitação:", err);
            return res.status(400).json({ error: "Não foi possível anexar o arquivo." });
        }

        return next();
    });
};

const WIKI_MEDIA_MAX_SIZE_MB = 500;
const WIKI_MEDIA_MAX_SIZE_BYTES = WIKI_MEDIA_MAX_SIZE_MB * 1024 * 1024;
const WIKI_DOCUMENT_TYPES = {
    ".pdf": "pdf",
    ".ppt": "powerpoint",
    ".pptx": "powerpoint",
    ".xls": "excel",
    ".xlsx": "excel",
};

const obterTipoArquivoWiki = (file = {}) => {
    const mime = String(file.mimetype || "").toLowerCase();
    const extension = path.extname(file.originalname || "").toLowerCase();

    if (mime.startsWith("image/")) return "image";
    if (mime.startsWith("video/")) return "video";

    return WIKI_DOCUMENT_TYPES[extension] || null;
};

const wikiMediaUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const empresaDiretorio = normalizarSegmentoUpload(req.admin?.empresa_id);
        const cursoDiretorio = normalizarSegmentoUpload(req.params?.cursoId);
        const aulaDiretorio = normalizarSegmentoUpload(req.params?.contentKey);
        const destino = path.join(
            WIKI_UPLOAD_ROOT,
            empresaDiretorio,
            cursoDiretorio,
            aulaDiretorio
        );

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname);
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const wikiMediaUpload = multer({
    storage: wikiMediaUploadStorage,
    limits: {
        fileSize: WIKI_MEDIA_MAX_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        if (obterTipoArquivoWiki(file)) {
            callback(null, true);
            return;
        }

        callback(new Error(
            "Envie imagens, vídeos, PDF, PowerPoint (.ppt/.pptx) ou Excel (.xls/.xlsx)."
        ));
    },
});

const uploadWikiMediaMiddleware = (req, res, next) => {
    wikiMediaUpload.single("arquivo")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Arquivo muito grande. Envie arquivos de até ${WIKI_MEDIA_MAX_SIZE_MB} MB`,
            });
        }

        if (err) {
            console.error("Erro ao processar mídia da aula:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar a mídia.",
            });
        }

        return next();
    });
};

const SALES_MATERIALS_MAX_SIZE_MB = 200;
const SALES_MATERIALS_MAX_SIZE_BYTES = SALES_MATERIALS_MAX_SIZE_MB * 1024 * 1024;
const SALES_MATERIAL_FILE_TYPES = {
    ".png": { type: "image", label: "Imagem PNG", mime: "image/png" },
    ".jpg": { type: "image", label: "Imagem JPG", mime: "image/jpeg" },
    ".jpeg": { type: "image", label: "Imagem JPEG", mime: "image/jpeg" },
    ".pdf": { type: "pdf", label: "PDF", mime: "application/pdf" },
    ".pptx": { type: "presentation", label: "PowerPoint", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
    ".docx": { type: "document", label: "Word", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
};
const SALES_MATERIAL_ALLOWED_EXTENSIONS = Object.keys(SALES_MATERIAL_FILE_TYPES);
const SALES_MATERIAL_SECTIONS = [
    {
        id: "tutoriais-vendas",
        title: "Tutoriais de Vendas",
        description: "Prints e materiais explicativos para preencher dados, consultar planos, abrir atendimento e finalizar venda.",
        action_label: "Abrir imagem",
        accepted_extensions: [".png", ".jpg", ".jpeg", ".pdf"],
    },
    {
        id: "ficha-instalacao",
        title: "Ficha de Instalação",
        description: "Use quando a venda precisar seguir para instalação com os dados conferidos e prontos para repasse.",
        action_label: "Visualizar",
        accepted_extensions: [".png", ".jpg", ".jpeg", ".pdf", ".docx"],
    },
    {
        id: "assinatura-meu-provedor",
        title: "Passo a Passo - Assinatura Meu Provedor",
        description: "Etapas para enviar contrato, acompanhar a assinatura e finalizar o atendimento.",
        action_label: "Visualizar",
        accepted_extensions: [".png", ".jpg", ".jpeg", ".pdf", ".docx"],
        steps: [
            { id: "acessar-sistema", number: 1, title: "Acessar o sistema" },
            { id: "localizar-cliente", number: 2, title: "Localizar cliente" },
            { id: "enviar-contrato-assinatura", number: 3, title: "Enviar contrato/assinatura" },
            { id: "confirmar-assinatura", number: 4, title: "Confirmar assinatura" },
            { id: "finalizar-atendimento", number: 5, title: "Finalizar atendimento" },
        ],
    },
    {
        id: "processos-vendas",
        title: "Apresentação de Processos de Vendas",
        description: "Apresentação com processos, regras, fluxo de atendimento e orientações comerciais.",
        action_label: "Baixar",
        accepted_extensions: [".pptx"],
    },
    {
        id: "script-pos-vendas",
        title: "Script de Pós-Vendas",
        description: "Textos prontos para contato com cliente após a venda.",
        action_label: "Visualizar",
        accepted_extensions: [".docx", ".pdf"],
    },
    {
        id: "materiais-apoio",
        title: "Materiais de Apoio",
        description: "Argumentos de venda, respostas para objeções, explicação dos planos, benefícios e regras comerciais.",
        action_label: "Visualizar",
        accepted_extensions: SALES_MATERIAL_ALLOWED_EXTENSIONS,
    },
];

const limitarTextoMaterialVendas = (valor = "", limite = 255) => (
    String(valor || "").trim().slice(0, limite)
);

const obterTipoMaterialVendas = (file = {}) => {
    const extensao = path.extname(file.originalname || "").toLowerCase();
    return SALES_MATERIAL_FILE_TYPES[extensao] || null;
};

const obterDiretorioVendasEmpresa = (empresaId) => {
    const empresaDiretorio = normalizarSegmentoUpload(empresaId);
    return path.join(SALES_UPLOAD_ROOT, empresaDiretorio);
};

const obterCaminhoConteudoVendas = (empresaId) => (
    path.join(obterDiretorioVendasEmpresa(empresaId), "conteudo.json")
);

const salesMaterialUploadStorage = multer.diskStorage({
    destination: (req, _file, callback) => {
        const destino = obterDiretorioVendasEmpresa(req.user?.empresa_id);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname);
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const salesMaterialUpload = multer({
    storage: salesMaterialUploadStorage,
    limits: {
        fileSize: SALES_MATERIALS_MAX_SIZE_BYTES,
        files: 1,
    },
    fileFilter: (_req, file, callback) => {
        if (obterTipoMaterialVendas(file)) {
            callback(null, true);
            return;
        }

        callback(new Error(
            "Envie arquivos .png, .jpg, .jpeg, .pdf, .pptx ou .docx."
        ));
    },
});

const uploadSalesMaterialMiddleware = (req, res, next) => {
    salesMaterialUpload.single("arquivo")(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Arquivo muito grande. Envie materiais de até ${SALES_MATERIALS_MAX_SIZE_MB} MB`,
            });
        }

        if (err) {
            console.error("Erro ao processar material de vendas:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar o material.",
            });
        }

        return next();
    });
};

const usuarioPodeGerenciarMateriaisVendas = (usuario = {}) => (
    [PERFIL_ADMIN, PERFIL_ADMIN_COMERCIAL].includes(usuario?.perfil)
);

const requireSalesMaterialsManager = (req, res, next) => {
    if (!usuarioPodeGerenciarMateriaisVendas(req.user)) {
        return res.status(403).json({ error: "Acesso restrito aos administradores comerciais." });
    }

    return next();
};

const SALES_COVER_ALLOWED_EXTENSIONS = [".png", ".jpg", ".jpeg", ".webp"];
const SALES_FILE_ALLOWED_EXTENSIONS = [
    ".pdf",
    ".doc",
    ".docx",
    ".ppt",
    ".pptx",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
];
const SALES_MATERIAL_TYPES = ["imagem", "pdf", "docx", "pptx", "link", "outro"];
const SALES_MATERIALS_PADRAO = [
    {
        title: "Passo a passo da venda",
        description: "Tutorial visual com todas as etapas do processo comercial.",
        category: "Tutorial",
        material_type: "imagem",
        display_order: 10,
    },
    {
        title: "Ficha de instalação",
        description: "Modelo para registrar dados do cliente, instalação e informações técnicas.",
        category: "Documento",
        material_type: "docx",
        display_order: 20,
    },
    {
        title: "Assinatura Meu Provedor",
        description: "Guia rápido com telas e instruções para realizar a assinatura do serviço.",
        category: "Guia rápido",
        material_type: "pdf",
        display_order: 30,
    },
    {
        title: "Apresentação de processos de vendas",
        description: "Apresentação para alinhamento, treinamento e padronização da equipe.",
        category: "PPTX",
        material_type: "pptx",
        display_order: 40,
    },
    {
        title: "Script de pós-venda",
        description: "Texto pronto para follow-up, relacionamento e confirmação de satisfação.",
        category: "Script",
        material_type: "docx",
        display_order: 50,
    },
    {
        title: "Imagens para mandar para cliente",
        description: "Artes prontas para envio no WhatsApp e outros canais de atendimento.",
        category: "Imagens prontas",
        material_type: "imagem",
        display_order: 60,
    },
    {
        title: "Planos e ofertas",
        description: "Tabela visual com planos, benefícios e condições comerciais atualizadas.",
        category: "Comercial",
        material_type: "imagem",
        display_order: 70,
    },
    {
        title: "Perguntas frequentes",
        description: "Respostas para as principais dúvidas que aparecem durante o atendimento.",
        category: "FAQ",
        material_type: "pdf",
        display_order: 80,
    },
];

const obterTipoMaterialPelaExtensao = (nome = "") => {
    const extensao = path.extname(nome || "").toLowerCase();

    if ([".png", ".jpg", ".jpeg", ".webp"].includes(extensao)) return "imagem";
    if (extensao === ".pdf") return "pdf";
    if ([".doc", ".docx"].includes(extensao)) return "docx";
    if ([".ppt", ".pptx"].includes(extensao)) return "pptx";

    return "outro";
};

const normalizarTipoMaterialCadastro = (valor = "", nomeArquivo = "") => {
    const tipo = String(valor || "").trim().toLowerCase();
    if (SALES_MATERIAL_TYPES.includes(tipo)) return tipo;

    return obterTipoMaterialPelaExtensao(nomeArquivo);
};

const obterPastaUploadVendas = (fieldname, empresaId) => {
    const empresaDiretorio = normalizarSegmentoUpload(empresaId);
    const subpasta = fieldname === "cover_image" ? "capas" : "arquivos";

    return path.join(SALES_UPLOAD_ROOT, subpasta, empresaDiretorio);
};

const obterUrlUploadVendas = (fieldname, empresaId, filename) => {
    const empresaDiretorio = normalizarSegmentoUpload(empresaId);
    const subpasta = fieldname === "cover_image" ? "capas" : "arquivos";

    return `/uploads/vendas/${subpasta}/${empresaDiretorio}/${filename}`;
};

const salesMaterialManagerUploadStorage = multer.diskStorage({
    destination: (req, file, callback) => {
        const destino = obterPastaUploadVendas(file.fieldname, req.user?.empresa_id);

        fs.mkdirSync(destino, { recursive: true });
        callback(null, destino);
    },
    filename: (_req, file, callback) => {
        const nomeSeguro = normalizarNomeArquivoUpload(file.originalname);
        callback(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}-${nomeSeguro}`);
    },
});

const salesMaterialManagerUpload = multer({
    storage: salesMaterialManagerUploadStorage,
    limits: {
        fileSize: SALES_MATERIALS_MAX_SIZE_BYTES,
        files: 2,
    },
    fileFilter: (_req, file, callback) => {
        const extensao = path.extname(file.originalname || "").toLowerCase();

        if (file.fieldname === "cover_image") {
            if (SALES_COVER_ALLOWED_EXTENSIONS.includes(extensao)) {
                callback(null, true);
                return;
            }

            callback(new Error("Envie uma capa em .png, .jpg, .jpeg ou .webp."));
            return;
        }

        if (file.fieldname === "material_file") {
            if (SALES_FILE_ALLOWED_EXTENSIONS.includes(extensao)) {
                callback(null, true);
                return;
            }

            callback(new Error("Envie materiais .pdf, .doc, .docx, .ppt, .pptx, .png, .jpg, .jpeg ou .webp."));
            return;
        }

        callback(new Error("Campo de upload inválido."));
    },
});

const uploadSalesMaterialManagerMiddleware = (req, res, next) => {
    salesMaterialManagerUpload.fields([
        { name: "cover_image", maxCount: 1 },
        { name: "material_file", maxCount: 1 },
    ])(req, res, (err) => {
        if (err instanceof multer.MulterError && err.code === "LIMIT_FILE_SIZE") {
            return res.status(413).json({
                error: `Arquivo muito grande. Envie arquivos de até ${SALES_MATERIALS_MAX_SIZE_MB} MB`,
            });
        }

        if (err) {
            console.error("Erro ao processar material de vendas:", err);
            return res.status(400).json({
                error: err.message || "Não foi possível enviar o material.",
            });
        }

        return next();
    });
};

const removerUploadsTemporariosVendas = (files = {}) => {
    Object.values(files || {})
        .flat()
        .filter(Boolean)
        .forEach((file) => {
            fs.rmSync(file.path, { force: true });
        });
};

const obterArquivoUploadVendas = (req, fieldname) => (
    Array.isArray(req.files?.[fieldname]) ? req.files[fieldname][0] : null
);

const criarConteudoVendasPadrao = () => ({
    atualizado_em: null,
    sections: SALES_MATERIAL_SECTIONS.map((section) => ({
        ...section,
        items: [],
    })),
});

const normalizarItemMaterialVendas = (item = {}) => {
    const url = limitarTextoMaterialVendas(item.url, 600);
    if (!url) return null;

    const extensao = path.extname(item.name || item.url || "").toLowerCase();
    const tipoExtensao = SALES_MATERIAL_FILE_TYPES[extensao];

    return {
        id: limitarTextoMaterialVendas(item.id, 80) || `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
        section_id: limitarTextoMaterialVendas(item.section_id, 80),
        step_id: limitarTextoMaterialVendas(item.step_id, 80),
        title: limitarTextoMaterialVendas(item.title, 180) || limitarTextoMaterialVendas(item.name, 180) || "Material de vendas",
        description: limitarTextoMaterialVendas(item.description, 500),
        file_type: item.file_type || tipoExtensao?.type || "file",
        file_label: item.file_label || tipoExtensao?.label || "Arquivo",
        url,
        name: limitarTextoMaterialVendas(item.name, 255) || "arquivo",
        mime: limitarTextoMaterialVendas(item.mime, 180) || tipoExtensao?.mime || DEFAULT_FILE_MIME,
        size: Number(item.size || 0),
        uploaded_at: item.uploaded_at || new Date().toISOString(),
        uploaded_by: limitarTextoMaterialVendas(item.uploaded_by, 160),
    };
};

const normalizarConteudoMateriaisVendas = (conteudo = {}) => {
    const secoesSalvas = Array.isArray(conteudo.sections) ? conteudo.sections : [];
    const itensPorSecao = new Map();

    secoesSalvas.forEach((section) => {
        const sectionId = limitarTextoMaterialVendas(section?.id, 80);
        const items = Array.isArray(section?.items) ? section.items : [];
        itensPorSecao.set(
            sectionId,
            items.map(normalizarItemMaterialVendas).filter(Boolean)
        );
    });

    return {
        atualizado_em: conteudo.atualizado_em || null,
        limite_mb: SALES_MATERIALS_MAX_SIZE_MB,
        allowed_extensions: SALES_MATERIAL_ALLOWED_EXTENSIONS,
        sections: SALES_MATERIAL_SECTIONS.map((section) => ({
            ...section,
            items: (itensPorSecao.get(section.id) || [])
                .filter((item) => item.section_id === section.id || !item.section_id)
                .map((item) => ({ ...item, section_id: section.id })),
        })),
    };
};

const lerConteudoMateriaisVendas = (empresaId) => {
    const caminho = obterCaminhoConteudoVendas(empresaId);

    try {
        if (!fs.existsSync(caminho)) {
            return normalizarConteudoMateriaisVendas(criarConteudoVendasPadrao());
        }

        const conteudo = JSON.parse(fs.readFileSync(caminho, "utf8"));
        return normalizarConteudoMateriaisVendas(conteudo);
    } catch (err) {
        console.error("Erro ao ler materiais de vendas:", err);
        return normalizarConteudoMateriaisVendas(criarConteudoVendasPadrao());
    }
};

const salvarConteudoMateriaisVendas = (empresaId, conteudo) => {
    const diretorio = obterDiretorioVendasEmpresa(empresaId);
    const caminho = obterCaminhoConteudoVendas(empresaId);
    const proximoConteudo = normalizarConteudoMateriaisVendas({
        ...conteudo,
        atualizado_em: new Date().toISOString(),
    });
    const temporario = `${caminho}.tmp`;

    fs.mkdirSync(diretorio, { recursive: true });
    fs.writeFileSync(temporario, JSON.stringify(proximoConteudo, null, 2));
    fs.renameSync(temporario, caminho);

    return proximoConteudo;
};

const buscarSecaoMaterialVendas = (sectionId) => (
    SALES_MATERIAL_SECTIONS.find((section) => section.id === sectionId)
);

const removerArquivoMaterialVendas = (empresaId, url = "") => {
    const diretorio = obterDiretorioVendasEmpresa(empresaId);
    const empresaDiretorio = normalizarSegmentoUpload(empresaId);
    const prefixo = `/uploads/vendas/${empresaDiretorio}/`;

    if (!String(url).startsWith(prefixo)) return;

    const relativo = String(url).slice(prefixo.length);
    const caminho = path.resolve(diretorio, relativo);
    const diretorioResolvido = path.resolve(diretorio);

    if (!caminho.startsWith(`${diretorioResolvido}${path.sep}`)) return;

    fs.rmSync(caminho, { force: true });
};

const converterDocumentoWikiParaPdf = async (file, tipo) => {
    if (tipo === "pdf") {
        return file.filename;
    }

    const destino = path.dirname(file.path);
    const nomeBase = path.parse(file.filename).name;
    const pdfGerado = path.join(destino, `${nomeBase}.pdf`);
    const nomePreview = `${nomeBase}-preview.pdf`;
    const caminhoPreview = path.join(destino, nomePreview);
    const profileDir = path.join(
        destino,
        `.libreoffice-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    );

    try {
        await execFileAsync(
            "/usr/bin/libreoffice",
            [
                "--headless",
                `-env:UserInstallation=file://${profileDir}`,
                "--convert-to",
                "pdf",
                "--outdir",
                destino,
                file.path,
            ],
            {
                timeout: 180000,
                maxBuffer: 10 * 1024 * 1024,
            }
        );

        if (!fs.existsSync(pdfGerado)) {
            throw new Error("O LibreOffice não gerou a prévia do documento.");
        }

        fs.renameSync(pdfGerado, caminhoPreview);
        return nomePreview;
    } finally {
        fs.rmSync(profileDir, { recursive: true, force: true });
    }
};

const isUploadChatUrl = (valor = "") => CHAT_UPLOAD_URL_REGEX.test(String(valor || ""));
const isUploadStickerUrl = (valor = "") => STICKER_UPLOAD_URL_REGEX.test(String(valor || ""));
const isAnexoDataUrlOuUpload = (valor = "", dataUrlRegex) => {
    const texto = String(valor || "");
    return dataUrlRegex.test(texto) || isUploadChatUrl(texto);
};
const CATEGORIAS_FIXAS_PADRAO = [
    "NOC",
    "Atendimento",
    "Suporte",
    "Comercial",
    "Financeiro",
    "RH",
    "TI",
];

let metadadosGruposGarantidos = false;
let tipoMensagemAudioGarantido = false;
let avisosInternosTabelaGarantida = false;
let feedbacksTabelaGarantida = false;
let leiturasMensagensTabelaGarantida = false;
let leiturasGruposTabelaGarantida = false;
let leiturasMensagensTabelaGarantidaPromise = null;
let leiturasGruposTabelaGarantidaPromise = null;
let avisoGeralTabelaGarantida = false;
let chatFavoritosTabelaGarantida = false;
let messageFavoritesTabelaGarantida = false;
let messageReactionsTabelaGarantida = false;
let pinnedMessagesTabelaGarantida = false;
let chatStickersTabelasGarantidas = false;
let acessosRapidosUsuarioTabelaGarantida = false;
let notasRapidasTabelaGarantida = false;
let solicitacoesInternasTabelaGarantida = false;
let textosAtendimentoTabelaGarantida = false;
let boasPraticasAtendimentoTabelaGarantida = false;
let changelogTabelaGarantida = false;
let plantaoDomingoTabelaGarantida = false;
let wikiInternaTabelaGarantida = false;
let wikiCursosConfigTabelaGarantida = false;
let wikiAulasConfigTabelaGarantida = false;
let wikiAulasProgressoTabelaGarantida = false;
let bannerHomeTabelaGarantida = false;
let competicaoCcnaTabelasGarantidas = false;
let connectivityTestTabelasGarantidas = false;
let connectivityPacketTargetsTabelaGarantida = false;

const MAX_AVISOS_HTML_LENGTH = 50000;
const FEEDBACK_TIPOS = ["bug", "sugestao", "pergunta"];
const FEEDBACK_PRIORIDADES = ["baixa", "media", "alta"];
const FEEDBACK_STATUS = ["aberto", "em_analise", "resolvido", "ignorado"];
const BOAS_PRATICAS_DUVIDAS_PAGINA = "/boas-praticas-duvidas";
const SOLICITACOES_INTERNAS_SETORES = [
    "Suporte interno",
    "Marketing/Design",
    "Cadastro",
    "Comercial",
    "Financeiro/Administração",
    "TI/Sistemas",
    "RH",
    "Outro",
];
const SOLICITACOES_INTERNAS_TIPOS = [
    "Suporte interno",
    "Pedido de marketing/design",
    "Ajuste em cadastro",
    "Solicitação comercial",
    "Problema em sistema",
    "Financeiro/Administração",
    "Outro",
];
const SOLICITACOES_INTERNAS_PRIORIDADES = ["baixa", "media", "alta", "urgente"];
const SOLICITACOES_INTERNAS_STATUS = [
    "aberto",
    "em_andamento",
    "aguardando_retorno",
    "resolvido",
    "cancelado",
];
const CONNECTIVITY_TEST_TIMEOUT_MS = 8000;
const CONNECTIVITY_TEST_CONCURRENCY = 5;
const CONNECTIVITY_TEST_STATUS_LABELS = {
    normal: "Normal",
    attention: "Atenção",
    slow: "Lento",
    very_slow: "Muito lento",
    offline: "Fora",
};
const CONNECTIVITY_TEST_DEFAULT_SITES = [
    { name: "Google", url: "https://www.google.com" },
    { name: "YouTube", url: "https://www.youtube.com" },
    { name: "WhatsApp Web", url: "https://web.whatsapp.com" },
    { name: "Instagram", url: "https://www.instagram.com" },
    { name: "Facebook", url: "https://www.facebook.com" },
    { name: "Cloudflare", url: "https://www.cloudflare.com" },
    { name: "Globo", url: "https://www.globo.com" },
    { name: "NIC.br Cursos", url: "https://cursoseventos.nic.br" },
    { name: "SGP Acessanet", url: "https://acessanet.sgp.net.br" },
];
const PACKET_LOSS_PING_COUNT = 10;
const PACKET_LOSS_PING_TIMEOUT_SECONDS = 2;
const PACKET_LOSS_COMMAND_TIMEOUT_MS = 26000;
const PACKET_LOSS_CONCURRENCY = 3;
const PACKET_LOSS_BLOCK_WARNING = "Este destino pode bloquear ping. Resultado pode não representar indisponibilidade real.";
const PACKET_LOSS_STATUS_LABELS = {
    normal: "Normal",
    attention: "Atenção",
    moderate_loss: "Perda moderada",
    high_loss: "Perda alta",
    no_response: "Sem resposta ou bloqueado",
};
const CONNECTIVITY_PACKET_DEFAULT_TARGETS = [
    { name: "Google DNS", host: "8.8.8.8" },
    { name: "Cloudflare DNS", host: "1.1.1.1" },
    { name: "Quad9 DNS", host: "9.9.9.9" },
    { name: "SGP Acessanet", host: "acessanet.sgp.net.br" },
    { name: "NIC.br", host: "cursoseventos.nic.br" },
];
const QUICK_ACCESS_ITEMS = [
    {
        id: "sgp",
        label: "SGP",
        icon: "◎",
        type: "external",
        target: "https://acessanet.sgp.net.br/admin/",
        sort_order: 10,
    },
    {
        id: "precadastro",
        label: "Pré-cadastro",
        subtitle: "Pessoa física ou pessoa jurídica, no SGP",
        icon: "PC",
        type: "menu",
        sort_order: 12,
        children: [
            {
                id: "precadastro-pf",
                label: "Pessoa física",
                icon: "F",
                type: "external",
                target: "https://acessanet.sgp.net.br/public/precadastro/F/",
            },
            {
                id: "precadastro-pj",
                label: "Pessoa jurídica",
                icon: "J",
                type: "external",
                target: "https://acessanet.sgp.net.br/public/precadastro/J/",
            },
        ],
    },
    {
        id: "olt-cloud",
        label: "OLT Cloud",
        icon: "☁",
        type: "external",
        target: "https://acessanet.oltcloud.co/",
        sort_order: 20,
    },
    {
        id: "dashboards",
        label: "Dashboards",
        icon: "▥",
        type: "external",
        target: "http://192.168.1.133/",
        sort_order: 30,
    },
    {
        id: "monitoramento-total",
        label: "Monitoramento Total",
        subtitle: "",
        icon: "MT",
        type: "internal",
        target: "/monitoramento-total",
        sort_order: 35,
    },
    {
        id: "teste-conectividade-sites",
        label: "Teste de Conectividade",
        icon: "🌐",
        type: "internal",
        target: "/teste-conectividade-sites",
        sort_order: 37,
    },
    {
        id: "diagnostico-conexao-cliente",
        label: "Diagnóstico de Conexão",
        subtitle: "Consulta conexão, consumo atual e histórico do cliente",
        icon: "DC",
        type: "internal",
        target: "/diagnostico-conexao-cliente",
        sort_order: 38,
        requires_network_diagnostic_permission: "network_diagnostics.view",
    },
    {
        id: "agenda",
        label: "Agenda",
        icon: "▣",
        type: "menu",
        sort_order: 40,
        children: [
            {
                id: "agenda-tecnicos",
                label: "Agenda técnicos",
                icon: "T",
                type: "external",
                target: "https://192.168.1.133:8500",
            },
            {
                id: "agenda-instalacao",
                label: "Agenda instalação",
                icon: "I",
                type: "external",
                target: "https://192.168.1.133:8501",
            },
        ],
    },
    {
        id: "busca-global",
        label: "Busca Global",
        icon: "⌕",
        type: "internal",
        target: "/busca-global",
        sort_order: 45,
    },
    {
        id: "controle-operacional",
        label: "Controle Operacional",
        subtitle: "Auditoria, eventos críticos e histórico da operação",
        icon: "CO",
        type: "internal",
        target: "/controle-operacional",
        sort_order: 47,
        perfis: [PERFIL_ADMIN],
        enabled: () => CONTROLE_OPERACIONAL_ENABLED,
    },
    {
        id: "solicitacoes-internas",
        label: "Chamados",
        icon: "CH",
        type: "internal",
        target: "/solicitacoes-internas",
        sort_order: 48,
    },
    {
        id: "vendas",
        label: "Vendas",
        icon: "V",
        type: "internal",
        target: "/acesso-rapido/vendas",
        sort_order: 50,
    },
    {
        id: "falhas-gerais",
        label: "Falhas Gerais",
        icon: "!",
        type: "internal",
        target: "/acesso-rapido/falhas-gerais",
        sort_order: 50,
    },
    {
        id: "imagens",
        label: "Imagens",
        subtitle: "Imagens compartilhadas pela administração",
        icon: "IM",
        type: "internal",
        target: "/imagens",
        sort_order: 50,
    },
    {
        id: "notas-rapidas",
        label: "Notas Rápidas",
        icon: "✎",
        type: "internal",
        target: "/notas-rapidas",
        sort_order: 50,
    },
    {
        id: "procedimentos-financeiro",
        label: "Procedimentos de financeiro",
        icon: "Tx",
        type: "internal",
        target: "/textos-atendimento",
        sort_order: 60,
    },
    {
        id: "boas-praticas-atendimento",
        label: "Boas Práticas de Atendimento",
        icon: "BP",
        type: "internal",
        target: "/boas-praticas-atendimento",
        sort_order: 65,
    },
    {
        id: "plantao-domingo",
        label: "Plantão domingo",
        icon: "D",
        type: "internal",
        target: "/plantao-domingo",
        sort_order: 70,
    },
    {
        id: "boas-praticas-duvidas",
        label: "Dúvidas Respondidas",
        icon: "?",
        type: "internal",
        target: "/boas-praticas-duvidas",
        sort_order: 80,
    },
    {
        id: "efeitos-sonoros",
        label: "Efeitos Sonoros",
        subtitle: "Disparo remoto de efeitos para usuários online",
        icon: "♪",
        type: "internal",
        target: "/acesso-rapido/efeitos-sonoros",
        sort_order: 82,
        requires_sound_effect_permission: true,
    },
    {
        id: "calculadoras-intranet",
        label: "Calculadoras",
        icon: "∑",
        type: "menu",
        sort_order: 88,
        children: [
            {
                id: "calculadora-internet-dedicada",
                label: "Calculadora Internet Dedicada",
                icon: "LD",
                type: "modal",
                target: "calculadora-link-dedicado",
            },
            {
                id: "calculadora-semi-dedicado",
                label: "Calculadora Semi Dedicado",
                icon: "SD",
                type: "modal",
                target: "calculadora-semi-dedicado",
            },
            {
                id: "calculadora-acordo",
                label: "Calculadora de Acordo",
                icon: "R$",
                type: "internal",
                target: "/acesso-rapido/calculadora-acordo",
            },
            {
                id: "calculadora-troca-plano",
                label: "Calculadora de Troca de Plano",
                icon: "TP",
                type: "modal",
                target: "calculadora-troca-plano",
            },
        ],
    },
    {
        id: "calculadora-internet-dedicada",
        label: "Calculadora Internet Dedicada",
        icon: "LD",
        type: "modal",
        target: "calculadora-link-dedicado",
        sort_order: 90,
    },
    {
        id: "calculadora-semi-dedicado",
        label: "Calculadora Semi Dedicado",
        icon: "SD",
        type: "modal",
        target: "calculadora-semi-dedicado",
        sort_order: 95,
    },
    {
        id: "calculadora-acordo",
        label: "Calculadora de Acordo",
        icon: "R$",
        type: "internal",
        target: "/acesso-rapido/calculadora-acordo",
        sort_order: 97,
    },
    {
        id: "calculadora-troca-plano",
        label: "Calculadora de Troca de Plano",
        icon: "TP",
        type: "modal",
        target: "calculadora-troca-plano",
        sort_order: 98,
    },
    {
        id: "assinaturas-email",
        label: "Assinaturas de e-mail",
        icon: "@",
        type: "internal",
        target: "/assinaturas-email",
        sort_order: 100,
    },
    {
        id: "mundiale",
        label: "Mundialle",
        icon: "M",
        type: "external",
        target: "https://oauth2.withub.ai/realms/withub/protocol/openid-connect/auth?client_id=authz&redirect_uri=https://account.withub.ai/server/oauth&scope=openid%20profile%20email&response_type=code&response_mode=form_post&state=vvscyus3hq&nonce=1mhxdefhn61",
        sort_order: 110,
    },
    {
        id: "grafana",
        label: "Grafana",
        icon: "▤",
        type: "external",
        target: "http://192.168.1.160:3000/login",
        sort_order: 120,
    },
    {
        id: "zabbix",
        label: "Zabbix",
        icon: "▧",
        type: "external",
        target: "http://192.168.1.160/zabbix.php?action=dashboard.view&dashboardid=1",
        sort_order: 130,
    },
    {
        id: "microsip",
        label: "Telefone",
        icon: "☎",
        type: "protocol",
        target: "tel:",
        sort_order: 140,
    },
];

const normalizarQuickAccessId = (valor = "") => (
    String(valor || "")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "")
        .slice(0, 80)
);

const usuarioPodeVerQuickAccess = async (usuario, item) => {
    if (typeof item.enabled === "function" && !item.enabled()) return false;
    if (item.enabled === false) return false;
    if (item.requires_purchase_permission) {
        return userHasPurchasePermission(usuario, item.requires_purchase_permission);
    }
    if (item.requires_network_diagnostic_permission) {
        return userHasNetworkDiagnosticPermission(usuario, item.requires_network_diagnostic_permission);
    }
    if (item.requires_sound_effect_permission) {
        return usuarioPodeUsarEfeitosSonoros(usuario);
    }
    if (!Array.isArray(item.perfis) || !item.perfis.length) return true;
    return item.perfis.includes(usuario?.perfil);
};

const serializarQuickAccessItem = (item) => ({
    id: item.id,
    label: item.label,
    subtitle: item.subtitle || "",
    icon: item.icon,
    type: item.type,
    target: item.target || null,
    sort_order: item.sort_order || 0,
    children: Array.isArray(item.children)
        ? item.children.map(serializarQuickAccessItem)
        : [],
});

const listarQuickAccessDisponiveis = async (usuario) => {
    const items = await Promise.all(
        QUICK_ACCESS_ITEMS.map(async (item) => (
            await usuarioPodeVerQuickAccess(usuario, item) ? item : null
        ))
    );

    return items
        .filter(Boolean)
        .sort((a, b) => (a.sort_order || 0) - (b.sort_order || 0))
        .map(serializarQuickAccessItem);
};

const buscarQuickAccessDisponivel = async (usuario, quickAccessId) => (
    (await listarQuickAccessDisponiveis(usuario))
        .find((item) => item.id === normalizarQuickAccessId(quickAccessId))
);
const CHANGELOG_CATEGORIAS = ["atualizacao", "correcao"];
const TEXTOS_ATENDIMENTO_PADRAO = [
    {
        title: "ALTERAÇÃO DE PLANO",
        content: `Recebemos uma solicitação de alteração de plano, caso opte pela alteração você entra em uma nova fidelidade!

Para dar continuidade à sua solicitação, por favor, me informe os seguintes dados:

* Nome completo:
* CPF/RG
* Data de nascimento:
* Endereço completo:

---

Nós temos os seguintes planos:

100Mb de 99,90 por 79,99 por 12 meses.
200Mb de 109,90 por 89,99 por 12 meses.
300Mb de 129,90 por 99,99 por 12 meses.
600MB por 109,99 por 12 meses.

---

Seu vencimento é todo dia 20, caso opte em alterar seu plano, será cobrado o valor do plano atual até a data da alteração, mais o valor proporcional até o dia 30 sob o valor do novo plano.

---

* A senhora confirma a alteração do plano para 700MB por 94,99?

---

Em razão da solicitação de troca de plano, informamos que o procedimento foi devidamente registrado.

Solicitamos, por gentileza, que aguarde alguns instantes, pois o setor responsável encaminhará, em seguida, o termo de adesão referente à solicitação realizada para a devida conferência e assinatura.

---

Cálculo proporcional:

Contar do último vencimento até a data de alteração + da data de alteração até o próximo vencimento.

Exemplo:
20/07/2025 até 25/07/2025 = 7 dias do plano antigo
25/07/2025 até 30/08/2025 = 3 dias do plano novo

---

Para calcular o proporcional:
Valor do plano ÷ 30 x os dias de utilização

Referente a 8 dias de uso 11/06/2026 até 18/06/2026:
R$24,52 do plano antigo 200mb por R$91,98
+
22 dias de uso de 19/06/2026 a 10/07/2026:
R$91,65 do plano 400mb por R$124,99

Referente a 3 dias de uso 16/06/2026 até 18/06/2026:
R$10,79 do plano antigo 300mb por R$107,99
+
27 dias de uso de 19/06/2026 a 15/07/2026:
R$112,49 do plano 400mb por R$124,99`,
    },
    {
        title: "ALTERAÇÃO DE VENCIMENTO",
        content: `Para dar continuidade à sua solicitação, por favor, me informe os seguintes dados:

* Nome completo:
* Data de nascimento:
* CPF/RG:
* Endereço completo

---

Nós temos as seguintes datas disponíveis:

Contratação na 1° quinzena do mês, do dia 01 a 15:
20, 25, 30.

---

Contratação na 2° quinzena do mês, do dia 16 a 31:
05, 10, 15.

************verificar internamente possibilidade de outras datas caso não agrade o cliente*****************

---

Seu vencimento é todo dia 20, caso opte em alterar seu vencimento, será cobrado o valor proporcional até a nova data escolhida.

Obs. Boletos vencidos não poderão ser alterados com a nova data, é necessário realizar o pagamento.

---

Certo, fazendo a alteração para todo dia 15, seu próximo vencimento será no dia 15/07/2026 no valor de R$158,66 se pago até o vencimento.

Referente a 46 dias de utilização de 31/05/2026 até 15/07/2026.

---

O senhor confirma a alteração do vencimento para dia 30?

Email/Mundiale:
Foi feita a alteração do seu vencimento para todo dia 10.`,
    },
];
const BOAS_PRATICAS_ATENDIMENTO_PADRAO = [
    {
        title: "SAUDAÇÃO INICIAL",
        content: `Sempre iniciar o atendimento com educação, identificação e disponibilidade para ajudar.

Exemplo:
Olá, tudo bem? Meu nome é [NOME] e vou te auxiliar no atendimento.`,
    },
    {
        title: "CONFIRMAÇÃO DE DADOS",
        content: `Antes de passar informações sensíveis, confirmar os dados do titular da conta.

Dados recomendados:

* Nome completo;
* CPF/RG;
* Data de nascimento;
* Endereço completo.`,
    },
    {
        title: "LINGUAGEM PROFISSIONAL",
        content: `Evitar gírias, abreviações excessivas, ironias ou respostas secas. Usar uma comunicação clara, objetiva e respeitosa.

Evitar:

* “não sei”;
* “não tem como”;
* “você tem que esperar”;
* “isso não é comigo”.

Preferir:

* “Vou verificar para você”;
* “Nesse caso, o procedimento correto é...”;
* “Vou te orientar da melhor forma”;
* “Peço por gentileza que aguarde enquanto verifico”.`,
    },
    {
        title: "CLIENTE INSATISFEITO",
        content: `Manter a calma, demonstrar empatia e não discutir com o cliente.

Exemplo:
Entendo sua insatisfação e peço desculpas pelo transtorno. Vou verificar a situação e buscar a melhor forma de te ajudar.`,
    },
    {
        title: "PALAVRAS DE BAIXO CALÃO",
        content: `Caso o cliente utilize palavras ofensivas, manter postura profissional e orientar com respeito.

Exemplo:
Entendo que a situação possa ser frustrante, mas peço por gentileza que mantenhamos o respeito durante o atendimento para que eu consiga te ajudar da melhor forma.`,
    },
    {
        title: "PRAZO DE RESPOSTA",
        content: `Nunca prometer um prazo sem confirmação. Quando depender de outro setor, informar que será encaminhado para análise.

Exemplo:
Vou encaminhar sua solicitação para o setor responsável e assim que houver retorno, informaremos você.`,
    },
    {
        title: "TRANSFERÊNCIA DE SETOR",
        content: `Sempre explicar o motivo da transferência e evitar passar o cliente sem contexto.

Exemplo:
Para te ajudar melhor, vou encaminhar seu atendimento para o setor responsável por esse tipo de solicitação.`,
    },
    {
        title: "ENCERRAMENTO DO ATENDIMENTO",
        content: `Antes de encerrar, confirmar se o cliente precisa de mais alguma coisa.

Exemplo:
Posso te ajudar com mais alguma informação?`,
    },
    {
        title: "ATENDIMENTO COM CLAREZA",
        content: `Responder de forma objetiva, mas sem parecer seco. Explicar o necessário sem gerar confusão.

Boas práticas:

* Ler a mensagem completa antes de responder;
* Evitar respostas automáticas fora de contexto;
* Confirmar informações antes de orientar;
* Não deixar o cliente sem retorno;
* Informar quando precisar de tempo para verificar.`,
    },
    {
        title: "REGISTRO INTERNO",
        content: `Sempre registrar informações importantes da conversa para manter histórico e facilitar futuros atendimentos.

Exemplos de informações importantes:

* Solicitação do cliente;
* Orientação passada;
* Prazo informado;
* Setor responsável;
* Pendências;
* Protocolo, se houver.`,
    },
];
const AVISO_GERAL_PADRAO = {
    titulo: "Novo recurso nos grupos",
    mensagem: "Agora é possível ver visualizações de mensagem nos grupos. Use a setinha da mensagem e clique em “Visualizações” para acompanhar quem recebeu e quem leu.",
};
const BANNER_HOME_PADRAO = {
    modo: "codigo",
    selo: "Dica de sucesso",
    titulo_linha_1: "Um bom vendedor sempre tem seu",
    titulo_linha_2: "",
    titulo_destaque: "produto em mãos.",
    descricao_linha_1: "Tenha sempre as ofertas da Acessa Net prontas para apresentar ao cliente.",
    descricao_linha_2: "",
    time_label: "",
    time_valor: "",
    time_detalhe: "",
    meta_label: "",
    meta_valor: "",
    meta_detalhe: "",
    rodada_label: "",
    rodada_valor: "",
    rodada_detalhe: "",
    oferta_titulo: "800 Mega",
    oferta_subtitulo: "+ Premiere",
    beneficio_1_titulo: "Internet ultrarrápida",
    beneficio_1_detalhe: "",
    beneficio_2_titulo: "Mais de 80 canais",
    beneficio_2_detalhe: "",
    beneficio_3_titulo: "App incluso",
    beneficio_3_detalhe: "",
    botao_texto: "Saiba mais",
    botao_url: "https://acessanet.com.br/planos#ofertas-tema",
    imagem_url: "",
    imagem_alt: "Banner principal da home",
};
const AVISOS_INTERNOS_PADRAO = {
    kicker: "Central interna",
    titulo: "Avisos, demandas e metas",
    subtitulo: "Acompanhe comunicados importantes, metas comerciais, demandas da equipe e conteúdos de apoio.",
    resumo_html: `
<div class="avisos-summary-card">
  <span class="avisos-summary-icon">📢</span>
  <div>
    <strong>3</strong>
    <p>Avisos ativos</p>
  </div>
</div>
<div class="avisos-summary-card">
  <span class="avisos-summary-icon">📋</span>
  <div>
    <strong>1</strong>
    <p>Demanda pendente</p>
  </div>
</div>
<div class="avisos-summary-card">
  <span class="avisos-summary-icon">🎯</span>
  <div>
    <strong>800 Mega</strong>
    <p>Foco de venda</p>
  </div>
</div>
<div class="avisos-summary-card">
  <span class="avisos-summary-icon">📚</span>
  <div>
    <strong>Wiki</strong>
    <p>Tutoriais internos</p>
  </div>
</div>`.trim(),
    comunicados_html: `
<div class="avisos-section-header">
  <div>
    <h2 class="avisos-section-title">Comunicados internos</h2>
    <p class="avisos-section-subtitle">Avisos, demandas e metas para a equipe.</p>
  </div>
</div>
<div class="avisos-notice-list">
  <article class="avisos-notice-card">
    <div class="avisos-notice-icon">📢</div>
    <div class="avisos-notice-content">
      <div class="avisos-notice-top">
        <span class="avisos-notice-type">Aviso interno</span>
        <span class="avisos-notice-date">Hoje</span>
      </div>
      <h3 class="avisos-notice-title">Atualização nos atendimentos</h3>
      <p class="avisos-notice-description">A equipe deve priorizar chamados de clientes sem conexão antes das demais solicitações.</p>
      <span class="avisos-status-badge">Importante</span>
    </div>
  </article>
  <article class="avisos-notice-card">
    <div class="avisos-notice-icon">📋</div>
    <div class="avisos-notice-content">
      <div class="avisos-notice-top">
        <span class="avisos-notice-type">Demanda</span>
        <span class="avisos-notice-date">Esta semana</span>
      </div>
      <h3 class="avisos-notice-title">Revisar clientes com planos antigos</h3>
      <p class="avisos-notice-description">Separar lista de clientes elegíveis para upgrade de plano e enviar para o comercial.</p>
      <span class="avisos-status-badge">Pendente</span>
    </div>
  </article>
  <article class="avisos-notice-card">
    <div class="avisos-notice-icon">🎯</div>
    <div class="avisos-notice-content">
      <div class="avisos-notice-top">
        <span class="avisos-notice-type">Meta de vendas</span>
        <span class="avisos-notice-date">Mensal</span>
      </div>
      <h3 class="avisos-notice-title">Meta do mês: novos planos</h3>
      <p class="avisos-notice-description">Objetivo comercial: aumentar vendas dos planos com 800 Mega + Premiere.</p>
      <span class="avisos-status-badge">Em andamento</span>
    </div>
  </article>
</div>`.trim(),
    lateral_html: `
<section class="avisos-goal-card">
  <span class="avisos-goal-badge">Meta comercial</span>
  <h2 class="avisos-goal-title">800 Mega + Premiere</h2>
  <p class="avisos-goal-text">Oferta principal para divulgação. Mantenha o argumento de venda simples, direto e focado no benefício para o cliente.</p>
  <div class="avisos-progress-box">
    <div class="avisos-progress-info">
      <span>Progresso da meta</span>
      <strong>62%</strong>
    </div>
    <div class="avisos-progress-track">
      <div class="avisos-progress-fill" style="width: 62%;"></div>
    </div>
  </div>
</section>
<section class="avisos-wiki-card">
  <div class="avisos-section-header-simple">
    <h2 class="avisos-section-title">Wiki interna</h2>
    <p class="avisos-section-subtitle">Tutoriais e dicas rápidas.</p>
  </div>
  <div class="avisos-wiki-list">
    <div class="avisos-wiki-item">
      <span class="avisos-wiki-icon">🖥️</span>
      <div>
        <strong>Como consultar plano do cliente</strong>
        <p>Passo a passo para localizar contrato, plano ativo e histórico do cliente.</p>
        <small>Sistema</small>
      </div>
    </div>
    <div class="avisos-wiki-item">
      <span class="avisos-wiki-icon">💬</span>
      <div>
        <strong>Como apresentar uma oferta</strong>
        <p>Dicas rápidas para explicar benefícios e fechar vendas com mais segurança.</p>
        <small>Vendas</small>
      </div>
    </div>
    <div class="avisos-wiki-item">
      <span class="avisos-wiki-icon">📚</span>
      <div>
        <strong>Informações úteis para novos funcionários</strong>
        <p>Resumo dos processos internos, canais de suporte e boas práticas.</p>
        <small>Treinamento</small>
      </div>
    </div>
  </div>
</section>`.trim(),
    resumo: [
        { id: "avisos-ativos", icone: "📢", valor: "3", rotulo: "Avisos ativos" },
        { id: "demanda-pendente", icone: "📋", valor: "1", rotulo: "Demanda pendente" },
        { id: "foco-venda", icone: "🎯", valor: "800 Mega", rotulo: "Foco de venda" },
        { id: "wiki", icone: "📚", valor: "Wiki", rotulo: "Tutoriais internos" },
    ],
    secao_comunicados: {
        titulo: "Comunicados internos",
        subtitulo: "Avisos, demandas e metas para a equipe.",
    },
    comunicados: [
        {
            id: "atualizacao-atendimentos",
            tipo: "Aviso interno",
            titulo: "Atualização nos atendimentos",
            descricao: "A equipe deve priorizar chamados de clientes sem conexão antes das demais solicitações.",
            status: "Importante",
            data: "Hoje",
            icone: "📢",
        },
        {
            id: "revisar-planos-antigos",
            tipo: "Demanda",
            titulo: "Revisar clientes com planos antigos",
            descricao: "Separar lista de clientes elegíveis para upgrade de plano e enviar para o comercial.",
            status: "Pendente",
            data: "Esta semana",
            icone: "📋",
        },
        {
            id: "meta-novos-planos",
            tipo: "Meta de vendas",
            titulo: "Meta do mês: novos planos",
            descricao: "Objetivo comercial: aumentar vendas dos planos com 800 Mega + Premiere.",
            status: "Em andamento",
            data: "Mensal",
            icone: "🎯",
        },
    ],
    meta: {
        selo: "Meta comercial",
        titulo: "800 Mega + Premiere",
        texto: "Oferta principal para divulgação. Mantenha o argumento de venda simples, direto e focado no benefício para o cliente.",
        progresso_label: "Progresso da meta",
        progresso: 62,
        vendas_reset_base: 0,
    },
    wiki: {
        titulo: "Wiki interna",
        subtitulo: "Tutoriais e dicas rápidas.",
        itens: [
            {
                id: "consultar-plano",
                icone: "🖥️",
                titulo: "Como consultar plano do cliente",
                descricao: "Passo a passo para localizar contrato, plano ativo e histórico do cliente.",
                categoria: "Sistema",
            },
            {
                id: "apresentar-oferta",
                icone: "💬",
                titulo: "Como apresentar uma oferta",
                descricao: "Dicas rápidas para explicar benefícios e fechar vendas com mais segurança.",
                categoria: "Vendas",
            },
            {
                id: "novos-funcionarios",
                icone: "📚",
                titulo: "Informações úteis para novos funcionários",
                descricao: "Resumo dos processos internos, canais de suporte e boas práticas.",
                categoria: "Treinamento",
            },
        ],
    },
};

const PLANTAO_DOMINGO_SETORES = [
    { id: "noc", nome: "NOC", aliases: [] },
    { id: "rede", nome: "Rede", aliases: ["red"] },
    { id: "cliente", nome: "Cliente", aliases: [] },
    { id: "terceiros", nome: "Terceiros", aliases: [] },
];

const PLANTAO_DOMINGO_PADRAO = {
    titulo: "Plantão de domingo",
    subtitulo: "Escala de quem ficará no plantão durante todo o domingo.",
    linhas: [
        {
            id: "domingo-inteiro",
            periodo: "Domingo",
            horario: "Dia inteiro",
            setores: PLANTAO_DOMINGO_SETORES.map(({ id, nome }) => ({
                id,
                nome,
                pessoas: [],
            })),
            observacoes: "",
        },
    ],
};

const WIKI_INTERNA_PADRAO = {
    categorias: [
        {
            id: "noc",
            titulo: "NOC",
            subtitulo: "Monitoramento, quedas, massivos e rotinas operacionais.",
            cor: "blue",
            cursos: [
                {
                    id: "massivos",
                    titulo: "Como identificar queda massiva",
                    descricao: "Procedimento para validar clientes offline, região afetada e abertura de alerta.",
                    atualizado: "Hoje",
                    destaque: true,
                },
                {
                    id: "dashboard-noc",
                    titulo: "Dashboard NOC",
                    descricao: "Explicação das métricas: baixa, regular, alta e offline.",
                    atualizado: "Hoje",
                },
                {
                    id: "rotina-monitoramento",
                    titulo: "Rotina de monitoramento",
                    descricao: "Checklist inicial para início de turno no NOC.",
                    atualizado: "Ontem",
                },
            ],
        },
        {
            id: "vendas",
            titulo: "Vendas",
            subtitulo: "Planos, abordagem comercial, promoções e dúvidas frequentes.",
            cor: "green",
            cursos: [
                {
                    id: "planos",
                    titulo: "Tabela de planos",
                    descricao: "Consulta rápida dos planos disponíveis, valores e benefícios.",
                    atualizado: "Hoje",
                    destaque: true,
                },
                {
                    id: "argumentos-venda",
                    titulo: "Argumentos de venda",
                    descricao: "Frases e estratégias para melhorar a conversão no atendimento.",
                    atualizado: "Esta semana",
                },
                {
                    id: "promocoes",
                    titulo: "Promoções ativas",
                    descricao: "Lista de campanhas atuais e regras comerciais.",
                    atualizado: "Hoje",
                },
            ],
        },
        {
            id: "desenvolvimento",
            titulo: "Desenvolvimento",
            subtitulo: "Documentação técnica, deploy, APIs, frontend e backend.",
            cor: "purple",
            cursos: [
                {
                    id: "deploy",
                    titulo: "Como subir alterações no servidor",
                    descricao: "Passo a passo para build, PM2, Git e atualização do projeto.",
                    atualizado: "Hoje",
                    destaque: true,
                },
                {
                    id: "apis",
                    titulo: "APIs do sistema",
                    descricao: "Onde ficam as URLs, tokens, variáveis .env e integrações.",
                    atualizado: "Ontem",
                },
                {
                    id: "estrutura-projeto",
                    titulo: "Estrutura do projeto",
                    descricao: "Organização de pastas, componentes, páginas e estilos.",
                    atualizado: "Esta semana",
                },
            ],
        },
        {
            id: "suporte",
            titulo: "Suporte Técnico",
            subtitulo: "Atendimento, diagnóstico, chamados e procedimentos técnicos.",
            cor: "orange",
            cursos: [
                {
                    id: "sem-internet",
                    titulo: "Cliente sem internet",
                    descricao: "Checklist de atendimento para clientes sem conexão.",
                    atualizado: "Hoje",
                    destaque: true,
                },
                {
                    id: "lentidao",
                    titulo: "Lentidão na conexão",
                    descricao: "Como validar sinal, equipamento, consumo e testes básicos.",
                    atualizado: "Ontem",
                },
                {
                    id: "abertura-chamado",
                    titulo: "Abertura de chamado",
                    descricao: "Padrão para registrar informações corretamente no sistema.",
                    atualizado: "Esta semana",
                },
            ],
        },
    ],
};

const garantirMetadadosGrupos = async (connection = db) => {
    if (metadadosGruposGarantidos) return;

    await connection.query(`
        ALTER TABLE grupos
        ADD COLUMN IF NOT EXISTS fixo TINYINT(1) NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS setor_id INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS deletado_em TIMESTAMP NULL DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS mensagem_fixada_titulo VARCHAR(180) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS mensagem_fixada_conteudo TEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS mensagem_fixada_ativo TINYINT(1) NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS mensagem_fixada_atualizada_em TIMESTAMP NULL DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS mensagem_fixada_atualizada_por INT DEFAULT NULL
    `);

    metadadosGruposGarantidos = true;
};

const garantirAvisosInternosTabela = async (connection = db) => {
    if (avisosInternosTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS avisos_internos_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            conteudo_json LONGTEXT NOT NULL,
            atualizado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_avisos_empresa (empresa_id),
            INDEX idx_avisos_empresa (empresa_id),
            INDEX idx_avisos_atualizado_por (atualizado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    avisosInternosTabelaGarantida = true;
};

const garantirPlantaoDomingoTabela = async (connection = db) => {
    if (plantaoDomingoTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS plantao_domingo_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            conteudo_json LONGTEXT NOT NULL,
            atualizado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_plantao_domingo_empresa (empresa_id),
            INDEX idx_plantao_domingo_empresa (empresa_id),
            INDEX idx_plantao_domingo_atualizado_por (atualizado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    plantaoDomingoTabelaGarantida = true;
};

const garantirWikiInternaTabela = async (connection = db) => {
    if (wikiInternaTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS wiki_interna_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            conteudo_json LONGTEXT NOT NULL,
            atualizado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_wiki_interna_empresa (empresa_id),
            INDEX idx_wiki_interna_empresa (empresa_id),
            INDEX idx_wiki_interna_atualizado_por (atualizado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    wikiInternaTabelaGarantida = true;
};

const garantirWikiCursosConfigTabela = async (connection = db) => {
    if (wikiCursosConfigTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS wiki_cursos_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            curso_id VARCHAR(160) NOT NULL,
            conteudo_json LONGTEXT NOT NULL,
            atualizado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_wiki_curso_empresa (empresa_id, curso_id),
            INDEX idx_wiki_curso_empresa (empresa_id),
            INDEX idx_wiki_curso_atualizado_por (atualizado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    wikiCursosConfigTabelaGarantida = true;
};

const garantirWikiAulasConfigTabela = async (connection = db) => {
    if (wikiAulasConfigTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS wiki_aulas_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            curso_id VARCHAR(160) NOT NULL,
            aula_chave VARCHAR(180) NOT NULL,
            conteudo_json LONGTEXT NOT NULL,
            atualizado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_wiki_aula_empresa (empresa_id, curso_id, aula_chave),
            INDEX idx_wiki_aula_empresa (empresa_id),
            INDEX idx_wiki_aula_atualizado_por (atualizado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    wikiAulasConfigTabelaGarantida = true;
};

const garantirWikiAulasProgressoTabela = async (connection = db) => {
    if (wikiAulasProgressoTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS wiki_aulas_progresso (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            usuario_id INT NOT NULL,
            curso_id VARCHAR(160) NOT NULL,
            aula_chave VARCHAR(180) NOT NULL,
            concluida TINYINT(1) NOT NULL DEFAULT 0,
            acessada_em TIMESTAMP NULL DEFAULT NULL,
            concluida_em TIMESTAMP NULL DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_wiki_aula_progresso_usuario (
                empresa_id,
                usuario_id,
                curso_id,
                aula_chave
            ),
            INDEX idx_wiki_aula_progresso_usuario (empresa_id, usuario_id, curso_id),
            INDEX idx_wiki_aula_progresso_ultima (empresa_id, usuario_id, curso_id, acessada_em),
            INDEX idx_wiki_aula_progresso_concluida (empresa_id, usuario_id, curso_id, concluida)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    wikiAulasProgressoTabelaGarantida = true;
};

const garantirBannerHomeTabela = async (connection = db) => {
    if (bannerHomeTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS banner_home_config (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            conteudo_json LONGTEXT NOT NULL,
            atualizado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_banner_home_empresa (empresa_id),
            INDEX idx_banner_home_empresa (empresa_id),
            INDEX idx_banner_home_atualizado_por (atualizado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    bannerHomeTabelaGarantida = true;
};

let imagensGaleriaTabelaGarantida = false;

const garantirImagensGaleriaTabela = async () => {
    if (imagensGaleriaTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS imagens_galeria (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            titulo VARCHAR(255) NOT NULL DEFAULT '',
            descricao TEXT DEFAULT NULL,
            imagem_url VARCHAR(500) NOT NULL,
            criado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_imagens_galeria_empresa_criado_em (empresa_id, criado_em),
            INDEX idx_imagens_galeria_criado_por (criado_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    imagensGaleriaTabelaGarantida = true;
};

const CCNA_COMPETITION_MODULES = [
    {
        id: "introduction-to-networks",
        title: "CCNA: Introduction to Networks",
        url: "https://cursoseventos.nic.br/curso/curso-ccna-intro-cisco-nicbr/",
    },
    {
        id: "switching-routing-wireless-essentials",
        title: "CCNA: Switching, Routing and Wireless Essentials",
        url: "https://cursoseventos.nic.br/curso/curso-ccna-srwe-cisco-nicbr/",
    },
    {
        id: "enterprise-networking-security-automation",
        title: "CCNA: Enterprise Networking, Security, and Automation",
        url: "https://cursoseventos.nic.br/curso/curso-ccna-ensa-cisco-nicbr/",
    },
];

const CCNA_VALID_MODULE_IDS = CCNA_COMPETITION_MODULES.map((module) => module.id);
const CCNA_PARTICIPANT_STATUSES = ["nao_iniciado", "em_andamento", "aguardando_validacao", "validado", "ganhador"];
const CCNA_PROOF_STATUSES = ["pendente", "enviado", "aprovado", "reprovado"];
const CCNA_COMPETITION_STATUSES = ["ativa", "encerrada", "ganhador_definido"];

const obterPrazoPadraoCompeticaoCcna = () => `${new Date().getFullYear()}-12-31`;

const garantirCompeticaoCcnaTabelas = async (connection = db) => {
    if (competicaoCcnaTabelasGarantidas) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS ccna_competition_config (
            id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
            deadline_date DATE NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'ativa',
            winner_participant_id INT UNSIGNED NULL,
            winner_user_id INT UNSIGNED NULL,
            winner_defined_at DATETIME NULL,
            updated_by INT UNSIGNED NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        CREATE TABLE IF NOT EXISTS ccna_competition_participants (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id INT UNSIGNED NOT NULL,
            empresa_id INT UNSIGNED NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'nao_iniciado',
            joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_ccna_participant_user (user_id),
            KEY idx_ccna_participant_empresa (empresa_id),
            KEY idx_ccna_participant_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        CREATE TABLE IF NOT EXISTS ccna_competition_proofs (
            id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            participant_id INT UNSIGNED NOT NULL,
            module_id VARCHAR(96) NOT NULL,
            proof_url TEXT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'pendente',
            admin_note TEXT NULL,
            submitted_at DATETIME NULL,
            validated_by INT UNSIGNED NULL,
            validated_at DATETIME NULL,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY unique_ccna_participant_module (participant_id, module_id),
            KEY idx_ccna_proofs_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        INSERT INTO ccna_competition_config (id, deadline_date, status)
        VALUES (1, ?, 'ativa')
        ON DUPLICATE KEY UPDATE id = id
    `, [obterPrazoPadraoCompeticaoCcna()]);

    competicaoCcnaTabelasGarantidas = true;
};

const garantirModulosParticipanteCcna = async (participantId, connection = db) => {
    for (const module of CCNA_COMPETITION_MODULES) {
        await connection.query(`
            INSERT INTO ccna_competition_proofs (participant_id, module_id)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE participant_id = participant_id
        `, [participantId, module.id]);
    }
};

const buscarConfigCompeticaoCcna = async (connection = db) => {
    await garantirCompeticaoCcnaTabelas(connection);

    const [rows] = await connection.query(`
        SELECT
            id,
            DATE_FORMAT(deadline_date, '%Y-%m-%d') AS deadline_date,
            status,
            winner_participant_id,
            winner_user_id,
            winner_defined_at,
            updated_at
        FROM ccna_competition_config
        WHERE id = 1
        LIMIT 1
    `);

    return rows[0] || {
        id: 1,
        deadline_date: obterPrazoPadraoCompeticaoCcna(),
        status: "ativa",
        winner_participant_id: null,
        winner_user_id: null,
        winner_defined_at: null,
    };
};

const normalizarStatusParticipanteCcna = (status) => (
    CCNA_PARTICIPANT_STATUSES.includes(status) ? status : "nao_iniciado"
);

const calcularStatusParticipanteCcna = (proofs, winnerParticipantId, participantId, statusAtual = "nao_iniciado") => {
    if (Number(winnerParticipantId) === Number(participantId) || statusAtual === "ganhador") {
        return "ganhador";
    }

    const totalAprovados = proofs.filter((proof) => proof.status === "aprovado").length;
    const totalEnviados = proofs.filter((proof) => proof.status === "enviado").length;
    const totalComProva = proofs.filter((proof) => proof.status !== "pendente").length;

    if (totalAprovados >= CCNA_COMPETITION_MODULES.length) return "validado";
    if (totalEnviados > 0) return "aguardando_validacao";
    if (totalComProva > 0) return "em_andamento";

    return normalizarStatusParticipanteCcna(statusAtual);
};

const montarParticipantesCompeticaoCcna = async ({ incluirProvasAdmin = false, currentUserId = null } = {}) => {
    await garantirCompeticaoCcnaTabelas();
    const config = await buscarConfigCompeticaoCcna();

    const [participantsRows] = await db.query(`
        SELECT
            p.id,
            p.user_id,
            p.empresa_id,
            p.status,
            p.joined_at,
            p.updated_at,
            u.nome,
            u.email,
            u.perfil
        FROM ccna_competition_participants p
        INNER JOIN usuarios u ON u.id = p.user_id
        WHERE u.deletado_em IS NULL
        ORDER BY p.joined_at ASC, p.id ASC
    `);

    if (participantsRows.length === 0) {
        return { config, participants: [] };
    }

    const participantIds = participantsRows.map((participant) => participant.id);
    const [proofRows] = await db.query(`
        SELECT
            id,
            participant_id,
            module_id,
            proof_url,
            status,
            admin_note,
            submitted_at,
            validated_by,
            validated_at,
            updated_at
        FROM ccna_competition_proofs
        WHERE participant_id IN (?)
        ORDER BY module_id
    `, [participantIds]);

    const proofsByParticipant = proofRows.reduce((acc, proof) => {
        if (!acc[proof.participant_id]) acc[proof.participant_id] = [];
        acc[proof.participant_id].push(proof);
        return acc;
    }, {});

    const participants = participantsRows.map((participant) => {
        const storedProofs = proofsByParticipant[participant.id] || [];
        const proofs = CCNA_COMPETITION_MODULES.map((module) => {
            const proof = storedProofs.find((item) => item.module_id === module.id) || {};

            return {
                id: proof.id || null,
                module_id: module.id,
                title: module.title,
                url: module.url,
                proof_url: incluirProvasAdmin || Number(participant.user_id) === Number(currentUserId)
                    ? (proof.proof_url || "")
                    : "",
                status: CCNA_PROOF_STATUSES.includes(proof.status) ? proof.status : "pendente",
                admin_note: incluirProvasAdmin ? (proof.admin_note || "") : "",
                submitted_at: proof.submitted_at || null,
                validated_by: proof.validated_by || null,
                validated_at: proof.validated_at || null,
                updated_at: proof.updated_at || null,
            };
        });
        const approvedCount = proofs.filter((proof) => proof.status === "aprovado").length;
        const submittedCount = proofs.filter((proof) => proof.status === "enviado").length;
        const status = calcularStatusParticipanteCcna(
            proofs,
            config.winner_participant_id,
            participant.id,
            participant.status
        );

        return {
            id: participant.id,
            user_id: participant.user_id,
            nome: participant.nome,
            email: incluirProvasAdmin ? participant.email : undefined,
            perfil: incluirProvasAdmin ? participant.perfil : undefined,
            status,
            progress: approvedCount,
            submitted_count: submittedCount,
            total_modules: CCNA_COMPETITION_MODULES.length,
            joined_at: participant.joined_at,
            updated_at: participant.updated_at,
            proofs,
        };
    });

    return { config, participants };
};

const definirGanhadorCcnaSeNecessario = async (participantId, adminId) => {
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();
        await garantirCompeticaoCcnaTabelas(connection);

        const [configRows] = await connection.query(`
            SELECT winner_participant_id
            FROM ccna_competition_config
            WHERE id = 1
            FOR UPDATE
        `);

        if (configRows[0]?.winner_participant_id) {
            await connection.commit();
            return false;
        }

        const [approvedRows] = await connection.query(`
            SELECT COUNT(*) AS total
            FROM ccna_competition_proofs
            WHERE participant_id = ? AND status = 'aprovado'
        `, [participantId]);

        const totalApproved = Number(approvedRows[0]?.total || 0);
        if (totalApproved < CCNA_COMPETITION_MODULES.length) {
            await connection.commit();
            return false;
        }

        const [participantRows] = await connection.query(`
            SELECT user_id
            FROM ccna_competition_participants
            WHERE id = ?
            LIMIT 1
        `, [participantId]);

        const participant = participantRows[0];
        if (!participant) {
            await connection.commit();
            return false;
        }

        await connection.query(`
            UPDATE ccna_competition_participants
            SET status = 'ganhador'
            WHERE id = ?
        `, [participantId]);

        await connection.query(`
            UPDATE ccna_competition_config
            SET
                status = 'ganhador_definido',
                winner_participant_id = ?,
                winner_user_id = ?,
                winner_defined_at = NOW(),
                updated_by = ?
            WHERE id = 1
        `, [participantId, participant.user_id, adminId]);

        await connection.commit();
        return true;
    } catch (err) {
        await connection.rollback();
        throw err;
    } finally {
        connection.release();
    }
};

const garantirFeedbacksTabela = async (connection = db) => {
    if (feedbacksTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS feedbacks (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            usuario_id INT DEFAULT NULL,
            nome VARCHAR(160) NOT NULL,
            tipo VARCHAR(20) NOT NULL,
            setor VARCHAR(120) DEFAULT NULL,
            prioridade VARCHAR(20) NOT NULL DEFAULT 'media',
            pagina VARCHAR(255) DEFAULT NULL,
            descricao TEXT NOT NULL,
            resposta TEXT DEFAULT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'aberto',
            resolvido_por INT DEFAULT NULL,
            resolvido_em TIMESTAMP NULL DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_feedbacks_empresa (empresa_id),
            INDEX idx_feedbacks_usuario (usuario_id),
            INDEX idx_feedbacks_resolvido_por (resolvido_por),
            INDEX idx_feedbacks_tipo (tipo),
            INDEX idx_feedbacks_status (status),
            INDEX idx_feedbacks_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        ALTER TABLE feedbacks
        ADD COLUMN IF NOT EXISTS resposta TEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS resolvido_por INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS resolvido_em TIMESTAMP NULL DEFAULT NULL
    `);

    feedbacksTabelaGarantida = true;
};

const garantirChangelogTabela = async (connection = db) => {
    if (changelogTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS changelog_entries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            categoria VARCHAR(20) NOT NULL DEFAULT 'atualizacao',
            titulo VARCHAR(180) NOT NULL,
            versao VARCHAR(40) NOT NULL,
            data_publicacao DATE NOT NULL,
            texto TEXT NOT NULL,
            criado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_changelog_empresa (empresa_id),
            INDEX idx_changelog_categoria (categoria),
            INDEX idx_changelog_data (data_publicacao),
            INDEX idx_changelog_criado_em (criado_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    changelogTabelaGarantida = true;
};

const garantirAvisoGeralTabela = async (connection = db) => {
    if (avisoGeralTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS avisos_gerais (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            titulo VARCHAR(180) NOT NULL,
            mensagem TEXT NOT NULL,
            image_url VARCHAR(500) DEFAULT NULL,
            summary VARCHAR(320) DEFAULT NULL,
            tipo VARCHAR(80) NOT NULL DEFAULT 'Comunicado',
            categoria VARCHAR(80) NOT NULL DEFAULT 'Sistema',
            prioridade VARCHAR(20) NOT NULL DEFAULT 'media',
            resume_text TEXT DEFAULT NULL,
            changes_json LONGTEXT DEFAULT NULL,
            important_info_json LONGTEXT DEFAULT NULL,
            action_required_json LONGTEXT DEFAULT NULL,
            detail_url VARCHAR(500) DEFAULT NULL,
            detail_button_text VARCHAR(80) DEFAULT 'Ver detalhes',
            show_new_badge TINYINT(1) NOT NULL DEFAULT 1,
            require_confirmation TINYINT(1) NOT NULL DEFAULT 1,
            ativo TINYINT(1) NOT NULL DEFAULT 1,
            allow_close TINYINT(1) NOT NULL DEFAULT 0,
            allow_snooze TINYINT(1) NOT NULL DEFAULT 1,
            starts_at DATETIME DEFAULT NULL,
            ends_at DATETIME DEFAULT NULL,
            criado_por INT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_avisos_gerais_empresa (empresa_id),
            INDEX idx_avisos_gerais_ativo (ativo),
            INDEX idx_avisos_gerais_criado_em (criado_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        ALTER TABLE avisos_gerais
        ADD COLUMN IF NOT EXISTS summary VARCHAR(320) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS image_url VARCHAR(500) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS tipo VARCHAR(80) NOT NULL DEFAULT 'Comunicado',
        ADD COLUMN IF NOT EXISTS categoria VARCHAR(80) NOT NULL DEFAULT 'Sistema',
        ADD COLUMN IF NOT EXISTS prioridade VARCHAR(20) NOT NULL DEFAULT 'media',
        ADD COLUMN IF NOT EXISTS resume_text TEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS changes_json LONGTEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS important_info_json LONGTEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS action_required_json LONGTEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS detail_url VARCHAR(500) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS detail_button_text VARCHAR(80) DEFAULT 'Ver detalhes',
        ADD COLUMN IF NOT EXISTS show_new_badge TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS require_confirmation TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS allow_close TINYINT(1) NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS allow_snooze TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS starts_at DATETIME DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS ends_at DATETIME DEFAULT NULL
    `);

    await connection.query(`
        CREATE TABLE IF NOT EXISTS avisos_gerais_confirmacoes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            aviso_id INT NOT NULL,
            usuario_id INT NOT NULL,
            confirmado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (aviso_id) REFERENCES avisos_gerais(id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_aviso_usuario (aviso_id, usuario_id),
            INDEX idx_aviso_confirmacao (aviso_id),
            INDEX idx_usuario_confirmacao (usuario_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        CREATE TABLE IF NOT EXISTS avisos_gerais_sonecas (
            id INT AUTO_INCREMENT PRIMARY KEY,
            aviso_id INT NOT NULL,
            usuario_id INT NOT NULL,
            snoozed_until DATETIME NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (aviso_id) REFERENCES avisos_gerais(id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_aviso_soneca_usuario (aviso_id, usuario_id),
            INDEX idx_aviso_soneca_usuario (aviso_id, usuario_id),
            INDEX idx_aviso_soneca_until (snoozed_until)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    avisoGeralTabelaGarantida = true;
};

const garantirAvisoGeralPadrao = async (empresaId, usuarioId = null) => {
    await garantirAvisoGeralTabela();

    const [rows] = await db.query(`
        SELECT id
        FROM avisos_gerais
        WHERE empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    if (rows.length) return;

    await db.query(`
        INSERT INTO avisos_gerais (empresa_id, titulo, mensagem, ativo, criado_por)
        VALUES (?, ?, ?, 1, ?)
    `, [
        empresaId,
        AVISO_GERAL_PADRAO.titulo,
        AVISO_GERAL_PADRAO.mensagem,
        usuarioId,
    ]);
};

const buscarAvisoGeralAdmin = async (empresaId) => {
    await garantirAvisoGeralPadrao(empresaId);

    const [avisos] = await db.query(`
        SELECT
            a.id,
            a.titulo,
            a.mensagem,
            a.image_url,
            a.ativo,
            a.summary,
            a.tipo,
            a.categoria,
            a.prioridade,
            a.resume_text,
            a.changes_json,
            a.important_info_json,
            a.action_required_json,
            a.detail_url,
            a.detail_button_text,
            a.show_new_badge,
            a.require_confirmation,
            a.allow_close,
            a.allow_snooze,
            a.starts_at,
            a.ends_at,
            a.criado_por,
            u.nome AS criado_por_nome,
            a.criado_em,
            a.atualizado_em,
            (SELECT COUNT(*) FROM avisos_gerais_confirmacoes c WHERE c.aviso_id = a.id) AS confirmacoes,
            (SELECT COUNT(*) FROM usuarios us WHERE us.empresa_id = a.empresa_id AND us.deletado_em IS NULL) AS total_usuarios
        FROM avisos_gerais a
        LEFT JOIN usuarios u ON a.criado_por = u.id
        WHERE a.empresa_id = ?
        ORDER BY a.criado_em DESC, a.id DESC
        LIMIT 1
    `, [empresaId]);

    const aviso = avisos[0] || null;
    if (!aviso) return null;

    const [usuariosConfirmacao] = await db.query(`
        SELECT
            u.id,
            u.nome,
            u.email,
            s.nome AS setor_nome,
            c.confirmado_em
        FROM usuarios u
        LEFT JOIN setores s ON s.id = u.setor_id
        LEFT JOIN avisos_gerais_confirmacoes c
            ON c.usuario_id = u.id
           AND c.aviso_id = ?
        WHERE u.empresa_id = ?
          AND u.deletado_em IS NULL
        ORDER BY
            CASE WHEN c.confirmado_em IS NULL THEN 1 ELSE 0 END,
            c.confirmado_em DESC,
            u.nome ASC
    `, [aviso.id, empresaId]);
    const confirmados = usuariosConfirmacao
        .filter((usuario) => usuario.confirmado_em)
        .map((usuario) => ({
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
            setor_nome: usuario.setor_nome,
            confirmado_em: usuario.confirmado_em,
        }));
    const usuariosPendentes = usuariosConfirmacao
        .filter((usuario) => !usuario.confirmado_em)
        .map((usuario) => ({
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email,
            setor_nome: usuario.setor_nome,
        }));

    return {
        ...aviso,
        ativo: Boolean(aviso.ativo),
        confirmacoes: confirmados.length,
        total_usuarios: usuariosConfirmacao.length || Number(aviso.total_usuarios || 0),
        pendentes: usuariosPendentes.length,
        confirmados,
        usuarios_pendentes: usuariosPendentes,
    };
};

const limitarTexto = (valor, limite = 255) => {
    const texto = String(valor || "").trim().replace(/\s+/g, " ");
    return texto.slice(0, limite);
};

const normalizarTextoLongo = (valor, limite = 3000) => (
    String(valor || "").trim().slice(0, limite)
);

const normalizarBooleanoAvisoInterno = (valor, fallback = false) => {
    if (valor === undefined || valor === null || valor === "") return fallback;
    if (typeof valor === "boolean") return valor;
    if (typeof valor === "number") return valor === 1;

    const texto = String(valor)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .trim();

    if (["1", "true", "sim", "yes", "on"].includes(texto)) return true;
    if (["0", "false", "nao", "no", "off"].includes(texto)) return false;

    return Boolean(valor);
};

const removerArquivoAvisoGeralPorUrl = (url = "") => {
    const texto = String(url || "");
    const prefixo = "/uploads/avisos/";

    if (!texto.startsWith(prefixo)) return;

    const relativo = texto.slice(prefixo.length);
    const caminho = path.resolve(AVISO_GERAL_UPLOAD_ROOT, relativo);
    const raiz = path.resolve(AVISO_GERAL_UPLOAD_ROOT);

    if (!caminho.startsWith(`${raiz}${path.sep}`)) return;

    fs.rmSync(caminho, { force: true });
};

const PRIORIDADES_AVISO_INTERNO = new Set(["baixa", "media", "alta", "critica"]);
const ICONES_AVISO_INTERNO = new Set([
    "alert",
    "bell",
    "calendar",
    "check",
    "info",
    "settings",
    "shield",
    "users",
    "wifi",
]);

const parseJsonAvisoInterno = (valor, fallback) => {
    if (valor === null || valor === undefined || valor === "") return fallback;
    if (typeof valor === "object") return valor;

    try {
        return JSON.parse(String(valor));
    } catch {
        return fallback;
    }
};

const normalizarPrioridadeAvisoInterno = (valor = "media") => {
    const prioridade = String(valor || "media")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .trim();

    return PRIORIDADES_AVISO_INTERNO.has(prioridade) ? prioridade : "media";
};

const normalizarIconeAvisoInterno = (valor = "info") => {
    const icone = String(valor || "info")
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9_-]/g, "")
        .slice(0, 40);

    return ICONES_AVISO_INTERNO.has(icone) ? icone : "info";
};

const normalizarAlteracoesAvisoInterno = (valor) => {
    const itens = parseJsonAvisoInterno(valor, []);
    const origem = Array.isArray(itens) ? itens : [];

    return origem.slice(0, 3).map((item, index) => ({
        icon: normalizarIconeAvisoInterno(item?.icon || item?.icone || (index === 0 ? "info" : "check")),
        title: limitarTexto(item?.title || item?.titulo, 90),
        description: normalizarTextoLongo(item?.description || item?.descricao, 180),
    })).filter((item) => item.title || item.description);
};

const normalizarInformacoesAvisoInterno = (valor) => {
    const itens = parseJsonAvisoInterno(valor, []);
    const origem = Array.isArray(itens) ? itens : [];

    return origem
        .slice(0, 8)
        .map((item) => normalizarTextoLongo(typeof item === "string" ? item : item?.text || item?.descricao, 220))
        .filter(Boolean);
};

const normalizarAcaoAvisoInterno = (valor) => {
    const acao = parseJsonAvisoInterno(valor, null);
    if (!acao || typeof acao !== "object") return null;

    const title = limitarTexto(acao.title || acao.titulo, 120);
    const description = normalizarTextoLongo(acao.description || acao.descricao, 360);

    if (!title && !description) return null;

    return { title, description };
};

const normalizarDataHoraAvisoInterno = (valor) => {
    if (!valor) return null;

    const data = new Date(valor);
    if (Number.isNaN(data.getTime())) return null;

    return data.toISOString().slice(0, 19).replace("T", " ");
};

const serializarAvisoInterno = (row = {}) => {
    const priority = normalizarPrioridadeAvisoInterno(row.prioridade);
    const message = normalizarTextoLongo(row.mensagem, 3000);
    const summary = limitarTexto(row.summary || message, 320);
    const resumeText = normalizarTextoLongo(row.resume_text, 1200);
    const resume = resumeText || message;
    const allowClose = priority !== "critica" && Boolean(row.allow_close);
    const allowSnooze = priority !== "critica" && Boolean(row.allow_snooze);
    const requireConfirmation = priority === "critica" || row.require_confirmation === undefined
        ? true
        : Boolean(row.require_confirmation);

    return {
        id: row.id,
        title: row.titulo,
        message,
        summary,
        imageUrl: row.image_url || "",
        type: row.tipo || "Comunicado",
        category: row.categoria || "Sistema",
        priority,
        createdAt: row.criado_em,
        updatedAt: row.atualizado_em,
        isNew: row.show_new_badge === undefined ? true : Boolean(row.show_new_badge),
        allowClose,
        allowSnooze,
        detailUrl: row.detail_url || "",
        detailButtonText: row.detail_button_text || "Ver detalhes",
        requireConfirmation,
        createdBy: row.criado_por || null,
        createdByName: row.criado_por_nome || "",
        sections: {
            resume,
            changes: normalizarAlteracoesAvisoInterno(row.changes_json),
            importantInfo: normalizarInformacoesAvisoInterno(row.important_info_json),
            actionRequired: normalizarAcaoAvisoInterno(row.action_required_json),
        },
    };
};

const ehPerguntaBoasPraticas = (feedback = {}) => (
    feedback.tipo === "pergunta"
    && feedback.pagina === BOAS_PRATICAS_DUVIDAS_PAGINA
);

const normalizarDataPublicacao = (valor) => {
    const texto = String(valor || "").trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(texto)) return "";
    return texto;
};

const NOTE_SHARE_PERMISSIONS = new Set(["view", "edit"]);

const normalizarPermissaoNota = (valor) => (
    NOTE_SHARE_PERMISSIONS.has(String(valor || "").trim())
        ? String(valor).trim()
        : "view"
);

const rotuloPermissaoNota = (permissao) => (
    permissao === "edit" ? "Pode editar" : "Pode visualizar"
);

const formatarUsuarioNota = (usuario = {}) => ({
    id: usuario.id,
    nome: usuario.nome || null,
    email: usuario.email || null,
    setor_nome: usuario.setor_nome || null,
});

const formatarNotaRapida = (nota) => {
    const ownerId = Number(nota.owner_user_id || nota.user_id);
    const accessType = nota.access_type || "owner";
    const permission = accessType === "owner"
        ? "owner"
        : normalizarPermissaoNota(nota.permission || nota.share_permission);

    return {
        id: nota.id,
        user_id: ownerId,
        owner_user_id: ownerId,
        owner: {
            id: ownerId,
            nome: nota.owner_name || null,
            email: nota.owner_email || null,
            setor_nome: nota.owner_setor_nome || null,
        },
        access_type: accessType,
        permission,
        can_edit: accessType === "owner" || permission === "edit",
        can_manage: accessType === "owner",
        title: nota.title,
        content: nota.content || "",
        pinned: Boolean(nota.pinned),
        created_at: nota.created_at,
        updated_at: nota.updated_at,
        last_edited_by: nota.last_edited_by_id
            ? {
                id: nota.last_edited_by_id,
                nome: nota.last_edited_by_name || null,
                email: nota.last_edited_by_email || null,
                setor_nome: nota.last_edited_by_setor_nome || null,
            }
            : null,
        shared_users: Array.isArray(nota.shared_users) ? nota.shared_users : [],
    };
};

const normalizarCompartilhamentosNota = (valor, usuarioAtualId) => {
    if (valor === undefined || valor === null) return [];
    if (!Array.isArray(valor)) return null;

    const compartilhamentos = [];
    const idsAdicionados = new Set();

    for (const item of valor) {
        const usuarioId = typeof item === "object" && item !== null
            ? Number(item.user_id ?? item.userId ?? item.id)
            : Number(item);

        if (
            !Number.isInteger(usuarioId)
            || usuarioId <= 0
            || usuarioId === Number(usuarioAtualId)
            || idsAdicionados.has(usuarioId)
        ) {
            continue;
        }

        compartilhamentos.push({
            user_id: usuarioId,
            permission: typeof item === "object" && item !== null
                ? normalizarPermissaoNota(item.permission)
                : "view",
        });
        idsAdicionados.add(usuarioId);
    }

    return compartilhamentos.slice(0, 100);
};

const normalizarBooleano = (valor, fallback = false) => {
    if (valor === undefined || valor === null) return fallback;
    return valor === true || valor === "true" || valor === 1 || valor === "1";
};

const normalizarOrdemTextoAtendimento = (valor, fallback = 0) => {
    const numero = Number(valor);
    if (!Number.isFinite(numero)) return fallback;
    return Math.trunc(numero);
};

const garantirTabelaMateriaisVendas = async () => {
    if (salesMaterialsTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS sales_materials (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            title VARCHAR(255) NOT NULL,
            description TEXT DEFAULT NULL,
            category VARCHAR(100) DEFAULT NULL,
            material_type VARCHAR(50) NOT NULL DEFAULT 'outro',
            cover_image_url VARCHAR(500) DEFAULT NULL,
            file_url VARCHAR(500) DEFAULT NULL,
            file_name VARCHAR(255) DEFAULT NULL,
            file_mime VARCHAR(180) DEFAULT NULL,
            file_size BIGINT DEFAULT NULL,
            external_url VARCHAR(500) DEFAULT NULL,
            display_order INT NOT NULL DEFAULT 0,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            created_by INT DEFAULT NULL,
            updated_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_sales_materials_empresa_active_order (empresa_id, is_active, display_order),
            INDEX idx_sales_materials_empresa_order (empresa_id, display_order),
            INDEX idx_sales_materials_created_by (created_by),
            INDEX idx_sales_materials_updated_by (updated_by)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE sales_materials
        ADD COLUMN IF NOT EXISTS empresa_id INT NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS material_type VARCHAR(50) NOT NULL DEFAULT 'outro',
        ADD COLUMN IF NOT EXISTS cover_image_url VARCHAR(500) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS file_url VARCHAR(500) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS file_name VARCHAR(255) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS file_mime VARCHAR(180) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS external_url VARCHAR(500) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS display_order INT NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS is_active TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS created_by INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS updated_by INT DEFAULT NULL
    `);

    salesMaterialsTabelaGarantida = true;
};

const garantirMateriaisVendasPadrao = async (empresaId, usuarioId = null) => {
    await garantirTabelaMateriaisVendas();

    const [existentes] = await db.query(`
        SELECT id
        FROM sales_materials
        WHERE empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    if (!existentes.length) {
        const connection = await db.getConnection();

        try {
            await connection.beginTransaction();

            const [existentesTransacao] = await connection.query(`
                SELECT id
                FROM sales_materials
                WHERE empresa_id = ?
                LIMIT 1
                FOR UPDATE
            `, [empresaId]);

            if (!existentesTransacao.length) {
                for (const material of SALES_MATERIALS_PADRAO) {
                    await connection.query(`
                        INSERT INTO sales_materials (
                            empresa_id,
                            title,
                            description,
                            category,
                            material_type,
                            display_order,
                            is_active,
                            created_by,
                            updated_by
                        )
                        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)
                    `, [
                        empresaId,
                        material.title,
                        material.description,
                        material.category,
                        material.material_type,
                        material.display_order,
                        usuarioId,
                        usuarioId,
                    ]);
                }
            }

            await connection.commit();
        } catch (err) {
            await connection.rollback();
            throw err;
        } finally {
            connection.release();
        }
    }

    await importarMateriaisVendasLegados(empresaId, usuarioId);
};

const obterTipoMaterialVendasLegado = (item = {}) => {
    if (item.file_type === "image") return "imagem";
    if (item.file_type === "presentation") return "pptx";
    if (item.file_type === "document") return "docx";
    if (item.file_type === "pdf") return "pdf";

    return obterTipoMaterialPelaExtensao(item.name || item.url || "");
};

const LEGACY_SECTION_SEED_TITLE = {
    "tutoriais-vendas": "Passo a passo da venda",
    "ficha-instalacao": "Ficha de instalação",
    "assinatura-meu-provedor": "Assinatura Meu Provedor",
    "processos-vendas": "Apresentação de processos de vendas",
    "script-pos-vendas": "Script de pós-venda",
};

const importarMateriaisVendasLegados = async (empresaId, usuarioId = null) => {
    const caminhoLegado = obterCaminhoConteudoVendas(empresaId);
    const empresaDiretorio = normalizarSegmentoUpload(empresaId);

    if (!fs.existsSync(caminhoLegado)) return;

    const [jaImportados] = await db.query(`
        SELECT id
        FROM sales_materials
        WHERE empresa_id = ?
          AND file_url LIKE ?
        LIMIT 1
    `, [empresaId, `/uploads/vendas/${empresaDiretorio}/%`]);

    if (jaImportados.length) return;

    const conteudoLegado = lerConteudoMateriaisVendas(empresaId);
    const materiaisLegados = [];

    conteudoLegado.sections.forEach((section) => {
        (section.items || []).forEach((item) => {
            if (!item.url) return;

            materiaisLegados.push({
                section,
                item,
            });
        });
    });

    if (!materiaisLegados.length) return;

    const connection = await db.getConnection();
    const seedsAtualizados = new Set();

    try {
        await connection.beginTransaction();

        for (const [index, { section, item }] of materiaisLegados.entries()) {
            const materialType = obterTipoMaterialVendasLegado(item);
            const isImagem = materialType === "imagem";
            const title = limitarTexto(item.title || item.name || section.title, 255);
            const description = normalizarTextoLongo(item.description || section.description || "", 4000);
            const category = limitarTexto(section.title || item.file_label || "Material", 100);
            const seedTitle = LEGACY_SECTION_SEED_TITLE[section.id];
            const coverImageUrl = isImagem ? item.url : null;

            if (seedTitle && !seedsAtualizados.has(seedTitle)) {
                const [result] = await connection.query(`
                    UPDATE sales_materials
                    SET
                        cover_image_url = COALESCE(NULLIF(cover_image_url, ''), ?),
                        file_url = COALESCE(NULLIF(file_url, ''), ?),
                        file_name = COALESCE(NULLIF(file_name, ''), ?),
                        file_mime = COALESCE(NULLIF(file_mime, ''), ?),
                        file_size = COALESCE(file_size, ?),
                        material_type = ?,
                        updated_by = ?
                    WHERE empresa_id = ?
                      AND title = ?
                    LIMIT 1
                `, [
                    coverImageUrl,
                    item.url,
                    item.name || title,
                    item.mime || DEFAULT_FILE_MIME,
                    Number(item.size || 0),
                    materialType,
                    usuarioId,
                    empresaId,
                    seedTitle,
                ]);

                if (result.affectedRows > 0) {
                    seedsAtualizados.add(seedTitle);
                    continue;
                }
            }

            await connection.query(`
                INSERT INTO sales_materials (
                    empresa_id,
                    title,
                    description,
                    category,
                    material_type,
                    cover_image_url,
                    file_url,
                    file_name,
                    file_mime,
                    file_size,
                    display_order,
                    is_active,
                    created_by,
                    updated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            `, [
                empresaId,
                title,
                description,
                category,
                materialType,
                coverImageUrl,
                item.url,
                item.name || title,
                item.mime || DEFAULT_FILE_MIME,
                Number(item.size || 0),
                1000 + (index * 10),
                usuarioId,
                usuarioId,
            ]);
        }

        await connection.commit();
    } catch (err) {
        await connection.rollback();
        throw err;
    } finally {
        connection.release();
    }
};

const formatarMaterialVendas = (material = {}) => ({
    id: material.id,
    title: material.title,
    description: material.description || "",
    category: material.category || "",
    material_type: material.material_type || "outro",
    cover_image_url: material.cover_image_url || "",
    file_url: material.file_url || "",
    file_name: material.file_name || "",
    file_mime: material.file_mime || "",
    file_size: Number(material.file_size || 0),
    external_url: material.external_url || "",
    display_order: Number(material.display_order || 0),
    is_active: Boolean(material.is_active),
    created_by: material.created_by || null,
    created_by_name: material.created_by_name || null,
    updated_by: material.updated_by || null,
    updated_by_name: material.updated_by_name || null,
    created_at: material.created_at,
    updated_at: material.updated_at,
});

const listarMateriaisVendas = async (empresaId, incluirInativos = false, usuarioId = null) => {
    await garantirMateriaisVendasPadrao(empresaId, usuarioId);

    const filtroAtivo = incluirInativos ? "" : "AND m.is_active = 1";
    const [rows] = await db.query(`
        SELECT
            m.id,
            m.title,
            m.description,
            m.category,
            m.material_type,
            m.cover_image_url,
            m.file_url,
            m.file_name,
            m.file_mime,
            m.file_size,
            m.external_url,
            m.display_order,
            m.is_active,
            m.created_by,
            criado.nome AS created_by_name,
            m.updated_by,
            atualizado.nome AS updated_by_name,
            m.created_at,
            m.updated_at
        FROM sales_materials m
        LEFT JOIN usuarios criado ON criado.id = m.created_by
        LEFT JOIN usuarios atualizado ON atualizado.id = m.updated_by
        WHERE m.empresa_id = ?
          ${filtroAtivo}
        ORDER BY m.display_order ASC, m.title ASC, m.id ASC
    `, [empresaId]);

    return rows.map(formatarMaterialVendas);
};

const buscarMaterialVendas = async (materialId, empresaId, incluirInativo = false) => {
    await garantirTabelaMateriaisVendas();

    const filtroAtivo = incluirInativo ? "" : "AND m.is_active = 1";
    const [rows] = await db.query(`
        SELECT
            m.id,
            m.title,
            m.description,
            m.category,
            m.material_type,
            m.cover_image_url,
            m.file_url,
            m.file_name,
            m.file_mime,
            m.file_size,
            m.external_url,
            m.display_order,
            m.is_active,
            m.created_by,
            criado.nome AS created_by_name,
            m.updated_by,
            atualizado.nome AS updated_by_name,
            m.created_at,
            m.updated_at
        FROM sales_materials m
        LEFT JOIN usuarios criado ON criado.id = m.created_by
        LEFT JOIN usuarios atualizado ON atualizado.id = m.updated_by
        WHERE m.id = ?
          AND m.empresa_id = ?
          ${filtroAtivo}
        LIMIT 1
    `, [materialId, empresaId]);

    return rows[0] ? formatarMaterialVendas(rows[0]) : null;
};

const removerArquivoUploadVendasPorUrl = (url = "") => {
    const texto = String(url || "");
    const prefixo = "/uploads/vendas/";

    if (!texto.startsWith(prefixo)) return;

    const relativo = texto.slice(prefixo.length);
    const caminho = path.resolve(SALES_UPLOAD_ROOT, relativo);
    const raiz = path.resolve(SALES_UPLOAD_ROOT);

    if (!caminho.startsWith(`${raiz}${path.sep}`)) return;

    fs.rmSync(caminho, { force: true });
};

const montarPayloadMaterialVendas = (req, materialAtual = {}) => {
    const coverFile = obterArquivoUploadVendas(req, "cover_image");
    const materialFile = obterArquivoUploadVendas(req, "material_file");
    const hasExternalUrl = Object.prototype.hasOwnProperty.call(req.body, "external_url");
    const title = limitarTexto(req.body.title, 255);
    const description = normalizarTextoLongo(req.body.description, 4000);
    const category = limitarTexto(req.body.category, 100);
    const displayOrder = normalizarOrdemTextoAtendimento(req.body.display_order, 0);
    const isActive = normalizarBooleano(req.body.is_active, true);
    const fileUrl = materialFile
        ? obterUrlUploadVendas("material_file", req.user.empresa_id, materialFile.filename)
        : materialAtual.file_url || null;
    const materialType = normalizarTipoMaterialCadastro(
        req.body.material_type,
        materialFile?.originalname || materialAtual.file_name || ""
    );

    return {
        title,
        description,
        category,
        material_type: materialType,
        cover_image_url: coverFile
            ? obterUrlUploadVendas("cover_image", req.user.empresa_id, coverFile.filename)
            : materialAtual.cover_image_url || null,
        file_url: fileUrl,
        file_name: materialFile ? materialFile.originalname : materialAtual.file_name || null,
        file_mime: materialFile ? materialFile.mimetype : materialAtual.file_mime || null,
        file_size: materialFile ? materialFile.size : materialAtual.file_size || null,
        external_url: hasExternalUrl
            ? limitarTexto(req.body.external_url, 500)
            : materialAtual.external_url || null,
        display_order: displayOrder,
        is_active: isActive,
        coverFile,
        materialFile,
    };
};

const usuarioPodeGerenciarSolicitacoesInternas = (usuario = {}) => (
    [PERFIL_ADMIN, PERFIL_ADMIN_COMERCIAL].includes(usuario?.perfil)
);

const normalizarOpcaoSolicitacaoInterna = (valor, opcoes, fallback) => {
    const texto = limitarTexto(valor, 140);
    const encontrada = opcoes.find((opcao) => (
        opcao.toLowerCase() === texto.toLowerCase()
    ));

    return encontrada || fallback;
};

const normalizarPrioridadeSolicitacaoInterna = (valor) => {
    const texto = String(valor || "").trim().toLowerCase();
    return SOLICITACOES_INTERNAS_PRIORIDADES.includes(texto) ? texto : "media";
};

const normalizarStatusSolicitacaoInterna = (valor, fallback = "aberto") => {
    const texto = String(valor || "").trim().toLowerCase();
    return SOLICITACOES_INTERNAS_STATUS.includes(texto) ? texto : fallback;
};

const obterUsuarioResponsavelSolicitacaoInterna = async (valor, empresaId) => {
    const texto = String(valor ?? "").trim();

    if (!texto || texto === "null" || texto === "undefined") return null;

    const usuarioId = Number(texto);

    if (!Number.isInteger(usuarioId) || usuarioId <= 0) {
        const err = new Error("Responsável inválido.");
        err.statusCode = 400;
        throw err;
    }

    const [rows] = await db.query(`
        SELECT id
        FROM usuarios
        WHERE id = ?
          AND empresa_id = ?
          AND deletado_em IS NULL
        LIMIT 1
    `, [usuarioId, empresaId]);

    if (!rows.length) {
        const err = new Error("Responsável não encontrado.");
        err.statusCode = 400;
        throw err;
    }

    return usuarioId;
};

const formatarSolicitacaoInterna = (solicitacao = {}) => ({
    id: solicitacao.id,
    setor: solicitacao.setor,
    tipo: solicitacao.tipo,
    prioridade: solicitacao.prioridade,
    titulo: solicitacao.titulo,
    descricao: solicitacao.descricao || "",
    status: solicitacao.status,
    resposta: solicitacao.resposta || "",
    solicitante: {
        id: solicitacao.usuario_id,
        nome: solicitacao.usuario_nome || null,
        email: solicitacao.usuario_email || null,
        setor: solicitacao.usuario_setor_nome || null,
    },
    responsavel: solicitacao.respondido_por ? {
        id: solicitacao.respondido_por,
        nome: solicitacao.respondido_por_nome || null,
    } : null,
    responsavel_criacao: solicitacao.responsavel_criacao_id ? {
        id: solicitacao.responsavel_criacao_id,
        nome: solicitacao.responsavel_criacao_nome || null,
    } : null,
    responsavel_execucao: solicitacao.responsavel_execucao_id ? {
        id: solicitacao.responsavel_execucao_id,
        nome: solicitacao.responsavel_execucao_nome || null,
    } : null,
    concluido_por: solicitacao.concluido_por ? {
        id: solicitacao.concluido_por,
        nome: solicitacao.concluido_por_nome || null,
    } : null,
    anexo: solicitacao.anexo_url ? {
        url: solicitacao.anexo_url,
        nome: solicitacao.anexo_nome || "Anexo",
        mime: solicitacao.anexo_mime || DEFAULT_FILE_MIME,
        tamanho: Number(solicitacao.anexo_tamanho || 0),
    } : null,
    criado_em: solicitacao.criado_em,
    atualizado_em: solicitacao.atualizado_em,
    respondido_em: solicitacao.respondido_em,
    concluido_em: solicitacao.concluido_em,
});

const removerArquivoSolicitacaoInterna = (file) => {
    if (!file?.path) return;

    try {
        fs.rmSync(file.path, { force: true });
    } catch (err) {
        console.error("Erro ao remover anexo temporário da solicitação:", err);
    }
};

const formatarTextoAtendimento = (texto) => ({
    id: texto.id,
    title: texto.title,
    content: texto.content || "",
    is_active: Boolean(texto.is_active),
    sort_order: Number(texto.sort_order || 0),
    created_by: texto.created_by || null,
    created_by_name: texto.created_by_name || null,
    updated_by: texto.updated_by || null,
    updated_by_name: texto.updated_by_name || null,
    created_at: texto.created_at,
    updated_at: texto.updated_at,
});

const criarPlaceholders = (total) => Array.from({ length: total }, () => "?").join(", ");

const sanitizarHtmlAvisosInternos = (valor = "") => (
    String(valor || "")
        .slice(0, MAX_AVISOS_HTML_LENGTH)
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "")
        .replace(/<iframe[\s\S]*?>[\s\S]*?<\/iframe>/gi, "")
        .replace(/<object[\s\S]*?>[\s\S]*?<\/object>/gi, "")
        .replace(/<embed[\s\S]*?>[\s\S]*?<\/embed>/gi, "")
        .replace(/\son\w+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)/gi, "")
        .replace(/javascript\s*:/gi, "")
);

const limitarTextoAvisosInternos = (valor, fallback = "", limite = 500) => (
    String(valor ?? fallback).slice(0, limite)
);

const limitarNumeroAvisosInternos = (valor, fallback = 0, minimo = 0, maximo = 100) => {
    const numero = Number(valor);

    if (!Number.isFinite(numero)) {
        return fallback;
    }

    return Math.min(Math.max(numero, minimo), maximo);
};

const normalizarListaAvisosInternos = (valor, fallback, mapper, limite = 20) => {
    const origem = Array.isArray(valor) ? valor : fallback;
    return origem.slice(0, limite).map(mapper);
};

const normalizarConteudoAvisosInternos = (conteudo = {}) => ({
    kicker: limitarTextoAvisosInternos(conteudo.kicker, AVISOS_INTERNOS_PADRAO.kicker, 80),
    titulo: limitarTextoAvisosInternos(conteudo.titulo, AVISOS_INTERNOS_PADRAO.titulo, 140),
    subtitulo: limitarTextoAvisosInternos(conteudo.subtitulo, AVISOS_INTERNOS_PADRAO.subtitulo, 320),
    resumo: normalizarListaAvisosInternos(
        conteudo.resumo,
        AVISOS_INTERNOS_PADRAO.resumo,
        (item, index) => ({
            id: limitarTextoAvisosInternos(item?.id, `resumo-${index}`, 80),
            icone: limitarTextoAvisosInternos(item?.icone, "📌", 12),
            valor: limitarTextoAvisosInternos(item?.valor, "", 80),
            rotulo: limitarTextoAvisosInternos(item?.rotulo, "", 120),
        }),
        8
    ),
    secao_comunicados: {
        titulo: limitarTextoAvisosInternos(
            conteudo.secao_comunicados?.titulo,
            AVISOS_INTERNOS_PADRAO.secao_comunicados.titulo,
            120
        ),
        subtitulo: limitarTextoAvisosInternos(
            conteudo.secao_comunicados?.subtitulo,
            AVISOS_INTERNOS_PADRAO.secao_comunicados.subtitulo,
            220
        ),
    },
    comunicados: normalizarListaAvisosInternos(
        conteudo.comunicados,
        AVISOS_INTERNOS_PADRAO.comunicados,
        (item, index) => ({
            id: limitarTextoAvisosInternos(item?.id, `comunicado-${index}`, 80),
            tipo: limitarTextoAvisosInternos(item?.tipo, "Aviso", 80),
            titulo: limitarTextoAvisosInternos(item?.titulo, "", 160),
            descricao: limitarTextoAvisosInternos(item?.descricao, "", 500),
            status: limitarTextoAvisosInternos(item?.status, "", 80),
            data: limitarTextoAvisosInternos(item?.data, "", 80),
            icone: limitarTextoAvisosInternos(item?.icone, "📢", 12),
        }),
        30
    ),
    meta: {
        selo: limitarTextoAvisosInternos(conteudo.meta?.selo, AVISOS_INTERNOS_PADRAO.meta.selo, 80),
        titulo: limitarTextoAvisosInternos(conteudo.meta?.titulo, AVISOS_INTERNOS_PADRAO.meta.titulo, 140),
        texto: limitarTextoAvisosInternos(conteudo.meta?.texto, AVISOS_INTERNOS_PADRAO.meta.texto, 500),
        progresso_label: limitarTextoAvisosInternos(
            conteudo.meta?.progresso_label,
            AVISOS_INTERNOS_PADRAO.meta.progresso_label,
            100
        ),
        progresso: limitarNumeroAvisosInternos(conteudo.meta?.progresso, AVISOS_INTERNOS_PADRAO.meta.progresso),
        vendas_reset_base: limitarNumeroAvisosInternos(
            conteudo.meta?.vendas_reset_base,
            AVISOS_INTERNOS_PADRAO.meta.vendas_reset_base,
            0,
            Number.MAX_SAFE_INTEGER
        ),
    },
    wiki: {
        titulo: limitarTextoAvisosInternos(conteudo.wiki?.titulo, AVISOS_INTERNOS_PADRAO.wiki.titulo, 120),
        subtitulo: limitarTextoAvisosInternos(conteudo.wiki?.subtitulo, AVISOS_INTERNOS_PADRAO.wiki.subtitulo, 220),
        itens: normalizarListaAvisosInternos(
            conteudo.wiki?.itens,
            AVISOS_INTERNOS_PADRAO.wiki.itens,
            (item, index) => ({
                id: limitarTextoAvisosInternos(item?.id, `tutorial-${index}`, 80),
                icone: limitarTextoAvisosInternos(item?.icone, "📚", 12),
                titulo: limitarTextoAvisosInternos(item?.titulo, "", 160),
                descricao: limitarTextoAvisosInternos(item?.descricao, "", 400),
                categoria: limitarTextoAvisosInternos(item?.categoria, "", 80),
            }),
            20
        ),
    },
});

const parseConteudoAvisosInternos = (valor) => {
    if (!valor) {
        return normalizarConteudoAvisosInternos(AVISOS_INTERNOS_PADRAO);
    }

    try {
        return normalizarConteudoAvisosInternos(JSON.parse(valor));
    } catch {
        return normalizarConteudoAvisosInternos(AVISOS_INTERNOS_PADRAO);
    }
};

const buscarConteudoAvisosInternos = async (empresaId) => {
    await garantirAvisosInternosTabela();

    const [rows] = await db.query(`
        SELECT
            a.conteudo_json,
            a.atualizado_em,
            a.atualizado_por,
            u.nome AS atualizado_por_nome
        FROM avisos_internos_config a
        LEFT JOIN usuarios u ON u.id = a.atualizado_por
        WHERE a.empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    const row = rows[0];

    return {
        conteudo: parseConteudoAvisosInternos(row?.conteudo_json),
        atualizado_em: row?.atualizado_em || null,
        atualizado_por: row?.atualizado_por || null,
        atualizado_por_nome: row?.atualizado_por_nome || "",
    };
};

const normalizarPessoaPlantaoDomingo = (valor) => {
    const nome = typeof valor === "string" ? valor : valor?.nome;
    return limitarTexto(nome, 140);
};

const obterPessoasLinhaPlantaoDomingo = (linha = {}) => {
    const pessoas = Array.isArray(linha.pessoas) ? linha.pessoas : [];

    return [
        ...pessoas,
        linha.responsavel,
        linha.apoio,
    ]
        .map(normalizarPessoaPlantaoDomingo)
        .filter(Boolean);
};

const normalizarIdSetorPlantaoDomingo = (valor = "") => (
    limitarTexto(valor, 80)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
);

const obterPessoasSetorPlantaoDomingo = (setor = {}) => {
    const pessoas = Array.isArray(setor?.pessoas) ? setor.pessoas : [];

    return pessoas
        .map(normalizarPessoaPlantaoDomingo)
        .filter(Boolean);
};

const normalizarSetoresPlantaoDomingo = (linha = {}, linhasOrigem = []) => {
    const setoresOrigem = Array.isArray(linha.setores) ? linha.setores : [];
    const setores = PLANTAO_DOMINGO_SETORES.map((setorPadrao) => {
        const idsAceitos = [setorPadrao.id, ...(setorPadrao.aliases || [])];
        const origem = setoresOrigem.find((setor) => (
            idsAceitos.includes(normalizarIdSetorPlantaoDomingo(setor?.id || setor?.nome))
        ));

        return {
            id: setorPadrao.id,
            nome: setorPadrao.nome,
            pessoas: [...new Set(obterPessoasSetorPlantaoDomingo(origem))].slice(0, 80),
        };
    });
    const pessoasLegadas = [
        ...obterPessoasLinhaPlantaoDomingo(linha),
        ...linhasOrigem.flatMap(obterPessoasLinhaPlantaoDomingo),
    ];

    if (pessoasLegadas.length) {
        const setorNoc = setores.find((setor) => setor.id === "noc");

        if (setorNoc) {
            setorNoc.pessoas = [...new Set([...setorNoc.pessoas, ...pessoasLegadas])].slice(0, 80);
        }
    }

    return setores;
};

const normalizarLinhaPlantaoDomingo = (linha = {}, linhasOrigem = []) => {
    const observacoesOrigem = linha.observacoes
        || linhasOrigem.map((item) => item?.observacoes).filter(Boolean).join("\n");

    return {
        id: "domingo-inteiro",
        periodo: "Domingo",
        horario: "Dia inteiro",
        setores: normalizarSetoresPlantaoDomingo(linha, linhasOrigem),
        observacoes: normalizarTextoLongo(observacoesOrigem, 800),
    };
};

const normalizarConteudoPlantaoDomingo = (conteudo = {}) => {
    const linhasOrigem = Array.isArray(conteudo.linhas) && conteudo.linhas.length
        ? conteudo.linhas
        : PLANTAO_DOMINGO_PADRAO.linhas;
    const linhaBase = linhasOrigem[0] || PLANTAO_DOMINGO_PADRAO.linhas[0];

    return {
        titulo: limitarTexto(conteudo.titulo, 140) || PLANTAO_DOMINGO_PADRAO.titulo,
        subtitulo: limitarTexto(conteudo.subtitulo, 220) || PLANTAO_DOMINGO_PADRAO.subtitulo,
        linhas: [normalizarLinhaPlantaoDomingo(linhaBase, linhasOrigem)],
    };
};

const parseConteudoPlantaoDomingo = (valor) => {
    if (!valor) {
        return normalizarConteudoPlantaoDomingo(PLANTAO_DOMINGO_PADRAO);
    }

    try {
        return normalizarConteudoPlantaoDomingo(JSON.parse(valor));
    } catch {
        return normalizarConteudoPlantaoDomingo(PLANTAO_DOMINGO_PADRAO);
    }
};

const buscarConteudoPlantaoDomingo = async (empresaId) => {
    await garantirPlantaoDomingoTabela();

    const [rows] = await db.query(`
        SELECT
            p.conteudo_json,
            p.atualizado_em,
            p.atualizado_por,
            u.nome AS atualizado_por_nome
        FROM plantao_domingo_config p
        LEFT JOIN usuarios u ON u.id = p.atualizado_por
        WHERE p.empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    const row = rows[0];

    return {
        conteudo: parseConteudoPlantaoDomingo(row?.conteudo_json),
        atualizado_em: row?.atualizado_em || null,
        atualizado_por: row?.atualizado_por || null,
        atualizado_por_nome: row?.atualizado_por_nome || null,
    };
};

const normalizarIdWikiInterna = (valor = "", fallback = "curso") => {
    const id = limitarTexto(valor, 100)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "");

    return id || fallback;
};

const normalizarProgressoWikiInterna = (valor = 0) => {
    const numero = Number(valor);

    if (!Number.isFinite(numero)) return 0;

    return Math.min(100, Math.max(0, Math.round(numero)));
};

const normalizarCursoWikiInterna = (curso = {}, index = 0, categoriaId = "geral") => {
    const titulo = limitarTexto(curso.titulo, 160);
    const descricao = normalizarTextoLongo(curso.descricao, 600);
    const fallbackId = normalizarIdWikiInterna(titulo, `curso-${categoriaId}-${index + 1}`);
    const cabecalho = limitarTexto(curso.cabecalho, 180) || titulo;
    const conteudo = normalizarTextoLongo(curso.conteudo, 6000) || descricao;

    return {
        id: normalizarIdWikiInterna(curso.id, fallbackId),
        titulo,
        descricao,
        atualizado: limitarTexto(curso.atualizado || "Hoje", 80) || "Hoje",
        destaque: Boolean(curso.destaque),
        cabecalho,
        conteudo,
        nivel: limitarTexto(curso.nivel || "Iniciante", 40) || "Iniciante",
        duracao: limitarTexto(curso.duracao || "1h", 40) || "1h",
        progresso: normalizarProgressoWikiInterna(curso.progresso),
        novo: Boolean(curso.novo),
        maisAcessado: Boolean(curso.maisAcessado ?? curso.mais_acessado),
    };
};

const normalizarCursosWikiInterna = (valor, fallback, categoriaId) => {
    const origem = Array.isArray(valor) ? valor : fallback;

    return origem
        .slice(0, 80)
        .map((curso, index) => normalizarCursoWikiInterna(curso, index, categoriaId))
        .filter((curso) => curso.titulo && curso.descricao);
};

const normalizarConteudoWikiInterna = (conteudo = {}) => {
    const categoriasRecebidas = Array.isArray(conteudo.categorias) ? conteudo.categorias : [];

    return {
        categorias: WIKI_INTERNA_PADRAO.categorias.map((categoriaPadrao) => {
            const categoriaRecebida = categoriasRecebidas.find((categoria) => (
                normalizarIdWikiInterna(categoria?.id, "") === categoriaPadrao.id
            ));
            const cursosRecebidos = categoriaRecebida?.cursos ?? categoriaRecebida?.artigos;

            return {
                ...categoriaPadrao,
                cursos: normalizarCursosWikiInterna(
                    cursosRecebidos,
                    categoriaPadrao.cursos,
                    categoriaPadrao.id
                ),
            };
        }),
    };
};

const parseConteudoWikiInterna = (valor) => {
    if (!valor) {
        return normalizarConteudoWikiInterna(WIKI_INTERNA_PADRAO);
    }

    try {
        return normalizarConteudoWikiInterna(JSON.parse(valor));
    } catch {
        return normalizarConteudoWikiInterna(WIKI_INTERNA_PADRAO);
    }
};

const buscarConteudoWikiInterna = async (empresaId) => {
    await garantirWikiInternaTabela();

    const [rows] = await db.query(`
        SELECT
            w.conteudo_json,
            w.atualizado_em,
            w.atualizado_por,
            u.nome AS atualizado_por_nome
        FROM wiki_interna_config w
        LEFT JOIN usuarios u ON u.id = w.atualizado_por
        WHERE w.empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    const row = rows[0];

    return {
        conteudo: parseConteudoWikiInterna(row?.conteudo_json),
        atualizado_em: row?.atualizado_em || null,
        atualizado_por: row?.atualizado_por || null,
        atualizado_por_nome: row?.atualizado_por_nome || null,
    };
};

const WIKI_TIPOS_AULA = new Set([
    "video",
    "text",
    "video-text",
    "pdf",
    "doc",
    "exercise",
    "material",
]);
const WIKI_ICONES_MODULO = new Set([
    "overview",
    "diagnostic",
    "support",
    "speech",
    "materials",
    "evaluation",
]);

const limitarTextoWikiCurso = (valor, tamanho, fallback = "") => {
    const texto = String(valor ?? "").trim().slice(0, tamanho);
    return texto || fallback;
};

const normalizarSlugWikiCurso = (valor, fallback = "aula") => (
    String(valor || fallback)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 180)
        || fallback
);

const normalizarConfigWikiCurso = (valor = {}) => {
    const modulos = Array.isArray(valor.modulos ?? valor.modules)
        ? (valor.modulos ?? valor.modules).slice(0, 30)
        : [];

    return {
        modules: modulos.map((modulo, moduloIndex) => {
            const moduleId = normalizarSlugWikiCurso(
                modulo?.id,
                `modulo-${moduloIndex + 1}`
            );
            const lessons = Array.isArray(modulo?.lessons)
                ? modulo.lessons.slice(0, 100)
                : [];

            return {
                id: moduleId,
                title: limitarTextoWikiCurso(
                    modulo?.title,
                    180,
                    `Módulo ${moduloIndex + 1}`
                ),
                description: limitarTextoWikiCurso(modulo?.description, 700),
                icon: WIKI_ICONES_MODULO.has(modulo?.icon) ? modulo.icon : "overview",
                lessons: lessons.map((lesson, lessonIndex) => ({
                    contentKey: normalizarSlugWikiCurso(
                        lesson?.contentKey,
                        normalizarSlugWikiCurso(lesson?.slug, `aula-${lessonIndex + 1}`)
                    ),
                    slug: normalizarSlugWikiCurso(
                        lesson?.slug,
                        `aula-${lessonIndex + 1}`
                    ),
                    previousSlugs: Array.isArray(lesson?.previousSlugs)
                        ? lesson.previousSlugs
                            .map((slug) => normalizarSlugWikiCurso(slug, ""))
                            .filter(Boolean)
                            .slice(0, 20)
                        : [],
                    number: limitarTextoWikiCurso(
                        lesson?.number,
                        20,
                        `${moduloIndex + 1}.${lessonIndex + 1}`
                    ),
                    title: limitarTextoWikiCurso(
                        lesson?.title,
                        220,
                        `Aula ${moduloIndex + 1}.${lessonIndex + 1}`
                    ),
                    type: WIKI_TIPOS_AULA.has(lesson?.type) ? lesson.type : "text",
                    duration: limitarTextoWikiCurso(lesson?.duration, 40, "Conteúdo"),
                })),
            };
        }),
    };
};

const buscarConfigWikiCurso = async (empresaId, cursoId) => {
    await garantirWikiCursosConfigTabela();

    const [rows] = await db.query(`
        SELECT
            w.conteudo_json,
            w.atualizado_em,
            w.atualizado_por,
            u.nome AS atualizado_por_nome
        FROM wiki_cursos_config w
        LEFT JOIN usuarios u ON u.id = w.atualizado_por
        WHERE w.empresa_id = ? AND w.curso_id = ?
        LIMIT 1
    `, [empresaId, cursoId]);

    const row = rows[0];
    let config = { modules: [] };

    if (row?.conteudo_json) {
        try {
            config = normalizarConfigWikiCurso(JSON.parse(row.conteudo_json));
        } catch {
            config = { modules: [] };
        }
    }

    return {
        config,
        atualizado_em: row?.atualizado_em || null,
        atualizado_por: row?.atualizado_por || null,
        atualizado_por_nome: row?.atualizado_por_nome || null,
    };
};

const normalizarListaTextoWikiAula = (valor, limiteItens = 30, limiteTexto = 1000) => (
    Array.isArray(valor)
        ? valor
            .map((item) => limitarTextoWikiCurso(item, limiteTexto))
            .filter(Boolean)
            .slice(0, limiteItens)
        : []
);

const normalizarMidiasWikiAula = (valor, limiteItens = 40) => (
    Array.isArray(valor)
        ? valor
            .slice(0, limiteItens)
            .map((item) => {
                const tipo = item?.type === "video" ? "video" : "image";
                const url = limitarTextoWikiCurso(item?.url, 1000);

                if (!/^\/uploads\/wiki\/[^\s?#]+$/i.test(url)) {
                    return null;
                }

                return {
                    id: limitarTextoWikiCurso(
                        item?.id,
                        180,
                        `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
                    ),
                    type: tipo,
                    url,
                    name: limitarTextoWikiCurso(item?.name, 255, "Mídia da aula"),
                    caption: limitarTextoWikiCurso(item?.caption, 1000),
                    mime: limitarTextoWikiCurso(item?.mime, 120),
                    size: Math.max(0, Number(item?.size) || 0),
                };
            })
            .filter(Boolean)
        : []
);

const normalizarDocumentoWikiAula = (valor) => {
    if (!valor || typeof valor !== "object") return null;

    const type = ["pdf", "powerpoint", "excel"].includes(valor.type)
        ? valor.type
        : null;
    const url = limitarTextoWikiCurso(valor.url, 1000);
    const previewUrl = limitarTextoWikiCurso(valor.previewUrl, 1000);

    if (
        !type ||
        !/^\/uploads\/wiki\/[^\s?#]+$/i.test(url) ||
        !/^\/uploads\/wiki\/[^\s?#]+$/i.test(previewUrl)
    ) {
        return null;
    }

    return {
        id: limitarTextoWikiCurso(
            valor.id,
            180,
            `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`
        ),
        type,
        url,
        previewUrl,
        name: limitarTextoWikiCurso(valor.name, 255, "Documento da aula"),
        mime: limitarTextoWikiCurso(valor.mime, 180),
        size: Math.max(0, Number(valor.size) || 0),
    };
};

const normalizarConteudoWikiAula = (valor = {}) => {
    const sections = Array.isArray(valor.sections) ? valor.sections.slice(0, 30) : [];
    const steps = Array.isArray(valor.steps) ? valor.steps.slice(0, 30) : [];
    const document = normalizarDocumentoWikiAula(valor.document);
    const comparisonHeaders = normalizarListaTextoWikiAula(
        valor.comparison?.headers,
        12,
        180
    );
    const comparisonRows = Array.isArray(valor.comparison?.rows)
        ? valor.comparison.rows
            .slice(0, 50)
            .map((row) => normalizarListaTextoWikiAula(row, 12, 700))
            .filter((row) => row.length > 0)
        : [];

    return {
        displayMode: valor.displayMode === "document" && document
            ? "document"
            : "content",
        document,
        summary: limitarTextoWikiCurso(valor.summary, 5000),
        objectives: normalizarListaTextoWikiAula(valor.objectives, 40, 1000),
        sections: sections.map((section) => ({
            eyebrow: limitarTextoWikiCurso(section?.eyebrow, 80),
            title: limitarTextoWikiCurso(section?.title, 240),
            paragraphs: normalizarListaTextoWikiAula(section?.paragraphs, 20, 5000),
            bullets: normalizarListaTextoWikiAula(section?.bullets, 40, 1500),
            tone: ["", "info", "warning"].includes(section?.tone)
                ? section.tone
                : "",
            media: normalizarMidiasWikiAula(section?.media, 20),
            mediaPosition: section?.mediaPosition === "before" ? "before" : "after",
        })).filter((section) => (
            section.title ||
            section.paragraphs.length ||
            section.bullets.length ||
            section.media.length
        )),
        comparison: comparisonHeaders.length || comparisonRows.length
            ? {
                headers: comparisonHeaders,
                rows: comparisonRows,
            }
            : null,
        steps: steps.map((step) => ({
            title: limitarTextoWikiCurso(step?.title, 240),
            description: limitarTextoWikiCurso(step?.description, 3000),
        })).filter((step) => step.title || step.description),
        example: valor.example && (
            valor.example.title ||
            valor.example.scenario ||
            valor.example.response
        )
            ? {
                title: limitarTextoWikiCurso(valor.example.title, 240),
                scenario: limitarTextoWikiCurso(valor.example.scenario, 5000),
                response: limitarTextoWikiCurso(valor.example.response, 5000),
            }
            : null,
        checklist: normalizarListaTextoWikiAula(valor.checklist, 50, 1200),
        takeaways: normalizarListaTextoWikiAula(valor.takeaways, 50, 1200),
        knowledgeCheck: valor.knowledgeCheck && (
            valor.knowledgeCheck.question ||
            valor.knowledgeCheck.answer
        )
            ? {
                question: limitarTextoWikiCurso(valor.knowledgeCheck.question, 1200),
                answer: limitarTextoWikiCurso(valor.knowledgeCheck.answer, 5000),
            }
            : null,
        media: normalizarMidiasWikiAula(valor.media),
    };
};

const buscarConteudoWikiAula = async (empresaId, cursoId, aulaChave) => {
    await garantirWikiAulasConfigTabela();

    const [rows] = await db.query(`
        SELECT
            w.conteudo_json,
            w.atualizado_em,
            w.atualizado_por,
            u.nome AS atualizado_por_nome
        FROM wiki_aulas_config w
        LEFT JOIN usuarios u ON u.id = w.atualizado_por
        WHERE w.empresa_id = ? AND w.curso_id = ? AND w.aula_chave = ?
        LIMIT 1
    `, [empresaId, cursoId, aulaChave]);

    const row = rows[0];
    let content = null;

    if (row?.conteudo_json) {
        try {
            content = normalizarConteudoWikiAula(JSON.parse(row.conteudo_json));
        } catch {
            content = null;
        }
    }

    return {
        content,
        atualizado_em: row?.atualizado_em || null,
        atualizado_por: row?.atualizado_por || null,
        atualizado_por_nome: row?.atualizado_por_nome || null,
    };
};

const formatarProgressoWikiAula = (row = {}) => ({
    aula_chave: row.aula_chave,
    concluida: Boolean(row.concluida),
    acessada_em: row.acessada_em || null,
    concluida_em: row.concluida_em || null,
    atualizado_em: row.atualizado_em || null,
});

const buscarProgressoWikiCurso = async (empresaId, usuarioId, cursoId) => {
    await garantirWikiAulasProgressoTabela();

    const [rows] = await db.query(`
        SELECT
            aula_chave,
            concluida,
            acessada_em,
            concluida_em,
            atualizado_em
        FROM wiki_aulas_progresso
        WHERE empresa_id = ? AND usuario_id = ? AND curso_id = ?
        ORDER BY COALESCE(acessada_em, atualizado_em) DESC, id DESC
    `, [empresaId, usuarioId, cursoId]);

    const aulas = rows.map(formatarProgressoWikiAula);
    const ultimaAula = aulas.find((aula) => aula.acessada_em) || aulas[0] || null;

    return {
        curso_id: cursoId,
        usuario_id: usuarioId,
        aulas,
        ultima_aula_chave: ultimaAula?.aula_chave || null,
        aulas_concluidas: aulas.filter((aula) => aula.concluida).length,
    };
};

const buscarProgressoWikiUsuario = async (empresaId, usuarioId) => {
    await garantirWikiAulasProgressoTabela();

    const [rows] = await db.query(`
        SELECT
            curso_id,
            aula_chave,
            concluida,
            acessada_em,
            concluida_em,
            atualizado_em
        FROM wiki_aulas_progresso
        WHERE empresa_id = ? AND usuario_id = ?
        ORDER BY curso_id ASC, COALESCE(acessada_em, atualizado_em) DESC, id DESC
    `, [empresaId, usuarioId]);
    const cursosMap = new Map();

    rows.forEach((row) => {
        const curso = cursosMap.get(row.curso_id) || {
            curso_id: row.curso_id,
            aulas: [],
            ultima_aula_chave: null,
            aulas_concluidas: 0,
        };
        const aula = formatarProgressoWikiAula(row);

        curso.aulas.push(aula);

        if (!curso.ultima_aula_chave && aula.acessada_em) {
            curso.ultima_aula_chave = aula.aula_chave;
        }

        if (aula.concluida) {
            curso.aulas_concluidas += 1;
        }

        cursosMap.set(row.curso_id, curso);
    });

    return {
        usuario_id: usuarioId,
        cursos: [...cursosMap.values()],
    };
};

const CAMPOS_BANNER_HOME = {
    modo: 20,
    selo: 80,
    titulo_linha_1: 100,
    titulo_linha_2: 80,
    titulo_destaque: 100,
    descricao_linha_1: 220,
    descricao_linha_2: 220,
    time_label: 60,
    time_valor: 30,
    time_detalhe: 80,
    meta_label: 60,
    meta_valor: 30,
    meta_detalhe: 80,
    rodada_label: 60,
    rodada_valor: 30,
    rodada_detalhe: 80,
    oferta_titulo: 80,
    oferta_subtitulo: 80,
    beneficio_1_titulo: 60,
    beneficio_1_detalhe: 60,
    beneficio_2_titulo: 60,
    beneficio_2_detalhe: 60,
    beneficio_3_titulo: 60,
    beneficio_3_detalhe: 60,
    botao_texto: 100,
    botao_url: 500,
    imagem_url: 500,
    imagem_alt: 120,
};

const MODOS_BANNER_HOME = ["codigo", "imagem"];
const BANNER_HOME_IMAGE_URL_REGEX = /^\/uploads\/banner-home\/[^\s?#]+$/i;

const normalizarUrlBannerHome = (valor) => {
    const url = String(valor || "").trim().slice(0, CAMPOS_BANNER_HOME.botao_url);

    if (!url) return "";

    try {
        const protocolo = new URL(url).protocol;
        return protocolo === "http:" || protocolo === "https:"
            ? url
            : BANNER_HOME_PADRAO.botao_url;
    } catch {
        return BANNER_HOME_PADRAO.botao_url;
    }
};

const normalizarImagemUrlBannerHome = (valor) => {
    const url = String(valor || "").trim().slice(0, CAMPOS_BANNER_HOME.imagem_url);

    if (!url) return "";

    if (BANNER_HOME_IMAGE_URL_REGEX.test(url)) {
        return url;
    }

    try {
        const protocolo = new URL(url).protocol;
        return protocolo === "http:" || protocolo === "https:" ? url : "";
    } catch {
        return "";
    }
};

const normalizarConteudoBannerHome = (conteudo = {}) => {
    const conteudoSeguro = conteudo && typeof conteudo === "object" ? conteudo : {};
    const temModoSalvo = Object.prototype.hasOwnProperty.call(conteudoSeguro, "modo");
    const origem = temModoSalvo ? conteudoSeguro : BANNER_HOME_PADRAO;
    const normalizado = Object.fromEntries(
        Object.entries(CAMPOS_BANNER_HOME).map(([campo, limite]) => {
            const valorRecebido = origem[campo];
            const valor = valorRecebido === undefined || valorRecebido === null
                ? BANNER_HOME_PADRAO[campo]
                : valorRecebido;

            return [campo, String(valor).trim().slice(0, limite)];
        })
    );

    normalizado.modo = MODOS_BANNER_HOME.includes(normalizado.modo)
        ? normalizado.modo
        : BANNER_HOME_PADRAO.modo;
    normalizado.botao_url = normalizarUrlBannerHome(normalizado.botao_url);
    normalizado.imagem_url = normalizarImagemUrlBannerHome(normalizado.imagem_url);
    return normalizado;
};

const parseConteudoBannerHome = (valor) => {
    if (!valor) {
        return normalizarConteudoBannerHome(BANNER_HOME_PADRAO);
    }

    try {
        return normalizarConteudoBannerHome(JSON.parse(valor));
    } catch {
        return normalizarConteudoBannerHome(BANNER_HOME_PADRAO);
    }
};

const buscarConteudoBannerHome = async (empresaId) => {
    await garantirBannerHomeTabela();

    const [rows] = await db.query(`
        SELECT
            b.conteudo_json,
            b.atualizado_em,
            b.atualizado_por,
            u.nome AS atualizado_por_nome
        FROM banner_home_config b
        LEFT JOIN usuarios u ON u.id = b.atualizado_por
        WHERE b.empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    const row = rows[0];

    return {
        conteudo: parseConteudoBannerHome(row?.conteudo_json),
        atualizado_em: row?.atualizado_em || null,
        atualizado_por: row?.atualizado_por || null,
        atualizado_por_nome: row?.atualizado_por_nome || null,
    };
};

const normalizarCategoria = (valor = "") => (
    valor
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
);

const montarCategoriasFixas = (setores = []) => {
    const categorias = new Map();

    const adicionar = (nome, setorId = null, fixaPadrao = false) => {
        const nomeNormalizado = (nome || "").trim();
        const chave = normalizarCategoria(nomeNormalizado);

        if (!chave) return;

        if (categorias.has(chave)) {
            const categoriaExistente = categorias.get(chave);

            if (!categoriaExistente.setor_id && setorId) {
                categorias.set(chave, {
                    ...categoriaExistente,
                    setor_id: setorId,
                    fixa_padrao: categoriaExistente.fixa_padrao || fixaPadrao,
                });
            }

            if (fixaPadrao && !categoriaExistente.fixa_padrao) {
                categorias.set(chave, {
                    ...categoriaExistente,
                    fixa_padrao: true,
                });
            }

            return;
        }

        categorias.set(chave, {
            chave,
            nome: nomeNormalizado,
            setor_id: setorId,
            fixa_padrao: fixaPadrao,
        });
    };

    CATEGORIAS_FIXAS_PADRAO.forEach((nome) => adicionar(nome, null, true));
    setores.forEach((setor) => adicionar(setor.nome, setor.id, false));

    return Array.from(categorias.values());
};

const obterCategoriasFixas = async (empresaId) => {
    const [setores] = await db.query(`
        SELECT id, nome
        FROM setores
        WHERE empresa_id = ?
        ORDER BY nome ASC
    `, [empresaId]);

    return montarCategoriasFixas(setores);
};

const buscarOuCriarSetorPorNome = async (connection, { nome, empresaId }) => {
    const nomeNormalizado = String(nome || "").trim().replace(/\s+/g, " ");
    const chaveSetor = normalizarCategoria(nomeNormalizado);

    if (!chaveSetor) {
        return null;
    }

    const [setores] = await connection.query(`
        SELECT id, nome
        FROM setores
        WHERE empresa_id = ?
    `, [empresaId]);

    const setorExistente = setores.find((setor) => (
        normalizarCategoria(setor.nome) === chaveSetor
    ));

    if (setorExistente) {
        return setorExistente;
    }

    const [result] = await connection.query(`
        INSERT INTO setores (nome, empresa_id)
        VALUES (?, ?)
    `, [nomeNormalizado, empresaId]);

    return {
        id: result.insertId,
        nome: nomeNormalizado,
    };
};

const sincronizarMembrosGrupoFixo = async (connection, grupo, empresaId) => {
    const grupoId = Number(grupo?.id);

    const [rows] = await connection.query(`
        SELECT COUNT(*) AS total_membros
        FROM grupo_membros gm
        JOIN usuarios u ON gm.usuario_id = u.id
        WHERE gm.grupo_id = ?
          AND u.empresa_id = ?
          AND u.deletado_em IS NULL
    `, [grupoId, empresaId]);

    return {
        total_membros: rows[0]?.total_membros || 0,
    };
};

const notificarRemocaoAcessoGrupo = async (req, { grupoId, usuarioIds = [] }) => {
    const io = req.app?.get?.("io");

    if (!io || !grupoId || !usuarioIds.length) return;

    await Promise.all(usuarioIds.map(async (usuarioId) => {
        const sockets = await io.in(`user_${usuarioId}`).fetchSockets();

        sockets.forEach((socket) => {
            socket.leave(`grupo_${grupoId}`);
            socket.emit("group_access_removed", { grupo_id: grupoId });
        });
    }));
};

const notificarMudancaAcessoGrupos = async (
    req,
    { usuarioId, gruposAdicionados = [], gruposRemovidos = [] }
) => {
    const io = req.app?.get?.("io");

    if (!io || !usuarioId || (!gruposAdicionados.length && !gruposRemovidos.length)) {
        return;
    }

    const sockets = await io.in(`user_${usuarioId}`).fetchSockets();

    sockets.forEach((socket) => {
        gruposRemovidos.forEach((grupoId) => socket.leave(`grupo_${grupoId}`));
        gruposAdicionados.forEach((grupoId) => socket.join(`grupo_${grupoId}`));

        socket.emit("group_access_changed", {
            grupos_adicionados: gruposAdicionados,
            grupos_removidos: gruposRemovidos,
        });
    });
};

const sincronizarGruposFixosDoUsuario = async (connection, usuarioId, empresaId) => {
    return {
        grupos_adicionados: [],
        grupos_removidos: [],
    };
};

const garantirGruposFixos = async (empresaId, criadorId = null) => {
    const connection = await db.getConnection();
    const lockName = `grupos_fixos_${empresaId}`;

    try {
        await garantirMetadadosGrupos(connection);

        const [lockRows] = await connection.query(
            "SELECT GET_LOCK(?, 5) AS lock_obtido",
            [lockName]
        );

        if (lockRows[0]?.lock_obtido !== 1) {
            return;
        }

        await connection.query(`
            UPDATE grupos
            SET fixo = 0,
                setor_id = NULL
            WHERE empresa_id = ?
              AND (fixo <> 0 OR setor_id IS NOT NULL)
        `, [empresaId]);

        const [setores] = await connection.query(`
            SELECT id, nome
            FROM setores
            WHERE empresa_id = ?
            ORDER BY nome ASC
        `, [empresaId]);

        const categorias = montarCategoriasFixas(setores);

        if (!categorias.length) return;

        const [gruposExistentes] = await connection.query(`
            SELECT id, nome, fixo, setor_id, deletado_em
            FROM grupos
            WHERE empresa_id = ?
        `, [empresaId]);

        const gruposPorChave = new Map(
            gruposExistentes.map((grupo) => [normalizarCategoria(grupo.nome), grupo])
        );

        const novosGrupos = categorias.filter((categoria) => !gruposPorChave.has(categoria.chave));

        for (const categoria of novosGrupos) {
            await connection.query(`
                INSERT INTO grupos (nome, descricao, criador_id, empresa_id, fixo, setor_id)
                VALUES (?, ?, ?, ?, 0, NULL)
            `, [
                categoria.nome,
                `Grupo da categoria ${categoria.nome}`,
                criadorId,
                empresaId,
            ]);
        }
    } finally {
        try {
            await connection.query("SELECT RELEASE_LOCK(?)", [lockName]);
        } catch (err) {
            console.error("Erro ao liberar lock de grupos fixos:", err);
        }
        connection.release();
    }
};

const buscarGrupoDaEmpresa = async (grupoId, empresaId) => {
    await garantirMetadadosGrupos();

    const [rows] = await db.query(`
	            SELECT 
	                g.id,
	                g.nome,
	                g.descricao,
            g.empresa_id,
            g.fixo,
            g.setor_id,
            g.mensagem_fixada_titulo,
            g.mensagem_fixada_conteudo,
            g.mensagem_fixada_ativo,
            g.mensagem_fixada_atualizada_em,
            g.mensagem_fixada_atualizada_por,
            s.nome AS setor_nome
        FROM grupos g
        LEFT JOIN setores s ON g.setor_id = s.id
        WHERE g.id = ? AND g.empresa_id = ? AND g.deletado_em IS NULL
        LIMIT 1
    `, [grupoId, empresaId]);

    return rows[0] || null;
};

const buscarGruposPorUsuarios = async (empresaId, usuarioIds = []) => {
    const ids = [...new Set(
        usuarioIds
            .map((id) => Number(id))
            .filter((id) => Number.isFinite(id) && id > 0)
    )];

    if (!ids.length) return new Map();

    const placeholders = ids.map(() => "?").join(", ");
    const [rows] = await db.query(`
        SELECT
            gm.usuario_id,
            g.id,
            g.nome,
            g.descricao,
            g.avatar,
            g.fixo,
            g.setor_id,
            s.nome AS setor_nome
        FROM grupo_membros gm
        JOIN grupos g ON g.id = gm.grupo_id
        LEFT JOIN setores s ON s.id = g.setor_id
        WHERE gm.usuario_id IN (${placeholders})
          AND g.empresa_id = ?
          AND g.deletado_em IS NULL
        ORDER BY g.nome ASC
    `, [...ids, empresaId]);

    const gruposPorUsuario = new Map(ids.map((id) => [id, []]));

    rows.forEach((row) => {
        const usuarioId = Number(row.usuario_id);
        const lista = gruposPorUsuario.get(usuarioId) || [];

        lista.push({
            id: row.id,
            nome: row.nome,
            descricao: row.descricao,
            avatar: row.avatar,
            fixo: Boolean(row.fixo),
            setor_id: row.setor_id,
            setor_nome: row.setor_nome,
        });

        gruposPorUsuario.set(usuarioId, lista);
    });

    return gruposPorUsuario;
};

const anexarGruposAUsuarios = async (usuarios = [], empresaId) => {
    const gruposPorUsuario = await buscarGruposPorUsuarios(
        empresaId,
        usuarios.map((usuario) => usuario.id)
    );

    return usuarios.map((usuario) => ({
        ...usuario,
        grupos: gruposPorUsuario.get(Number(usuario.id)) || [],
    }));
};

const garantirTabelaMensagensOcultas = async () => {
    await db.query(`
        CREATE TABLE IF NOT EXISTS mensagens_ocultas_usuario (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mensagem_id INT NOT NULL,
            usuario_id INT NOT NULL,
            ocultada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (mensagem_id) REFERENCES mensagens(id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_mensagem_usuario (mensagem_id, usuario_id),
            INDEX idx_usuario (usuario_id),
            INDEX idx_mensagem (mensagem_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
};

const garantirTabelaConversasOcultas = async () => {
    await db.query(`
        CREATE TABLE IF NOT EXISTS conversas_ocultas_usuario (
            id INT AUTO_INCREMENT PRIMARY KEY,
            conversa_direta_id INT NOT NULL,
            usuario_id INT NOT NULL,
            ocultada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (conversa_direta_id) REFERENCES conversas_diretas(id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_conversa_usuario (conversa_direta_id, usuario_id),
            INDEX idx_conversa_oculta_usuario (usuario_id),
            INDEX idx_conversa_oculta_conversa (conversa_direta_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
};

const garantirTabelaChatFavoritos = async () => {
    if (chatFavoritosTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS chat_favoritos (
            id INT AUTO_INCREMENT PRIMARY KEY,
            usuario_id INT NOT NULL,
            tipo ENUM('direta', 'grupo') NOT NULL,
            referencia_id INT NOT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_chat_favorito (usuario_id, tipo, referencia_id),
            INDEX idx_chat_favoritos_usuario (usuario_id),
            INDEX idx_chat_favoritos_tipo_ref (tipo, referencia_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    chatFavoritosTabelaGarantida = true;
};

const garantirTabelaMessageFavorites = async () => {
    if (messageFavoritesTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS message_favorites (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            message_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (message_id) REFERENCES mensagens(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_message_favorite (user_id, message_id),
            INDEX idx_message_favorites_user_created (user_id, created_at),
            INDEX idx_message_favorites_message (message_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    messageFavoritesTabelaGarantida = true;
};

const MESSAGE_REACTIONS_PERMITIDAS = ["👍", "✅", "👀"];

const garantirTabelaMessageReactions = async () => {
    if (messageReactionsTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS message_reactions (
            id INT AUTO_INCREMENT PRIMARY KEY,
            message_id INT NOT NULL,
            user_id INT NOT NULL,
            reaction VARCHAR(16) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES mensagens(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_message_reaction (message_id, user_id, reaction),
            INDEX idx_message_reactions_message (message_id),
            INDEX idx_message_reactions_user (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    messageReactionsTabelaGarantida = true;
};

const formatarReacoesMensagens = (rows = [], userId) => {
    const porMensagem = new Map();

    rows.forEach((row) => {
        const messageId = Number(row.message_id);
        const reaction = row.reaction;

        if (!porMensagem.has(messageId)) {
            porMensagem.set(messageId, new Map());
        }

        const reacoesMensagem = porMensagem.get(messageId);

        if (!reacoesMensagem.has(reaction)) {
            reacoesMensagem.set(reaction, {
                reaction,
                total: 0,
                reacted_by_me: false,
                users: [],
            });
        }

        const grupo = reacoesMensagem.get(reaction);
        grupo.total += 1;

        if (Number(row.user_id) === Number(userId)) {
            grupo.reacted_by_me = true;
        }

        grupo.users.push({
            id: row.user_id,
            nome: row.nome || "Usuário",
        });
    });

    return new Map(
        Array.from(porMensagem.entries()).map(([messageId, reactionsMap]) => [
            messageId,
            Array.from(reactionsMap.values()),
        ])
    );
};

const buscarReacoesPorMensagens = async (messageIds = [], userId) => {
    const ids = Array.from(new Set(messageIds.map(Number).filter(Boolean)));

    if (!ids.length) return new Map();

    await garantirTabelaMessageReactions();

    const placeholders = criarPlaceholders(ids.length);
    const [rows] = await db.query(`
        SELECT
            mr.message_id,
            mr.user_id,
            mr.reaction,
            u.nome
        FROM message_reactions mr
        JOIN usuarios u ON u.id = mr.user_id
        WHERE mr.message_id IN (${placeholders})
        ORDER BY mr.created_at ASC, mr.id ASC
    `, ids);

    return formatarReacoesMensagens(rows, userId);
};

const anexarReacoesMensagens = async (mensagens = [], userId) => {
    if (!mensagens.length) return mensagens;

    const reacoesPorMensagem = await buscarReacoesPorMensagens(
        mensagens.map((mensagem) => mensagem.id),
        userId
    );

    return mensagens.map((mensagem) => ({
        ...mensagem,
        reacoes: reacoesPorMensagem.get(Number(mensagem.id)) || [],
    }));
};

const garantirTabelaPinnedMessages = async () => {
    if (pinnedMessagesTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS pinned_messages (
            id INT AUTO_INCREMENT PRIMARY KEY,
            tipo ENUM('direta', 'grupo') NOT NULL,
            referencia_id INT NOT NULL,
            message_id INT NOT NULL,
            pinned_by INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES mensagens(id) ON DELETE CASCADE,
            FOREIGN KEY (pinned_by) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_pinned_chat (tipo, referencia_id),
            INDEX idx_pinned_messages_message (message_id),
            INDEX idx_pinned_messages_ref (tipo, referencia_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    pinnedMessagesTabelaGarantida = true;
};

const formatarMensagemFixada = (row = null) => {
    if (!row) return null;

    return {
        id: row.id,
        tipo: row.tipo,
        referencia_id: row.referencia_id,
        message_id: row.message_id,
        pinned_by: row.pinned_by,
        pinned_by_name: row.pinned_by_name,
        pinned_at: row.created_at,
        remetente_id: row.remetente_id,
        remetente_nome: row.remetente_nome,
        tipo_mensagem: row.tipo_mensagem,
        mensagem: row.mensagem,
        anexo_nome: row.anexo_nome,
        anexo_mime: row.anexo_mime,
        sticker_id: row.sticker_id || null,
        previa: row.previa || "Mensagem",
    };
};

const buscarMensagemFixada = async ({ tipo, referenciaId, userId }) => {
    const referencia = Number(referenciaId);

    if (!["direta", "grupo"].includes(tipo) || !referencia) return null;

    await garantirTabelaPinnedMessages();
    await garantirTabelaMensagensOcultas();

    const [rows] = await db.query(`
        SELECT
            pm.id,
            pm.tipo,
            pm.referencia_id,
            pm.message_id,
            pm.pinned_by,
            pm.created_at,
            autor.nome AS remetente_nome,
            fixador.nome AS pinned_by_name,
            m.remetente_id,
            m.tipo_mensagem,
            m.mensagem,
            m.anexo_nome,
            m.anexo_mime,
            m.sticker_id,
            CASE
                WHEN m.tipo_mensagem = 'imagem' THEN '[Imagem]'
                WHEN m.tipo_mensagem = 'audio' THEN '[Áudio]'
                WHEN m.tipo_mensagem = 'arquivo' THEN COALESCE(m.anexo_nome, '[Arquivo]')
                WHEN m.tipo_mensagem = 'sticker' THEN 'Figurinha'
                ELSE LEFT(m.mensagem, 180)
            END AS previa
        FROM pinned_messages pm
        JOIN mensagens m ON m.id = pm.message_id
        JOIN usuarios autor ON autor.id = m.remetente_id
        JOIN usuarios fixador ON fixador.id = pm.pinned_by
        WHERE pm.tipo = ?
          AND pm.referencia_id = ?
          AND m.deletada_em IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM mensagens_ocultas_usuario mou
              WHERE mou.mensagem_id = m.id
                AND mou.usuario_id = ?
          )
        LIMIT 1
    `, [tipo, referencia, userId]);

    return formatarMensagemFixada(rows[0]);
};

const emitirAtualizacaoMensagemFixada = (req, mensagem, pinnedMessage) => {
    const io = req.app.get("io");

    if (!io) return;

    const tipo = mensagem.tipo_origem;
    const referenciaId = tipo === "grupo" ? mensagem.grupo_id : mensagem.conversa_id;
    const sala = tipo === "grupo" ? `grupo_${referenciaId}` : `conversa_${referenciaId}`;

    io.to(sala).emit("pinned_message_updated", {
        tipo,
        referencia_id: referenciaId,
        pinned_message: pinnedMessage || null,
    });
};

const buscarMensagemVisivelParaUsuario = async (messageId, usuario) => {
    const userId = Number(usuario?.id);
    const empresaId = Number(usuario?.empresa_id);

    if (!Number.isInteger(messageId) || messageId <= 0 || !userId || !empresaId) {
        return null;
    }

    await garantirTabelaMensagensOcultas();
    await garantirTipoMensagemAudio();

    const [rows] = await db.query(`
        SELECT *
        FROM (
            SELECT
                m.id,
                m.mensagem,
                m.tipo_mensagem,
                m.anexo_nome,
                m.anexo_mime,
                m.sticker_id,
                m.criada_em,
                m.remetente_id,
                autor.nome AS remetente_nome,
                'direta' AS tipo_origem,
                cd.id AS conversa_id,
                NULL AS grupo_id,
                outro.id AS destinatario_id,
                outro.nome AS origem_nome
            FROM mensagens m
            JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id
            JOIN usuarios autor ON autor.id = m.remetente_id
            JOIN usuarios u1 ON u1.id = cd.usuario1_id
            JOIN usuarios u2 ON u2.id = cd.usuario2_id
            JOIN usuarios outro ON (
                (cd.usuario1_id = ? AND outro.id = cd.usuario2_id)
                OR (cd.usuario2_id = ? AND outro.id = cd.usuario1_id)
            )
            WHERE m.id = ?
              AND m.deletada_em IS NULL
              AND (cd.usuario1_id = ? OR cd.usuario2_id = ?)
              AND u1.empresa_id = ?
              AND u2.empresa_id = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM mensagens_ocultas_usuario mou
                  WHERE mou.mensagem_id = m.id
                    AND mou.usuario_id = ?
              )
            UNION ALL
            SELECT
                m.id,
                m.mensagem,
                m.tipo_mensagem,
                m.anexo_nome,
                m.anexo_mime,
                m.sticker_id,
                m.criada_em,
                m.remetente_id,
                autor.nome AS remetente_nome,
                'grupo' AS tipo_origem,
                NULL AS conversa_id,
                g.id AS grupo_id,
                NULL AS destinatario_id,
                g.nome AS origem_nome
            FROM mensagens m
            JOIN grupos g ON g.id = m.grupo_id
            JOIN grupo_membros gm ON gm.grupo_id = g.id AND gm.usuario_id = ?
            JOIN usuarios autor ON autor.id = m.remetente_id
            WHERE m.id = ?
              AND m.deletada_em IS NULL
              AND g.empresa_id = ?
              AND g.deletado_em IS NULL
              AND NOT EXISTS (
                  SELECT 1
                  FROM mensagens_ocultas_usuario mou
                  WHERE mou.mensagem_id = m.id
                    AND mou.usuario_id = ?
              )
        ) mensagem_visivel
        LIMIT 1
    `, [
        userId,
        userId,
        messageId,
        userId,
        userId,
        empresaId,
        empresaId,
        userId,
        userId,
        messageId,
        empresaId,
        userId,
    ]);

    return rows[0] || null;
};

const formatarSticker = (row = {}) => ({
    id: Number(row.id),
    sticker_id: Number(row.id),
    user_id: row.user_id ? Number(row.user_id) : null,
    empresa_id: row.empresa_id ? Number(row.empresa_id) : null,
    created_by_user_id: row.created_by_user_id ? Number(row.created_by_user_id) : null,
    file_url: row.file_url,
    url: row.file_url,
    width: Number(row.width || CHAT_STICKER_SIZE),
    height: Number(row.height || CHAT_STICKER_SIZE),
    mime: row.mime || "image/webp",
    size: row.file_size ? Number(row.file_size) : null,
    animated: Boolean(row.is_animated),
    is_animated: Boolean(row.is_animated),
    frame_count: Number(row.frame_count || 1),
    duration_ms: row.duration_ms ? Number(row.duration_ms) : null,
    source_sticker_id: row.source_sticker_id ? Number(row.source_sticker_id) : null,
    created_at: row.created_at,
    favorited: Boolean(row.favorited),
    in_library: Boolean(row.in_library),
    last_used_at: row.last_used_at || null,
});

const garantirTabelasChatStickers = async () => {
    if (chatStickersTabelasGarantidas) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS stickers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            created_by_user_id INT NOT NULL,
            file_url VARCHAR(600) NOT NULL,
            storage_path VARCHAR(800) NOT NULL,
            mime VARCHAR(80) NOT NULL DEFAULT 'image/webp',
            width INT NOT NULL DEFAULT 512,
            height INT NOT NULL DEFAULT 512,
            file_size INT DEFAULT NULL,
            is_animated TINYINT(1) NOT NULL DEFAULT 0,
            frame_count INT NOT NULL DEFAULT 1,
            duration_ms INT DEFAULT NULL,
            source_sticker_id INT DEFAULT NULL,
            deleted_at TIMESTAMP NULL DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by_user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (source_sticker_id) REFERENCES stickers(id) ON DELETE SET NULL,
            UNIQUE KEY unique_sticker_file_url (file_url),
            INDEX idx_stickers_empresa_created (empresa_id, created_at),
            INDEX idx_stickers_created_by (created_by_user_id),
            INDEX idx_stickers_source (source_sticker_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS user_stickers (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            sticker_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            deleted_at TIMESTAMP NULL DEFAULT NULL,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_sticker (user_id, sticker_id),
            INDEX idx_user_stickers_user_created (user_id, deleted_at, created_at),
            INDEX idx_user_stickers_sticker (sticker_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS sticker_favorites (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            sticker_id INT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_sticker_favorite (user_id, sticker_id),
            INDEX idx_sticker_favorites_user_created (user_id, created_at),
            INDEX idx_sticker_favorites_sticker (sticker_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS sticker_recents (
            user_id INT NOT NULL,
            sticker_id INT NOT NULL,
            last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            use_count INT NOT NULL DEFAULT 1,
            PRIMARY KEY (user_id, sticker_id),
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE CASCADE,
            INDEX idx_sticker_recents_user_used (user_id, last_used_at),
            INDEX idx_sticker_recents_sticker (sticker_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE mensagens
        ADD COLUMN IF NOT EXISTS sticker_id INT DEFAULT NULL
    `);

    await db.query(`
        ALTER TABLE stickers
        ADD COLUMN IF NOT EXISTS is_animated TINYINT(1) NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS frame_count INT NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS duration_ms INT DEFAULT NULL
    `);

    await db.query("CREATE INDEX IF NOT EXISTS idx_mensagens_sticker ON mensagens(sticker_id)");

    chatStickersTabelasGarantidas = true;
};

const buscarStickerPorId = async (stickerId, empresaId = null) => {
    const id = Number(stickerId);
    if (!Number.isInteger(id) || id <= 0) return null;

    await garantirTabelasChatStickers();

    const params = [id];
    const filtroEmpresa = empresaId ? "AND empresa_id = ?" : "";

    if (empresaId) {
        params.push(empresaId);
    }

    const [rows] = await db.query(`
        SELECT *
        FROM stickers
        WHERE id = ?
          AND deleted_at IS NULL
          ${filtroEmpresa}
        LIMIT 1
    `, params);

    return rows[0] || null;
};

const mensagemPermiteAcessarSticker = async ({ messageId, stickerId, usuario }) => {
    const mensagemId = Number(messageId);
    const stickerIdNumerico = Number(stickerId);

    if (!Number.isInteger(mensagemId) || mensagemId <= 0 || !stickerIdNumerico) {
        return false;
    }

    const mensagem = await buscarMensagemVisivelParaUsuario(mensagemId, usuario);

    if (!mensagem || mensagem.tipo_mensagem !== "sticker") return false;

    if (Number(mensagem.sticker_id) === stickerIdNumerico) {
        return true;
    }

    const sticker = await buscarStickerPorId(stickerIdNumerico, usuario.empresa_id);
    return Boolean(sticker && mensagem.mensagem === sticker.file_url);
};

const usuarioPodeUsarSticker = async ({ stickerId, usuario, messageId = null }) => {
    const sticker = await buscarStickerPorId(stickerId, usuario?.empresa_id);
    const userId = Number(usuario?.id);

    if (!sticker || !userId) return null;

    if (Number(sticker.created_by_user_id) === userId) {
        return sticker;
    }

    const [vinculos] = await db.query(`
        SELECT 1
        FROM user_stickers
        WHERE user_id = ?
          AND sticker_id = ?
          AND deleted_at IS NULL
        LIMIT 1
    `, [userId, sticker.id]);

    if (vinculos.length) return sticker;

    const [favoritos] = await db.query(`
        SELECT 1
        FROM sticker_favorites
        WHERE user_id = ?
          AND sticker_id = ?
        LIMIT 1
    `, [userId, sticker.id]);

    if (favoritos.length) return sticker;

    const [recentes] = await db.query(`
        SELECT 1
        FROM sticker_recents
        WHERE user_id = ?
          AND sticker_id = ?
        LIMIT 1
    `, [userId, sticker.id]);

    if (recentes.length) return sticker;

    if (messageId && await mensagemPermiteAcessarSticker({ messageId, stickerId: sticker.id, usuario })) {
        return sticker;
    }

    return null;
};

const contarStickersBibliotecaUsuario = async (userId) => {
    await garantirTabelasChatStickers();

    const [rows] = await db.query(`
        SELECT COUNT(*) AS total
        FROM user_stickers us
        JOIN stickers s ON s.id = us.sticker_id
        WHERE us.user_id = ?
          AND us.deleted_at IS NULL
          AND s.deleted_at IS NULL
    `, [userId]);

    return Number(rows[0]?.total || 0);
};

const adicionarStickerNaBibliotecaUsuario = async ({ stickerId, usuario, messageId = null }) => {
    const sticker = await usuarioPodeUsarSticker({ stickerId, usuario, messageId });

    if (!sticker) return null;

    const userId = Number(usuario.id);
    const total = await contarStickersBibliotecaUsuario(userId);

    const [existente] = await db.query(`
        SELECT id, deleted_at
        FROM user_stickers
        WHERE user_id = ?
          AND sticker_id = ?
        LIMIT 1
    `, [userId, sticker.id]);

    if (!existente.length && total >= CHAT_STICKER_MAX_PER_USER) {
        const erro = new Error(`Limite de ${CHAT_STICKER_MAX_PER_USER} figurinhas atingido.`);
        erro.status = 409;
        throw erro;
    }

    await db.query(`
        INSERT INTO user_stickers (user_id, sticker_id)
        VALUES (?, ?)
        ON DUPLICATE KEY UPDATE deleted_at = NULL
    `, [userId, sticker.id]);

    return sticker;
};

const registrarStickerRecente = async (userId, stickerId) => {
    if (!userId || !stickerId) return;

    await garantirTabelasChatStickers();

    await db.query(`
        INSERT INTO sticker_recents (user_id, sticker_id, last_used_at, use_count)
        VALUES (?, ?, NOW(), 1)
        ON DUPLICATE KEY UPDATE
            last_used_at = VALUES(last_used_at),
            use_count = sticker_recents.use_count + 1
    `, [userId, stickerId]);

    const [excedentes] = await db.query(`
        SELECT sticker_id
        FROM sticker_recents
        WHERE user_id = ?
        ORDER BY last_used_at DESC, sticker_id DESC
        LIMIT 1000 OFFSET ?
    `, [userId, CHAT_STICKER_RECENTS_LIMIT]);

    if (excedentes.length) {
        await db.query(`
            DELETE FROM sticker_recents
            WHERE user_id = ?
              AND sticker_id IN (?)
        `, [userId, excedentes.map((row) => row.sticker_id)]);
    }
};

const buscarStickersUsuario = async (usuario) => {
    const userId = Number(usuario.id);

    await garantirTabelasChatStickers();

    const [mine] = await db.query(`
        SELECT
            s.*,
            us.user_id,
            1 AS in_library,
            EXISTS (
                SELECT 1
                FROM sticker_favorites sf
                WHERE sf.user_id = ?
                  AND sf.sticker_id = s.id
            ) AS favorited
        FROM user_stickers us
        JOIN stickers s ON s.id = us.sticker_id
        WHERE us.user_id = ?
          AND us.deleted_at IS NULL
          AND s.deleted_at IS NULL
        ORDER BY us.created_at DESC, s.id DESC
        LIMIT 250
    `, [userId, userId]);

    const [favorites] = await db.query(`
        SELECT
            s.*,
            sf.user_id,
            1 AS favorited,
            EXISTS (
                SELECT 1
                FROM user_stickers us
                WHERE us.user_id = ?
                  AND us.sticker_id = s.id
                  AND us.deleted_at IS NULL
            ) AS in_library
        FROM sticker_favorites sf
        JOIN stickers s ON s.id = sf.sticker_id
        WHERE sf.user_id = ?
          AND s.deleted_at IS NULL
        ORDER BY sf.created_at DESC, s.id DESC
        LIMIT 250
    `, [userId, userId]);

    const [recents] = await db.query(`
        SELECT
            s.*,
            sr.user_id,
            sr.last_used_at,
            EXISTS (
                SELECT 1
                FROM sticker_favorites sf
                WHERE sf.user_id = ?
                  AND sf.sticker_id = s.id
            ) AS favorited,
            EXISTS (
                SELECT 1
                FROM user_stickers us
                WHERE us.user_id = ?
                  AND us.sticker_id = s.id
                  AND us.deleted_at IS NULL
            ) AS in_library
        FROM sticker_recents sr
        JOIN stickers s ON s.id = sr.sticker_id
        WHERE sr.user_id = ?
          AND s.deleted_at IS NULL
        ORDER BY sr.last_used_at DESC, s.id DESC
        LIMIT ?
    `, [userId, userId, userId, CHAT_STICKER_RECENTS_LIMIT]);

    return {
        mine: mine.map(formatarSticker),
        favorites: favorites.map(formatarSticker),
        recents: recents.map(formatarSticker),
        limits: {
            max_per_user: CHAT_STICKER_MAX_PER_USER,
            max_upload_mb: CHAT_STICKER_MAX_UPLOAD_SIZE_MB,
            max_frames: CHAT_STICKER_MAX_FRAMES,
            recents: CHAT_STICKER_RECENTS_LIMIT,
        },
    };
};

const normalizarLoopStickerAnimado = (loop) => {
    const valor = Number(loop);
    return Number.isInteger(valor) && valor >= 0 && valor <= 65535 ? valor : 0;
};

const normalizarDelaysStickerAnimado = (delays, frameCount) => {
    const totalFrames = Number(frameCount || 0);

    if (!Number.isInteger(totalFrames) || totalFrames <= 1) {
        return null;
    }

    const origem = Array.isArray(delays) ? delays : [];
    return Array.from({ length: totalFrames }, (_, index) => {
        const valor = Number(origem[index]);
        return Number.isFinite(valor) && valor > 0 && valor <= 65535 ? Math.round(valor) : 100;
    });
};

const somarDuracaoStickerAnimado = (delays) => {
    if (!Array.isArray(delays) || !delays.length) return null;
    return delays.reduce((total, delay) => total + Number(delay || 0), 0);
};

const prepararStickerParaEnvio = async ({ stickerId, usuario }) => {
    const sticker = await usuarioPodeUsarSticker({ stickerId, usuario });

    if (!sticker) {
        const erro = new Error("Figurinha não encontrada na sua biblioteca.");
        erro.status = 404;
        throw erro;
    }

    return sticker;
};

const criarStickerAPartirDeUpload = async ({ file, usuario }) => {
    if (!file?.buffer?.length) {
        const erro = new Error("Envie uma imagem para criar a figurinha.");
        erro.status = 400;
        throw erro;
    }

    const mimeReal = detectarTipoImagemSticker(file.buffer);
    if (!mimeReal) {
        const erro = new Error("Arquivo inválido. Envie uma imagem PNG, JPG, JPEG, WEBP ou GIF.");
        erro.status = 400;
        throw erro;
    }

    const userId = Number(usuario.id);
    const total = await contarStickersBibliotecaUsuario(userId);

    if (total >= CHAT_STICKER_MAX_PER_USER) {
        const erro = new Error(`Limite de ${CHAT_STICKER_MAX_PER_USER} figurinhas atingido.`);
        erro.status = 409;
        throw erro;
    }

    const empresaDiretorio = normalizarSegmentoUpload(usuario.empresa_id);
    const usuarioDiretorio = normalizarSegmentoUpload(usuario.id);
    const destinoDiretorio = path.join(STICKER_UPLOAD_ROOT, empresaDiretorio, usuarioDiretorio);
    const filename = `${crypto.randomUUID()}.webp`;
    const storagePath = path.join(destinoDiretorio, filename);
    const fileUrl = `/uploads/stickers/${empresaDiretorio}/${usuarioDiretorio}/${filename}`;

    fs.mkdirSync(destinoDiretorio, { recursive: true });

    let processed;
    let isAnimated = false;
    let frameCount = 1;
    let durationMs = null;

    try {
        const metadata = await sharp(file.buffer, {
            animated: true,
            failOn: "warning",
            limitInputPixels: 32_000_000,
        }).metadata();
        const paginasEntrada = Number(metadata.pages || 1);
        isAnimated = paginasEntrada > 1;

        if (isAnimated && paginasEntrada > CHAT_STICKER_MAX_FRAMES) {
            const erro = new Error(`Figurinha animada muito longa. Use até ${CHAT_STICKER_MAX_FRAMES} frames.`);
            erro.status = 413;
            throw erro;
        }

        const delays = normalizarDelaysStickerAnimado(metadata.delay, paginasEntrada);
        const webpOptions = {
            quality: 90,
            alphaQuality: 100,
            effort: isAnimated ? 5 : 4,
        };

        if (isAnimated) {
            webpOptions.loop = normalizarLoopStickerAnimado(metadata.loop);
            webpOptions.delay = delays;
            webpOptions.mixed = true;
        }

        processed = await sharp(file.buffer, {
            animated: isAnimated,
            failOn: "warning",
            limitInputPixels: 32_000_000,
        })
            .rotate()
            .resize({
                width: CHAT_STICKER_SIZE,
                height: CHAT_STICKER_SIZE,
                fit: "contain",
                background: { r: 0, g: 0, b: 0, alpha: 0 },
            })
            .webp(webpOptions)
            .toBuffer({ resolveWithObject: true });

        frameCount = Number(processed.info.pages || paginasEntrada || 1);
        isAnimated = frameCount > 1;
        durationMs = isAnimated ? somarDuracaoStickerAnimado(delays) : null;

        await fs.promises.writeFile(storagePath, processed.data);
    } catch (err) {
        fs.rmSync(storagePath, { force: true });
        if (err.status) {
            throw err;
        }
        const erro = new Error("Não foi possível converter a imagem em figurinha.");
        erro.status = 422;
        erro.cause = err;
        throw erro;
    }

    try {
        const [result] = await db.query(`
            INSERT INTO stickers (
                empresa_id,
                created_by_user_id,
                file_url,
                storage_path,
                mime,
                width,
                height,
                file_size,
                is_animated,
                frame_count,
                duration_ms
            )
            VALUES (?, ?, ?, ?, 'image/webp', ?, ?, ?, ?, ?, ?)
        `, [
            usuario.empresa_id,
            usuario.id,
            fileUrl,
            storagePath,
            processed.info.width || CHAT_STICKER_SIZE,
            processed.info.pageHeight || processed.info.height || CHAT_STICKER_SIZE,
            processed.data.length,
            isAnimated ? 1 : 0,
            frameCount,
            durationMs,
        ]);

        await db.query(`
            INSERT INTO user_stickers (user_id, sticker_id)
            VALUES (?, ?)
        `, [usuario.id, result.insertId]);

        const sticker = await buscarStickerPorId(result.insertId, usuario.empresa_id);
        return formatarSticker({
            ...sticker,
            user_id: usuario.id,
            favorited: 0,
            in_library: 1,
        });
    } catch (err) {
        fs.rmSync(storagePath, { force: true });
        throw err;
    }
};

const garantirTabelaAcessosRapidosUsuario = async () => {
    if (acessosRapidosUsuarioTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS user_quick_access (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            quick_access_id VARCHAR(80) NOT NULL,
            \`position\` INT NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_user_quick_access (user_id, quick_access_id),
            INDEX idx_user_quick_access_user_position (user_id, \`position\`),
            INDEX idx_user_quick_access_id (quick_access_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE user_quick_access
        ADD COLUMN IF NOT EXISTS \`position\` INT NOT NULL DEFAULT 0
    `);

    acessosRapidosUsuarioTabelaGarantida = true;
};

const listarAcessosRapidosUsuario = async (usuario) => {
    await garantirTabelaAcessosRapidosUsuario();

    const available = await listarQuickAccessDisponiveis(usuario);
    const availableMap = new Map(available.map((item) => [item.id, item]));

    const [rows] = await db.query(`
        SELECT quick_access_id, \`position\`
        FROM user_quick_access
        WHERE user_id = ?
        ORDER BY \`position\` ASC, id ASC
    `, [usuario.id]);

    const selected = rows
        .map((row) => {
            const item = availableMap.get(row.quick_access_id);
            if (!item) return null;

            return {
                ...item,
                position: Number(row.position || 0),
            };
        })
        .filter(Boolean);

    return { available, selected };
};

const CHAT_APPEARANCE_FONT_SIZES = ["small", "normal", "large"];
const CHAT_APPEARANCE_DENSITIES = ["compact", "comfortable", "spacious"];
const CHAT_APPEARANCE_WALLPAPER_MODES = ["cover", "contain", "repeat"];
const CHAT_APPEARANCE_WALLPAPER_TYPES = ["none", "preset", "upload", "color", "gradient"];
const CHAT_APPEARANCE_WALLPAPER_PRESETS = ["aurora", "sunset", "forest", "night", "ocean"];
const CHAT_APPEARANCE_HEX_COLOR_REGEX = /^#[0-9a-f]{6}$/i;
const CHAT_APPEARANCE_CONVERSATION_TIPOS = ["direta", "grupo"];

const CHAT_APPEARANCE_DEFAULTS = {
    theme: "default",
    accentColor: null,
    backgroundColor: null,
    panelColor: null,
    ownMessageColor: null,
    receivedMessageColor: null,
    textColor: null,
    secondaryTextColor: null,
    linkColor: null,
    wallpaperType: "none",
    wallpaperUrl: null,
    wallpaperColor: null,
    wallpaperColor2: null,
    wallpaperAngle: 135,
    wallpaperMode: "cover",
    wallpaperIntensity: 100,
    wallpaperBlur: 0,
    messageRadius: 18,
    messageDensity: "comfortable",
    fontSize: "normal",
    bubbleOpacity: 100,
    showTimestamp: true,
    showAvatar: true,
    showDateSeparator: true,
    showWallpaper: true,
    animationsEnabled: true,
};

let chatUserAppearanceTabelaGarantida = false;
let chatConversationAppearanceTabelaGarantida = false;

const garantirTabelaChatUserAppearance = async () => {
    if (chatUserAppearanceTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS chat_user_appearance (
            user_id INT NOT NULL PRIMARY KEY,
            theme VARCHAR(30) NOT NULL DEFAULT 'default',
            accent_color CHAR(7) NULL,
            background_color CHAR(7) NULL,
            panel_color CHAR(7) NULL,
            own_message_color CHAR(7) NULL,
            received_message_color CHAR(7) NULL,
            text_color CHAR(7) NULL,
            secondary_text_color CHAR(7) NULL,
            link_color CHAR(7) NULL,
            wallpaper_type ENUM('none','preset','upload','color','gradient') NOT NULL DEFAULT 'none',
            wallpaper_url VARCHAR(500) NULL,
            wallpaper_color CHAR(7) NULL,
            wallpaper_color2 CHAR(7) NULL,
            wallpaper_angle SMALLINT UNSIGNED NOT NULL DEFAULT 135,
            wallpaper_mode ENUM('cover','contain','repeat') NOT NULL DEFAULT 'cover',
            wallpaper_intensity TINYINT UNSIGNED NOT NULL DEFAULT 100,
            wallpaper_blur TINYINT UNSIGNED NOT NULL DEFAULT 0,
            message_radius TINYINT UNSIGNED NOT NULL DEFAULT 18,
            message_density ENUM('compact','comfortable','spacious') NOT NULL DEFAULT 'comfortable',
            font_size ENUM('small','normal','large') NOT NULL DEFAULT 'normal',
            bubble_opacity TINYINT UNSIGNED NOT NULL DEFAULT 100,
            show_timestamp TINYINT(1) NOT NULL DEFAULT 1,
            show_avatar TINYINT(1) NOT NULL DEFAULT 1,
            show_date_separator TINYINT(1) NOT NULL DEFAULT 1,
            show_wallpaper TINYINT(1) NOT NULL DEFAULT 1,
            animations_enabled TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    chatUserAppearanceTabelaGarantida = true;
};

const garantirTabelaChatConversationAppearance = async () => {
    if (chatConversationAppearanceTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS chat_conversation_appearance (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            tipo ENUM('direta','grupo') NOT NULL,
            referencia_id INT NOT NULL,
            wallpaper_type ENUM('none','preset','upload','color','gradient') NOT NULL DEFAULT 'none',
            wallpaper_url VARCHAR(500) NULL,
            wallpaper_color CHAR(7) NULL,
            wallpaper_color2 CHAR(7) NULL,
            wallpaper_angle SMALLINT UNSIGNED NOT NULL DEFAULT 135,
            wallpaper_mode ENUM('cover','contain','repeat') NOT NULL DEFAULT 'cover',
            background_color CHAR(7) NULL,
            own_message_color CHAR(7) NULL,
            received_message_color CHAR(7) NULL,
            accent_color CHAR(7) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_chat_conversation_appearance (user_id, tipo, referencia_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    chatConversationAppearanceTabelaGarantida = true;
};

const clampInteiro = (valor, min, max, fallback) => {
    const numero = Number(valor);
    if (!Number.isFinite(numero)) return fallback;
    return Math.min(max, Math.max(min, Math.round(numero)));
};

const validarCorHex = (valor) => (
    typeof valor === "string" && CHAT_APPEARANCE_HEX_COLOR_REGEX.test(valor.trim())
        ? valor.trim().toLowerCase()
        : null
);

const validarWallpaperUrlArmazenada = (tipo, valor) => {
    if (typeof valor !== "string" || !valor.trim()) return null;

    const texto = valor.trim();

    if (tipo === "preset") {
        return CHAT_APPEARANCE_WALLPAPER_PRESETS.includes(texto) ? texto : null;
    }

    if (tipo === "upload") {
        return WALLPAPER_UPLOAD_URL_REGEX.test(texto) ? texto : null;
    }

    return null;
};

const formatarChatUserAppearance = (row) => {
    if (!row) return { ...CHAT_APPEARANCE_DEFAULTS };

    return {
        theme: row.theme || CHAT_APPEARANCE_DEFAULTS.theme,
        accentColor: row.accent_color || null,
        backgroundColor: row.background_color || null,
        panelColor: row.panel_color || null,
        ownMessageColor: row.own_message_color || null,
        receivedMessageColor: row.received_message_color || null,
        textColor: row.text_color || null,
        secondaryTextColor: row.secondary_text_color || null,
        linkColor: row.link_color || null,
        wallpaperType: row.wallpaper_type || CHAT_APPEARANCE_DEFAULTS.wallpaperType,
        wallpaperUrl: row.wallpaper_url || null,
        wallpaperColor: row.wallpaper_color || null,
        wallpaperColor2: row.wallpaper_color2 || null,
        wallpaperAngle: Number(row.wallpaper_angle ?? CHAT_APPEARANCE_DEFAULTS.wallpaperAngle),
        wallpaperMode: row.wallpaper_mode || CHAT_APPEARANCE_DEFAULTS.wallpaperMode,
        wallpaperIntensity: Number(row.wallpaper_intensity ?? CHAT_APPEARANCE_DEFAULTS.wallpaperIntensity),
        wallpaperBlur: Number(row.wallpaper_blur ?? CHAT_APPEARANCE_DEFAULTS.wallpaperBlur),
        messageRadius: Number(row.message_radius ?? CHAT_APPEARANCE_DEFAULTS.messageRadius),
        messageDensity: row.message_density || CHAT_APPEARANCE_DEFAULTS.messageDensity,
        fontSize: row.font_size || CHAT_APPEARANCE_DEFAULTS.fontSize,
        bubbleOpacity: Number(row.bubble_opacity ?? CHAT_APPEARANCE_DEFAULTS.bubbleOpacity),
        showTimestamp: Boolean(row.show_timestamp ?? 1),
        showAvatar: Boolean(row.show_avatar ?? 1),
        showDateSeparator: Boolean(row.show_date_separator ?? 1),
        showWallpaper: Boolean(row.show_wallpaper ?? 1),
        animationsEnabled: Boolean(row.animations_enabled ?? 1),
    };
};

const formatarChatConversationAppearance = (row) => {
    if (!row) return null;

    return {
        wallpaperType: row.wallpaper_type || "none",
        wallpaperUrl: row.wallpaper_url || null,
        wallpaperColor: row.wallpaper_color || null,
        wallpaperColor2: row.wallpaper_color2 || null,
        wallpaperAngle: Number(row.wallpaper_angle ?? 135),
        wallpaperMode: row.wallpaper_mode || "cover",
        backgroundColor: row.background_color || null,
        ownMessageColor: row.own_message_color || null,
        receivedMessageColor: row.received_message_color || null,
        accentColor: row.accent_color || null,
    };
};

const obterChatUserAppearance = async (userId) => {
    await garantirTabelaChatUserAppearance();

    const [rows] = await db.query(`
        SELECT *
        FROM chat_user_appearance
        WHERE user_id = ?
        LIMIT 1
    `, [userId]);

    return formatarChatUserAppearance(rows[0]);
};

const validarPayloadChatUserAppearance = (body = {}) => {
    const wallpaperType = CHAT_APPEARANCE_WALLPAPER_TYPES.includes(body.wallpaperType)
        ? body.wallpaperType
        : CHAT_APPEARANCE_DEFAULTS.wallpaperType;

    return {
        theme: typeof body.theme === "string" && body.theme.trim()
            ? body.theme.trim().slice(0, 30)
            : CHAT_APPEARANCE_DEFAULTS.theme,
        accent_color: validarCorHex(body.accentColor),
        background_color: validarCorHex(body.backgroundColor),
        panel_color: validarCorHex(body.panelColor),
        own_message_color: validarCorHex(body.ownMessageColor),
        received_message_color: validarCorHex(body.receivedMessageColor),
        text_color: validarCorHex(body.textColor),
        secondary_text_color: validarCorHex(body.secondaryTextColor),
        link_color: validarCorHex(body.linkColor),
        wallpaper_type: wallpaperType,
        wallpaper_url: validarWallpaperUrlArmazenada(wallpaperType, body.wallpaperUrl),
        wallpaper_color: validarCorHex(body.wallpaperColor),
        wallpaper_color2: validarCorHex(body.wallpaperColor2),
        wallpaper_angle: clampInteiro(body.wallpaperAngle, 0, 360, CHAT_APPEARANCE_DEFAULTS.wallpaperAngle),
        wallpaper_mode: CHAT_APPEARANCE_WALLPAPER_MODES.includes(body.wallpaperMode)
            ? body.wallpaperMode
            : CHAT_APPEARANCE_DEFAULTS.wallpaperMode,
        wallpaper_intensity: clampInteiro(body.wallpaperIntensity, 0, 100, CHAT_APPEARANCE_DEFAULTS.wallpaperIntensity),
        wallpaper_blur: clampInteiro(body.wallpaperBlur, 0, 20, CHAT_APPEARANCE_DEFAULTS.wallpaperBlur),
        message_radius: clampInteiro(body.messageRadius, 0, 28, CHAT_APPEARANCE_DEFAULTS.messageRadius),
        message_density: CHAT_APPEARANCE_DENSITIES.includes(body.messageDensity)
            ? body.messageDensity
            : CHAT_APPEARANCE_DEFAULTS.messageDensity,
        font_size: CHAT_APPEARANCE_FONT_SIZES.includes(body.fontSize)
            ? body.fontSize
            : CHAT_APPEARANCE_DEFAULTS.fontSize,
        bubble_opacity: clampInteiro(body.bubbleOpacity, 40, 100, CHAT_APPEARANCE_DEFAULTS.bubbleOpacity),
        show_timestamp: body.showTimestamp !== false ? 1 : 0,
        show_avatar: body.showAvatar !== false ? 1 : 0,
        show_date_separator: body.showDateSeparator !== false ? 1 : 0,
        show_wallpaper: body.showWallpaper !== false ? 1 : 0,
        animations_enabled: body.animationsEnabled !== false ? 1 : 0,
    };
};

const validarPayloadChatConversationAppearance = (body = {}) => {
    const wallpaperType = CHAT_APPEARANCE_WALLPAPER_TYPES.includes(body.wallpaperType)
        ? body.wallpaperType
        : "none";

    return {
        wallpaper_type: wallpaperType,
        wallpaper_url: validarWallpaperUrlArmazenada(wallpaperType, body.wallpaperUrl),
        wallpaper_color: validarCorHex(body.wallpaperColor),
        wallpaper_color2: validarCorHex(body.wallpaperColor2),
        wallpaper_angle: clampInteiro(body.wallpaperAngle, 0, 360, 135),
        wallpaper_mode: CHAT_APPEARANCE_WALLPAPER_MODES.includes(body.wallpaperMode)
            ? body.wallpaperMode
            : "cover",
        background_color: validarCorHex(body.backgroundColor),
        own_message_color: validarCorHex(body.ownMessageColor),
        received_message_color: validarCorHex(body.receivedMessageColor),
        accent_color: validarCorHex(body.accentColor),
    };
};

const validarAcessoConversaAppearance = async ({ tipo, referenciaId, userId }) => {
    if (!CHAT_APPEARANCE_CONVERSATION_TIPOS.includes(tipo) || !Number.isInteger(referenciaId) || referenciaId <= 0) {
        return false;
    }

    if (tipo === "direta") {
        const [linhas] = await db.query(`
            SELECT id
            FROM conversas_diretas
            WHERE id = ?
              AND (usuario1_id = ? OR usuario2_id = ?)
            LIMIT 1
        `, [referenciaId, userId, userId]);

        return linhas.length > 0;
    }

    const [linhas] = await db.query(`
        SELECT gm.grupo_id
        FROM grupo_membros gm
        JOIN grupos g ON gm.grupo_id = g.id
        WHERE gm.grupo_id = ?
          AND gm.usuario_id = ?
          AND g.deletado_em IS NULL
        LIMIT 1
    `, [referenciaId, userId]);

    return linhas.length > 0;
};

const garantirTabelasConnectivityTest = async (connection = db) => {
    if (connectivityTestTabelasGarantidas) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS connectivity_test_sites (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            name VARCHAR(120) NOT NULL,
            url VARCHAR(2048) NOT NULL,
            is_default TINYINT(1) NOT NULL DEFAULT 0,
            display_order INT NOT NULL DEFAULT 0,
            created_by INT NULL,
            active TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
            INDEX idx_connectivity_sites_empresa_active (empresa_id, active),
            INDEX idx_connectivity_sites_default (empresa_id, is_default)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        CREATE TABLE IF NOT EXISTS connectivity_test_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            site_id INT NOT NULL,
            status_code INT NULL,
            total_time_ms INT NOT NULL,
            status VARCHAR(20) NOT NULL,
            error_message VARCHAR(255) NULL,
            tested_at DATETIME NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (site_id) REFERENCES connectivity_test_sites(id) ON DELETE CASCADE,
            INDEX idx_connectivity_results_site_id (site_id, tested_at),
            INDEX idx_connectivity_results_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        ALTER TABLE connectivity_test_sites
        ADD COLUMN IF NOT EXISTS active TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS display_order INT NOT NULL DEFAULT 0
    `);

    await connection.query(`
        ALTER TABLE connectivity_test_results
        ADD COLUMN IF NOT EXISTS error_message VARCHAR(255) NULL
    `);

    connectivityTestTabelasGarantidas = true;
};

const normalizarConnectivityUrl = (valor = "") => {
    const texto = String(valor || "").trim();

    if (!texto) {
        throw new Error("URL do site é obrigatória.");
    }

    if (!/^https?:\/\//i.test(texto)) {
        throw new Error("A URL deve começar com http:// ou https://.");
    }

    let url;

    try {
        url = new URL(texto);
    } catch (_err) {
        throw new Error("Informe uma URL válida.");
    }

    if (!["http:", "https:"].includes(url.protocol)) {
        throw new Error("A URL deve usar http:// ou https://.");
    }

    url.hash = "";

    if (url.pathname === "/" && !url.search) {
        return url.origin;
    }

    return url.href;
};

const normalizarConnectivitySitePayload = (body = {}) => {
    const name = String(body.name ?? body.nome ?? "").trim().replace(/\s+/g, " ");
    const url = normalizarConnectivityUrl(body.url);

    if (!name) {
        throw new Error("Nome do site é obrigatório.");
    }

    if (name.length > 120) {
        throw new Error("Nome do site deve ter no máximo 120 caracteres.");
    }

    if (url.length > 2048) {
        throw new Error("URL do site deve ter no máximo 2048 caracteres.");
    }

    return { name, url };
};

const serializarDataIso = (valor) => {
    if (!valor) return null;

    const data = valor instanceof Date ? valor : new Date(valor);
    if (Number.isNaN(data.getTime())) return null;

    return data.toISOString();
};

const classificarConnectivityTeste = (totalTimeMs, erro = null) => {
    if (erro) return "offline";
    if (totalTimeMs <= 800) return "normal";
    if (totalTimeMs <= 2000) return "attention";
    if (totalTimeMs <= 4000) return "slow";
    return "very_slow";
};

const obterMensagemErroConnectivity = (err) => {
    if (!err) return "Falha na conexão";
    if (err.name === "AbortError" || /aborted|timeout/i.test(err.message || "")) return "Timeout";
    if (/ENOTFOUND|EAI_AGAIN|DNS/i.test(err.cause?.code || err.message || "")) return "Erro de DNS";
    if (/ECONNREFUSED/i.test(err.cause?.code || err.message || "")) return "Conexão recusada";
    if (/ECONNRESET/i.test(err.cause?.code || err.message || "")) return "Conexão interrompida";
    return "Falha na conexão";
};

const serializarConnectivityResult = (row = {}) => ({
    id: row.result_id || row.id || null,
    siteId: row.site_id || row.siteId || null,
    statusCode: row.status_code ?? row.statusCode ?? null,
    totalTimeMs: Number(row.total_time_ms ?? row.totalTimeMs ?? 0),
    status: row.status || "offline",
    statusLabel: CONNECTIVITY_TEST_STATUS_LABELS[row.status] || CONNECTIVITY_TEST_STATUS_LABELS.offline,
    error: row.error_message || row.error || null,
    testedAt: serializarDataIso(row.tested_at || row.testedAt),
});

const serializarConnectivitySite = (row = {}) => ({
    id: row.id,
    name: row.name,
    url: row.url,
    isDefault: Boolean(row.is_default),
    active: Boolean(row.active),
    displayOrder: Number(row.display_order || 0),
    createdBy: row.created_by || null,
    createdAt: serializarDataIso(row.created_at),
    updatedAt: serializarDataIso(row.updated_at),
    lastResult: row.result_id
        ? serializarConnectivityResult({
            result_id: row.result_id,
            site_id: row.id,
            status_code: row.status_code,
            total_time_ms: row.total_time_ms,
            status: row.status,
            error_message: row.error_message,
            tested_at: row.tested_at,
        })
        : null,
});

const semearConnectivitySitesPadrao = async (empresaId, connection = db) => {
    for (const [index, site] of CONNECTIVITY_TEST_DEFAULT_SITES.entries()) {
        const url = normalizarConnectivityUrl(site.url);
        const displayOrder = (index + 1) * 10;
        const [existentes] = await connection.query(`
            SELECT id
            FROM connectivity_test_sites
            WHERE empresa_id = ?
              AND LOWER(url) = LOWER(?)
            LIMIT 1
        `, [empresaId, url]);

        if (existentes.length) {
            await connection.query(`
                UPDATE connectivity_test_sites
                SET name = ?,
                    is_default = 1,
                    display_order = ?,
                    active = 1
                WHERE id = ?
            `, [site.name, displayOrder, existentes[0].id]);
            continue;
        }

        await connection.query(`
            INSERT INTO connectivity_test_sites (empresa_id, name, url, is_default, display_order, created_by, active)
            VALUES (?, ?, ?, 1, ?, NULL, 1)
        `, [empresaId, site.name, url, displayOrder]);
    }
};

const listarConnectivitySites = async (empresaId) => {
    await garantirTabelasConnectivityTest();
    await semearConnectivitySitesPadrao(empresaId);

    const [rows] = await db.query(`
        SELECT
            s.id,
            s.name,
            s.url,
            s.is_default,
            s.active,
            s.display_order,
            s.created_by,
            s.created_at,
            s.updated_at,
            r.id AS result_id,
            r.status_code,
            r.total_time_ms,
            r.status,
            r.error_message,
            r.tested_at
        FROM connectivity_test_sites s
        LEFT JOIN (
            SELECT r1.*
            FROM connectivity_test_results r1
            JOIN (
                SELECT site_id, MAX(id) AS max_id
                FROM connectivity_test_results
                GROUP BY site_id
            ) latest ON latest.max_id = r1.id
        ) r ON r.site_id = s.id
        WHERE s.empresa_id = ?
          AND s.active = 1
        ORDER BY s.is_default DESC, s.display_order ASC, s.name ASC
    `, [empresaId]);

    return rows.map(serializarConnectivitySite);
};

const buscarConnectivitySiteAtivo = async (empresaId, siteId) => {
    await garantirTabelasConnectivityTest();
    await semearConnectivitySitesPadrao(empresaId);

    const [rows] = await db.query(`
        SELECT id, empresa_id, name, url, is_default, active, display_order, created_by, created_at, updated_at
        FROM connectivity_test_sites
        WHERE empresa_id = ?
          AND id = ?
          AND active = 1
        LIMIT 1
    `, [empresaId, siteId]);

    return rows[0] || null;
};

const testarConnectivitySite = async (site) => {
    const startedAt = Date.now();
    const testedAt = new Date();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), CONNECTIVITY_TEST_TIMEOUT_MS);
    let lastError = null;

    const requestOptions = (method) => ({
        method,
        redirect: "follow",
        signal: controller.signal,
        headers: {
            "User-Agent": "Acessanet-Connectivity-Test/1.0",
            "Accept": "*/*",
        },
    });

    try {
        for (const method of ["HEAD", "GET"]) {
            try {
                const response = await fetch(site.url, requestOptions(method));

                if (method === "HEAD" && [405, 501].includes(response.status)) {
                    await response.body?.cancel?.();
                    continue;
                }

                await response.body?.cancel?.();

                const totalTimeMs = Math.max(1, Date.now() - startedAt);
                const status = classificarConnectivityTeste(totalTimeMs);

                return {
                    siteId: site.id,
                    name: site.name,
                    url: site.url,
                    statusCode: response.status,
                    totalTimeMs,
                    status,
                    statusLabel: CONNECTIVITY_TEST_STATUS_LABELS[status],
                    error: null,
                    testedAt: testedAt.toISOString(),
                };
            } catch (err) {
                lastError = err;

                if (controller.signal.aborted || method === "GET") {
                    break;
                }
            }
        }

        const error = obterMensagemErroConnectivity(lastError);
        const totalTimeMs = error === "Timeout"
            ? CONNECTIVITY_TEST_TIMEOUT_MS
            : Math.max(1, Math.min(Date.now() - startedAt, CONNECTIVITY_TEST_TIMEOUT_MS));

        return {
            siteId: site.id,
            name: site.name,
            url: site.url,
            statusCode: null,
            totalTimeMs,
            status: "offline",
            statusLabel: CONNECTIVITY_TEST_STATUS_LABELS.offline,
            error,
            testedAt: testedAt.toISOString(),
        };
    } finally {
        clearTimeout(timeoutId);
    }
};

const salvarConnectivityResult = async (resultado) => {
    const testedAt = resultado.testedAt
        ? new Date(resultado.testedAt)
        : new Date();

    const [insert] = await db.query(`
        INSERT INTO connectivity_test_results (
            site_id,
            status_code,
            total_time_ms,
            status,
            error_message,
            tested_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    `, [
        resultado.siteId,
        resultado.statusCode,
        resultado.totalTimeMs,
        resultado.status,
        resultado.error,
        testedAt,
    ]);

    return {
        ...resultado,
        id: insert.insertId,
    };
};

const testarConnectivitySitesComLimite = async (sites = []) => {
    const resultados = new Array(sites.length);
    let proximoIndice = 0;

    const worker = async () => {
        while (proximoIndice < sites.length) {
            const indiceAtual = proximoIndice;
            proximoIndice += 1;

            const resultado = await testarConnectivitySite(sites[indiceAtual]);
            resultados[indiceAtual] = await salvarConnectivityResult(resultado);
        }
    };

    const totalWorkers = Math.min(CONNECTIVITY_TEST_CONCURRENCY, sites.length);
    await Promise.all(Array.from({ length: totalWorkers }, () => worker()));

    return resultados;
};

const garantirTabelaConnectivityPacketTargets = async (connection = db) => {
    if (connectivityPacketTargetsTabelaGarantida) return;

    await connection.query(`
        CREATE TABLE IF NOT EXISTS connectivity_packet_targets (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            name VARCHAR(120) NOT NULL,
            host VARCHAR(255) NOT NULL,
            is_default TINYINT(1) NOT NULL DEFAULT 0,
            active TINYINT(1) NOT NULL DEFAULT 1,
            created_by INT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (empresa_id) REFERENCES empresas(id) ON DELETE CASCADE,
            FOREIGN KEY (created_by) REFERENCES usuarios(id) ON DELETE SET NULL,
            INDEX idx_connectivity_packet_empresa_active (empresa_id, active),
            INDEX idx_connectivity_packet_default (empresa_id, is_default),
            INDEX idx_connectivity_packet_host (empresa_id, host)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await connection.query(`
        ALTER TABLE connectivity_packet_targets
        ADD COLUMN IF NOT EXISTS active TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS is_default TINYINT(1) NOT NULL DEFAULT 0
    `);

    connectivityPacketTargetsTabelaGarantida = true;
};

const normalizarConnectivityPacketHost = (valor = "") => {
    let texto = String(valor || "").trim();

    if (!texto) {
        throw new Error("Host ou IP é obrigatório.");
    }

    if (/^https?:\/\//i.test(texto)) {
        try {
            texto = new URL(texto).hostname;
        } catch (_err) {
            throw new Error("Informe um host ou IP válido.");
        }
    }

    texto = texto.trim().replace(/\.$/, "");

    if (!texto || texto.startsWith("-") || texto.includes("/") || texto.includes("?") || texto.includes("#")) {
        throw new Error("Informe apenas o host ou IP, sem caminho ou parâmetros.");
    }

    if (texto.length > 255) {
        throw new Error("Host ou IP deve ter no máximo 255 caracteres.");
    }

    if (net.isIP(texto)) {
        return texto;
    }

    const labels = texto.split(".");
    const labelsValidos = labels.every((label) => (
        label.length > 0
        && label.length <= 63
        && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    ));

    if (!labelsValidos) {
        throw new Error("Informe um host ou IP válido.");
    }

    return texto.toLowerCase();
};

const normalizarConnectivityPacketTargetPayload = (body = {}) => {
    const name = String(body.name ?? body.nome ?? "").trim().replace(/\s+/g, " ");
    const host = normalizarConnectivityPacketHost(body.host ?? body.ip ?? body.url);

    if (!name) {
        throw new Error("Nome do destino é obrigatório.");
    }

    if (name.length > 120) {
        throw new Error("Nome do destino deve ter no máximo 120 caracteres.");
    }

    return { name, host };
};

const serializarConnectivityPacketTarget = (row = {}) => ({
    id: row.id,
    name: row.name,
    host: row.host,
    isDefault: Boolean(row.is_default),
    active: Boolean(row.active),
    createdBy: row.created_by || null,
    createdAt: serializarDataIso(row.created_at),
    updatedAt: serializarDataIso(row.updated_at),
});

const semearConnectivityPacketTargetsPadrao = async (empresaId, connection = db) => {
    for (const target of CONNECTIVITY_PACKET_DEFAULT_TARGETS) {
        const host = normalizarConnectivityPacketHost(target.host);
        const [existentes] = await connection.query(`
            SELECT id
            FROM connectivity_packet_targets
            WHERE empresa_id = ?
              AND LOWER(host) = LOWER(?)
            LIMIT 1
        `, [empresaId, host]);

        if (existentes.length) {
            await connection.query(`
                UPDATE connectivity_packet_targets
                SET name = ?,
                    is_default = 1,
                    active = 1
                WHERE id = ?
            `, [target.name, existentes[0].id]);
            continue;
        }

        await connection.query(`
            INSERT INTO connectivity_packet_targets (empresa_id, name, host, is_default, active, created_by)
            VALUES (?, ?, ?, 1, 1, NULL)
        `, [empresaId, target.name, host]);
    }
};

const listarConnectivityPacketTargets = async (empresaId) => {
    await garantirTabelaConnectivityPacketTargets();
    await semearConnectivityPacketTargetsPadrao(empresaId);

    const [rows] = await db.query(`
        SELECT id, empresa_id, name, host, is_default, active, created_by, created_at, updated_at
        FROM connectivity_packet_targets
        WHERE empresa_id = ?
          AND active = 1
        ORDER BY is_default DESC, id ASC, name ASC
    `, [empresaId]);

    return rows.map(serializarConnectivityPacketTarget);
};

const buscarConnectivityPacketTargetAtivo = async (empresaId, targetId) => {
    await garantirTabelaConnectivityPacketTargets();
    await semearConnectivityPacketTargetsPadrao(empresaId);

    const [rows] = await db.query(`
        SELECT id, empresa_id, name, host, is_default, active, created_by, created_at, updated_at
        FROM connectivity_packet_targets
        WHERE empresa_id = ?
          AND id = ?
          AND active = 1
        LIMIT 1
    `, [empresaId, targetId]);

    return rows[0] || null;
};

const arredondarMetricaPing = (valor) => {
    const numero = Number(valor);
    if (!Number.isFinite(numero)) return null;
    return Number(numero.toFixed(2));
};

const parsePingOutput = (output = "") => {
    const texto = String(output || "");
    const statsMatch = texto.match(/(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets\s+)?received(?:,\s+\+\d+\s+errors)?(?:,\s+([\d.]+)%\s+packet loss)?/i);
    const lossMatch = texto.match(/([\d.]+)%\s+packet loss/i);
    const rttMatch = texto.match(/(?:rtt|round-trip)\s+min\/avg\/max\/(?:mdev|stddev)\s+=\s+([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/i);
    const samples = [...texto.matchAll(/time[=<]([\d.]+)\s*ms/gi)]
        .map((match) => Number(match[1]))
        .filter((valor) => Number.isFinite(valor));

    let jitterMs = null;

    if (samples.length > 1) {
        const variacoes = samples.slice(1).map((valor, index) => Math.abs(valor - samples[index]));
        const mediaVariacao = variacoes.reduce((total, valor) => total + valor, 0) / variacoes.length;
        jitterMs = arredondarMetricaPing(mediaVariacao);
    } else if (rttMatch) {
        jitterMs = arredondarMetricaPing(rttMatch[4]);
    }

    return {
        sent: statsMatch ? Number(statsMatch[1]) : null,
        received: statsMatch ? Number(statsMatch[2]) : null,
        packetLossPercent: lossMatch ? arredondarMetricaPing(lossMatch[1]) : null,
        minMs: rttMatch ? arredondarMetricaPing(rttMatch[1]) : null,
        avgMs: rttMatch ? arredondarMetricaPing(rttMatch[2]) : null,
        maxMs: rttMatch ? arredondarMetricaPing(rttMatch[3]) : null,
        jitterMs,
    };
};

const classificarPacketLoss = (packetLossPercent, received) => {
    const perda = Number(packetLossPercent);

    if (!Number.isFinite(perda) || received === 0 || perda >= 100) return "no_response";
    if (perda === 0) return "normal";
    if (perda <= 2) return "attention";
    if (perda <= 5) return "moderate_loss";
    return "high_loss";
};

const resolverIpPacketTarget = async (host) => {
    if (net.isIP(host)) return host;

    try {
        const resultado = await Promise.race([
            dns.lookup(host),
            new Promise((_, reject) => {
                setTimeout(() => reject(new Error("Timeout de DNS")), 2500);
            }),
        ]);

        return resultado?.address || null;
    } catch (_err) {
        return null;
    }
};

const obterMensagemErroPing = (err, output = "") => {
    const texto = `${err?.message || ""}\n${output || ""}`;

    if (/Name or service not known|Temporary failure|unknown host|not known|ENOTFOUND|EAI_AGAIN/i.test(texto)) {
        return "Erro de DNS";
    }

    if (/timed out|timeout/i.test(texto)) {
        return "Timeout";
    }

    return "Sem resposta";
};

const testarConnectivityPacketTarget = async (target) => {
    const testedAt = new Date().toISOString();
    const host = normalizarConnectivityPacketHost(target.host);
    const resolvedIp = await resolverIpPacketTarget(host);
    let stdout = "";
    let stderr = "";
    let erroPing = null;

    try {
        const resultado = await execFileAsync(
            "ping",
            ["-n", "-c", String(PACKET_LOSS_PING_COUNT), "-W", String(PACKET_LOSS_PING_TIMEOUT_SECONDS), host],
            {
                timeout: PACKET_LOSS_COMMAND_TIMEOUT_MS,
                maxBuffer: 128 * 1024,
                env: {
                    ...process.env,
                    LANG: "C",
                    LC_ALL: "C",
                },
            }
        );

        stdout = resultado.stdout || "";
        stderr = resultado.stderr || "";
    } catch (err) {
        erroPing = err;
        stdout = err.stdout || "";
        stderr = err.stderr || "";
    }

    const parsed = parsePingOutput(`${stdout}\n${stderr}`);
    const sent = parsed.sent ?? PACKET_LOSS_PING_COUNT;
    const received = parsed.received ?? 0;
    const packetLossPercent = parsed.packetLossPercent ?? (
        sent > 0
            ? arredondarMetricaPing(((sent - received) / sent) * 100)
            : 100
    );
    const status = classificarPacketLoss(packetLossPercent, received);
    const semResposta = status === "no_response";

    return {
        targetId: target.id,
        name: target.name,
        host,
        resolvedIp,
        sent,
        received,
        packetLossPercent,
        minMs: parsed.minMs,
        avgMs: parsed.avgMs,
        maxMs: parsed.maxMs,
        jitterMs: parsed.jitterMs,
        status,
        statusLabel: PACKET_LOSS_STATUS_LABELS[status],
        warning: semResposta ? PACKET_LOSS_BLOCK_WARNING : null,
        error: semResposta ? obterMensagemErroPing(erroPing, `${stdout}\n${stderr}`) : null,
        testedAt,
    };
};

const testarConnectivityPacketTargetsComLimite = async (targets = []) => {
    const resultados = new Array(targets.length);
    let proximoIndice = 0;

    const worker = async () => {
        while (proximoIndice < targets.length) {
            const indiceAtual = proximoIndice;
            proximoIndice += 1;

            resultados[indiceAtual] = await testarConnectivityPacketTarget(targets[indiceAtual]);
        }
    };

    const totalWorkers = Math.min(PACKET_LOSS_CONCURRENCY, targets.length);
    await Promise.all(Array.from({ length: totalWorkers }, () => worker()));

    return resultados;
};

const garantirTabelaNotasRapidas = async () => {
    if (notasRapidasTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS notes (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            owner_user_id INT DEFAULT NULL,
            title VARCHAR(180) NOT NULL,
            content TEXT DEFAULT NULL,
            pinned TINYINT(1) NOT NULL DEFAULT 0,
            last_edited_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            INDEX idx_notes_user (user_id),
            INDEX idx_notes_owner (owner_user_id),
            INDEX idx_notes_last_edited_by (last_edited_by),
            INDEX idx_notes_user_pinned_updated (user_id, pinned, updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE notes
        ADD COLUMN IF NOT EXISTS owner_user_id INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS last_edited_by INT DEFAULT NULL
    `);

    await db.query(`
        UPDATE notes
        SET owner_user_id = COALESCE(owner_user_id, user_id),
            last_edited_by = COALESCE(last_edited_by, user_id)
        WHERE owner_user_id IS NULL
           OR last_edited_by IS NULL
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS note_shares (
            id INT AUTO_INCREMENT PRIMARY KEY,
            note_id INT NOT NULL,
            user_id INT NOT NULL,
            permission ENUM('view', 'edit') NOT NULL DEFAULT 'view',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (note_id) REFERENCES notes(id) ON DELETE CASCADE,
            FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
            UNIQUE KEY unique_note_user (note_id, user_id),
            INDEX idx_note_shares_note (note_id),
            INDEX idx_note_shares_user (user_id),
            INDEX idx_note_shares_user_permission (user_id, permission)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE note_shares
        ADD COLUMN IF NOT EXISTS permission ENUM('view', 'edit') NOT NULL DEFAULT 'view',
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    `);

    notasRapidasTabelaGarantida = true;
};

const garantirTabelaSolicitacoesInternas = async () => {
    if (solicitacoesInternasTabelaGarantida) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS solicitacoes_internas (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            usuario_id INT NOT NULL,
            setor VARCHAR(120) NOT NULL,
            tipo VARCHAR(140) NOT NULL,
            prioridade VARCHAR(20) NOT NULL DEFAULT 'media',
            titulo VARCHAR(180) NOT NULL,
            descricao TEXT NOT NULL,
            status VARCHAR(30) NOT NULL DEFAULT 'aberto',
            resposta TEXT DEFAULT NULL,
            respondido_por INT DEFAULT NULL,
            respondido_em TIMESTAMP NULL DEFAULT NULL,
            responsavel_criacao_id INT DEFAULT NULL,
            responsavel_execucao_id INT DEFAULT NULL,
            concluido_por INT DEFAULT NULL,
            concluido_em TIMESTAMP NULL DEFAULT NULL,
            anexo_url VARCHAR(1000) DEFAULT NULL,
            anexo_nome VARCHAR(255) DEFAULT NULL,
            anexo_mime VARCHAR(180) DEFAULT NULL,
            anexo_tamanho BIGINT DEFAULT NULL,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_solicitacoes_empresa_status (empresa_id, status, atualizado_em),
            INDEX idx_solicitacoes_usuario (usuario_id, atualizado_em),
            INDEX idx_solicitacoes_responsavel (respondido_por),
            INDEX idx_solicitacoes_responsavel_criacao (responsavel_criacao_id),
            INDEX idx_solicitacoes_responsavel_execucao (responsavel_execucao_id),
            INDEX idx_solicitacoes_concluido_por (concluido_por)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE solicitacoes_internas
        ADD COLUMN IF NOT EXISTS resposta TEXT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS respondido_por INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS respondido_em TIMESTAMP NULL DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS responsavel_criacao_id INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS responsavel_execucao_id INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS concluido_por INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS concluido_em TIMESTAMP NULL DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS anexo_url VARCHAR(1000) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS anexo_nome VARCHAR(255) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS anexo_mime VARCHAR(180) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS anexo_tamanho BIGINT DEFAULT NULL
    `);

    solicitacoesInternasTabelaGarantida = true;
};

const TEXTOS_ATENDIMENTO_LIBRARY = {
    tableName: "attendance_texts",
    seedControlTableName: "attendance_texts_seed_control",
    indexPrefix: "attendance_texts",
    defaultItems: TEXTOS_ATENDIMENTO_PADRAO,
    logLabel: "textos de atendimento",
    isGuaranteed: () => textosAtendimentoTabelaGarantida,
    markGuaranteed: () => {
        textosAtendimentoTabelaGarantida = true;
    },
};

const BOAS_PRATICAS_ATENDIMENTO_LIBRARY = {
    tableName: "attendance_best_practices",
    seedControlTableName: "attendance_best_practices_seed_control",
    indexPrefix: "attendance_best_practices",
    defaultItems: BOAS_PRATICAS_ATENDIMENTO_PADRAO,
    logLabel: "boas práticas de atendimento",
    isGuaranteed: () => boasPraticasAtendimentoTabelaGarantida,
    markGuaranteed: () => {
        boasPraticasAtendimentoTabelaGarantida = true;
    },
};

const garantirTabelaBibliotecaConteudo = async (config) => {
    if (config.isGuaranteed()) return;

    await db.query(`
        CREATE TABLE IF NOT EXISTS ${config.tableName} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            empresa_id INT NOT NULL,
            title VARCHAR(180) NOT NULL,
            content LONGTEXT NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1,
            sort_order INT NOT NULL DEFAULT 0,
            created_by INT DEFAULT NULL,
            updated_by INT DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_${config.indexPrefix}_empresa_active_order (empresa_id, is_active, sort_order),
            INDEX idx_${config.indexPrefix}_created_by (created_by),
            INDEX idx_${config.indexPrefix}_updated_by (updated_by)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    await db.query(`
        ALTER TABLE ${config.tableName}
        ADD COLUMN IF NOT EXISTS is_active TINYINT(1) NOT NULL DEFAULT 1,
        ADD COLUMN IF NOT EXISTS sort_order INT NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS created_by INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS updated_by INT DEFAULT NULL
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS ${config.seedControlTableName} (
            empresa_id INT PRIMARY KEY,
            seeded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    config.markGuaranteed();
};

const garantirBibliotecaConteudoPadrao = async (config, empresaId, usuarioId = null) => {
    await garantirTabelaBibliotecaConteudo(config);

    const [controle] = await db.query(`
        SELECT empresa_id
        FROM ${config.seedControlTableName}
        WHERE empresa_id = ?
        LIMIT 1
    `, [empresaId]);

    if (controle.length) return;

    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();

        const [controleTransacao] = await connection.query(`
            SELECT empresa_id
            FROM ${config.seedControlTableName}
            WHERE empresa_id = ?
            LIMIT 1
            FOR UPDATE
        `, [empresaId]);

        if (!controleTransacao.length) {
            for (const [index, texto] of config.defaultItems.entries()) {
                await connection.query(`
                    INSERT INTO ${config.tableName} (
                        empresa_id,
                        title,
                        content,
                        is_active,
                        sort_order,
                        created_by,
                        updated_by
                    )
                    SELECT ?, ?, ?, 1, ?, ?, ?
                    FROM DUAL
                    WHERE NOT EXISTS (
                        SELECT 1
                        FROM ${config.tableName}
                        WHERE empresa_id = ?
                          AND title = ?
                        LIMIT 1
                    )
                `, [
                    empresaId,
                    texto.title,
                    texto.content,
                    (index + 1) * 10,
                    usuarioId,
                    usuarioId,
                    empresaId,
                    texto.title,
                ]);
            }

            await connection.query(`
                INSERT INTO ${config.seedControlTableName} (empresa_id)
                VALUES (?)
            `, [empresaId]);
        }

        await connection.commit();
    } catch (err) {
        try {
            await connection.rollback();
        } catch (rollbackErr) {
            console.error(`Erro ao desfazer seed de ${config.logLabel}:`, rollbackErr);
        }

        throw err;
    } finally {
        connection.release();
    }
};

const garantirTabelaTextosAtendimento = async () => (
    garantirTabelaBibliotecaConteudo(TEXTOS_ATENDIMENTO_LIBRARY)
);

const garantirTextosAtendimentoPadrao = async (empresaId, usuarioId = null) => (
    garantirBibliotecaConteudoPadrao(TEXTOS_ATENDIMENTO_LIBRARY, empresaId, usuarioId)
);

const garantirTabelaBoasPraticasAtendimento = async () => (
    garantirTabelaBibliotecaConteudo(BOAS_PRATICAS_ATENDIMENTO_LIBRARY)
);

const garantirBoasPraticasAtendimentoPadrao = async (empresaId, usuarioId = null) => (
    garantirBibliotecaConteudoPadrao(BOAS_PRATICAS_ATENDIMENTO_LIBRARY, empresaId, usuarioId)
);

const validarUsuariosCompartilhamentoNota = async (connection, userIds, empresaId) => {
    if (!userIds.length) return [];

    const placeholders = criarPlaceholders(userIds.length);
    const [usuarios] = await connection.query(`
        SELECT id, nome, email
        FROM usuarios
        WHERE empresa_id = ?
          AND deletado_em IS NULL
          AND id IN (${placeholders})
        ORDER BY nome ASC
    `, [empresaId, ...userIds]);

    if (usuarios.length !== userIds.length) {
        return null;
    }

    return usuarios;
};

const salvarCompartilhamentosNota = async (connection, noteId, compartilhamentos, empresaId) => {
    const userIds = compartilhamentos.map((item) => Number(item.user_id));
    const usuariosValidos = await validarUsuariosCompartilhamentoNota(connection, userIds, empresaId);

    if (!usuariosValidos) {
        const erro = new Error("Um ou mais usuários selecionados para compartilhamento são inválidos.");
        erro.statusCode = 400;
        throw erro;
    }

    await connection.query("DELETE FROM note_shares WHERE note_id = ?", [noteId]);

    if (!userIds.length) return;

    const valuesSql = compartilhamentos.map(() => "(?, ?, ?)").join(", ");
    const params = compartilhamentos.flatMap((item) => [
        noteId,
        Number(item.user_id),
        normalizarPermissaoNota(item.permission),
    ]);

    await connection.query(`
        INSERT INTO note_shares (note_id, user_id, permission)
        VALUES ${valuesSql}
    `, params);
};

const anexarCompartilhamentosNotas = async (notas) => {
    if (!notas.length) return [];

    const noteIds = notas.map((nota) => Number(nota.id));
    const placeholders = criarPlaceholders(noteIds.length);
    const [compartilhamentos] = await db.query(`
        SELECT
            ns.note_id,
            ns.permission,
            ns.created_at,
            ns.updated_at,
            u.id,
            u.nome,
            u.email,
            s.nome AS setor_nome
        FROM note_shares ns
        JOIN usuarios u ON u.id = ns.user_id
        LEFT JOIN setores s ON s.id = u.setor_id
        WHERE ns.note_id IN (${placeholders})
          AND u.deletado_em IS NULL
        ORDER BY u.nome ASC
    `, noteIds);

    const usuariosPorNota = new Map();

    compartilhamentos.forEach((usuario) => {
        const lista = usuariosPorNota.get(Number(usuario.note_id)) || [];
        const permission = normalizarPermissaoNota(usuario.permission);
        lista.push({
            id: usuario.id,
            nome: usuario.nome,
            email: usuario.email || null,
            setor_nome: usuario.setor_nome || null,
            permission,
            permission_label: rotuloPermissaoNota(permission),
            created_at: usuario.created_at,
            updated_at: usuario.updated_at,
        });
        usuariosPorNota.set(Number(usuario.note_id), lista);
    });

    return notas.map((nota) => formatarNotaRapida({
        ...nota,
        shared_users: usuariosPorNota.get(Number(nota.id)) || [],
    }));
};

const buscarNotaRapidaPorId = async (noteId, usuarioId, empresaId, somenteDono = false) => {
    const params = [
        usuarioId,
        usuarioId,
        usuarioId,
        noteId,
        empresaId,
        usuarioId,
    ];

    if (!somenteDono) {
        params.push(usuarioId);
    }

    const permissaoSql = somenteDono
        ? "COALESCE(n.owner_user_id, n.user_id) = ?"
        : "(COALESCE(n.owner_user_id, n.user_id) = ? OR ns_usuario.user_id = ?)";

    const [notas] = await db.query(`
        SELECT
            n.id,
            COALESCE(n.owner_user_id, n.user_id) AS user_id,
            COALESCE(n.owner_user_id, n.user_id) AS owner_user_id,
            owner.nome AS owner_name,
            owner.email AS owner_email,
            owner_setor.nome AS owner_setor_nome,
            CASE WHEN COALESCE(n.owner_user_id, n.user_id) = ? THEN 'owner' ELSE 'shared' END AS access_type,
            CASE
                WHEN COALESCE(n.owner_user_id, n.user_id) = ? THEN 'owner'
                ELSE COALESCE(ns_usuario.permission, 'view')
            END AS permission,
            n.title,
            n.content,
            n.pinned,
            n.created_at,
            n.updated_at,
            editor.id AS last_edited_by_id,
            editor.nome AS last_edited_by_name,
            editor.email AS last_edited_by_email,
            editor_setor.nome AS last_edited_by_setor_nome
        FROM notes n
        JOIN usuarios owner ON owner.id = COALESCE(n.owner_user_id, n.user_id)
        LEFT JOIN setores owner_setor ON owner_setor.id = owner.setor_id
        LEFT JOIN note_shares ns_usuario
               ON ns_usuario.note_id = n.id
              AND ns_usuario.user_id = ?
        LEFT JOIN usuarios editor ON editor.id = n.last_edited_by
        LEFT JOIN setores editor_setor ON editor_setor.id = editor.setor_id
        WHERE n.id = ?
          AND owner.empresa_id = ?
          AND owner.deletado_em IS NULL
          AND ${permissaoSql}
        LIMIT 1
    `, params);

    const notasFormatadas = await anexarCompartilhamentosNotas(notas);
    return notasFormatadas[0] || null;
};

const buscarAcessoNotaRapida = async (connection, noteId, usuarioId, empresaId) => {
    const [notas] = await connection.query(`
        SELECT
            n.id,
            COALESCE(n.owner_user_id, n.user_id) AS owner_user_id,
            n.pinned,
            ns.permission AS share_permission
        FROM notes n
        JOIN usuarios owner ON owner.id = COALESCE(n.owner_user_id, n.user_id)
        LEFT JOIN note_shares ns
               ON ns.note_id = n.id
              AND ns.user_id = ?
        WHERE n.id = ?
          AND owner.empresa_id = ?
          AND owner.deletado_em IS NULL
        LIMIT 1
    `, [usuarioId, noteId, empresaId]);

    if (!notas.length) return null;

    const nota = notas[0];
    const ehDono = Number(nota.owner_user_id) === Number(usuarioId);
    const permissao = ehDono ? "owner" : normalizarPermissaoNota(nota.share_permission);
    const temAcesso = ehDono || Boolean(nota.share_permission);

    return {
        ...nota,
        is_owner: ehDono,
        has_access: temAcesso,
        permission: permissao,
        can_edit: ehDono || permissao === "edit",
        can_manage: ehDono,
    };
};

const listarUsuariosComAcessoNotaRapida = async (noteId, connection = db) => {
    const [rows] = await connection.query(`
        SELECT COALESCE(n.owner_user_id, n.user_id) AS user_id
        FROM notes n
        WHERE n.id = ?
        UNION
        SELECT ns.user_id
        FROM note_shares ns
        WHERE ns.note_id = ?
    `, [noteId, noteId]);

    return rows
        .map((row) => Number(row.user_id))
        .filter((id) => Number.isInteger(id) && id > 0);
};

const emitirEventoNotaRapida = (req, usuarioIds, payload) => {
    const io = req.app.get("io");

    if (!io || !usuarioIds?.length) return;

    const idsUnicos = [...new Set(usuarioIds.map((id) => Number(id)).filter(Boolean))];

    idsUnicos.forEach((usuarioId) => {
        io.to(`user_${usuarioId}`).emit("quick_note_changed", payload);
    });
};

const garantirTabelaLeiturasMensagens = async () => {
    if (leiturasMensagensTabelaGarantida) return;
    if (leiturasMensagensTabelaGarantidaPromise) {
        return leiturasMensagensTabelaGarantidaPromise;
    }

    leiturasMensagensTabelaGarantidaPromise = (async () => {
        await db.query(`
            CREATE TABLE IF NOT EXISTS leituras_mensagens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                mensagem_id INT NOT NULL,
                usuario_id INT NOT NULL,
                entregue_em TIMESTAMP NULL DEFAULT NULL,
                lida_em TIMESTAMP NULL DEFAULT NULL,
                FOREIGN KEY (mensagem_id) REFERENCES mensagens(id) ON DELETE CASCADE,
                FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                UNIQUE KEY unique_leitura (mensagem_id, usuario_id),
                INDEX idx_mensagem (mensagem_id),
                INDEX idx_usuario (usuario_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);

        await db.query(`
            ALTER TABLE leituras_mensagens
            ADD COLUMN IF NOT EXISTS entregue_em TIMESTAMP NULL DEFAULT NULL
        `);

        await db.query(`
            ALTER TABLE leituras_mensagens
            MODIFY COLUMN lida_em TIMESTAMP NULL DEFAULT NULL
        `);

        try {
            await db.query(`
                UPDATE leituras_mensagens
                SET entregue_em = COALESCE(entregue_em, lida_em)
                WHERE lida_em IS NOT NULL
                  AND entregue_em IS NULL
            `);
        } catch (err) {
            if (err?.code !== "ER_LOCK_DEADLOCK") {
                throw err;
            }

            console.warn("Deadlock ignorado ao compatibilizar leituras_mensagens; tentativa futura manterá a tabela atualizada.");
        }

        leiturasMensagensTabelaGarantida = true;
    })();

    try {
        await leiturasMensagensTabelaGarantidaPromise;
    } finally {
        leiturasMensagensTabelaGarantidaPromise = null;
    }
};

const garantirTabelaLeiturasGrupos = async () => {
    if (leiturasGruposTabelaGarantida) return;
    if (leiturasGruposTabelaGarantidaPromise) {
        return leiturasGruposTabelaGarantidaPromise;
    }

    leiturasGruposTabelaGarantidaPromise = (async () => {
        await db.query(`
            CREATE TABLE IF NOT EXISTS group_message_reads (
                user_id INT NOT NULL,
                group_id INT NOT NULL,
                last_read_message_id INT NULL DEFAULT NULL,
                last_read_at TIMESTAMP NULL DEFAULT NULL,
                PRIMARY KEY (user_id, group_id),
                FOREIGN KEY (user_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                FOREIGN KEY (group_id) REFERENCES grupos(id) ON DELETE CASCADE,
                FOREIGN KEY (last_read_message_id) REFERENCES mensagens(id) ON DELETE SET NULL,
                INDEX idx_group_message_reads_group_user (group_id, user_id),
                INDEX idx_group_message_reads_message (last_read_message_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        `);

        await db.query(`
            INSERT INTO group_message_reads (
                user_id,
                group_id,
                last_read_message_id,
                last_read_at
            )
            SELECT
                lm.usuario_id,
                m.grupo_id,
                MAX(m.id) AS last_read_message_id,
                MAX(lm.lida_em) AS last_read_at
            FROM leituras_mensagens lm
            JOIN mensagens m ON m.id = lm.mensagem_id
            JOIN grupo_membros gm
              ON gm.grupo_id = m.grupo_id
             AND gm.usuario_id = lm.usuario_id
            WHERE lm.lida_em IS NOT NULL
              AND m.grupo_id IS NOT NULL
              AND m.deletada_em IS NULL
            GROUP BY lm.usuario_id, m.grupo_id
            ON DUPLICATE KEY UPDATE
                last_read_message_id = CASE
                    WHEN VALUES(last_read_message_id) > COALESCE(group_message_reads.last_read_message_id, 0)
                        THEN VALUES(last_read_message_id)
                    ELSE group_message_reads.last_read_message_id
                END,
                last_read_at = CASE
                    WHEN group_message_reads.last_read_at IS NULL
                        THEN VALUES(last_read_at)
                    WHEN VALUES(last_read_at) IS NULL
                        THEN group_message_reads.last_read_at
                    WHEN VALUES(last_read_at) > group_message_reads.last_read_at
                        THEN VALUES(last_read_at)
                    ELSE group_message_reads.last_read_at
                END
        `);

        leiturasGruposTabelaGarantida = true;
    })();

    try {
        await leiturasGruposTabelaGarantidaPromise;
    } finally {
        leiturasGruposTabelaGarantidaPromise = null;
    }
};

const marcarLeituraGrupoPorCursor = async (grupoId, usuarioId) => {
    const grupoIdNumerico = Number(grupoId);
    const usuarioIdNumerico = Number(usuarioId);

    if (!grupoIdNumerico || !usuarioIdNumerico) return;

    await garantirTabelaLeiturasGrupos();

    await db.query(`
        INSERT INTO group_message_reads (
            user_id,
            group_id,
            last_read_message_id,
            last_read_at
        )
        SELECT
            ?,
            ?,
            MAX(m.id),
            NOW()
        FROM mensagens m
        WHERE m.grupo_id = ?
          AND m.deletada_em IS NULL
        ON DUPLICATE KEY UPDATE
            last_read_message_id = CASE
                WHEN VALUES(last_read_message_id) IS NULL
                    THEN group_message_reads.last_read_message_id
                WHEN group_message_reads.last_read_message_id IS NULL
                    THEN VALUES(last_read_message_id)
                WHEN VALUES(last_read_message_id) > group_message_reads.last_read_message_id
                    THEN VALUES(last_read_message_id)
                ELSE group_message_reads.last_read_message_id
            END,
            last_read_at = VALUES(last_read_at)
    `, [usuarioIdNumerico, grupoIdNumerico, grupoIdNumerico]);
};

const marcarMensagensGrupoComoLidas = async (grupoId, usuarioId) => {
    await garantirTabelaLeiturasMensagens();

    await db.query(`
        INSERT INTO leituras_mensagens (mensagem_id, usuario_id, entregue_em, lida_em)
        SELECT m.id, ?, NOW(), NOW()
        FROM mensagens m
        WHERE m.grupo_id = ?
          AND m.remetente_id != ?
          AND m.deletada_em IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM leituras_mensagens lm
              WHERE lm.mensagem_id = m.id
                AND lm.usuario_id = ?
                AND lm.lida_em IS NOT NULL
          )
        ON DUPLICATE KEY UPDATE
            entregue_em = COALESCE(leituras_mensagens.entregue_em, VALUES(entregue_em)),
            lida_em = COALESCE(leituras_mensagens.lida_em, VALUES(lida_em))
    `, [usuarioId, grupoId, usuarioId, usuarioId]);

    await marcarLeituraGrupoPorCursor(grupoId, usuarioId);
};

const normalizarLimiteMensagens = (valor, padrao = 100, maximo = 150) => {
    const limite = Number.parseInt(valor, 10);

    if (!Number.isFinite(limite) || limite <= 0) {
        return padrao;
    }

    return Math.min(limite, maximo);
};

const garantirIndicesChatPerformance = async () => {
    if (indicesChatPerformanceGarantidos) return;

    await db.query("CREATE INDEX IF NOT EXISTS idx_mensagens_grupo_criada_id ON mensagens(grupo_id, criada_em DESC, id DESC)");
    await db.query("CREATE INDEX IF NOT EXISTS idx_mensagens_grupo_id ON mensagens(grupo_id, id DESC)");
    await db.query("CREATE INDEX IF NOT EXISTS idx_grupo_membros_usuario_grupo ON grupo_membros(usuario_id, grupo_id)");
    await db.query("CREATE INDEX IF NOT EXISTS idx_grupo_membros_grupo_usuario ON grupo_membros(grupo_id, usuario_id)");

    indicesChatPerformanceGarantidos = true;
};

const marcarMensagemGrupoComoLidaPeloAutor = async (mensagemId, usuarioId) => {
    await garantirTabelaLeiturasMensagens();

    await db.query(`
        INSERT INTO leituras_mensagens (mensagem_id, usuario_id, entregue_em, lida_em)
        VALUES (?, ?, NOW(), NOW())
        ON DUPLICATE KEY UPDATE
            entregue_em = COALESCE(leituras_mensagens.entregue_em, VALUES(entregue_em)),
            lida_em = COALESCE(leituras_mensagens.lida_em, VALUES(lida_em))
    `, [mensagemId, usuarioId]);
};

const garantirTipoMensagemAudio = async () => {
    if (tipoMensagemAudioGarantido) return;

    await db.query(`
        ALTER TABLE mensagens
        ADD COLUMN IF NOT EXISTS tipo_mensagem ENUM('texto', 'imagem', 'audio', 'arquivo', 'sticker') DEFAULT 'texto',
        ADD COLUMN IF NOT EXISTS resposta_mensagem_id INT DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS sticker_id INT DEFAULT NULL
    `);

    await db.query(`
        ALTER TABLE mensagens
        MODIFY COLUMN tipo_mensagem ENUM('texto', 'imagem', 'audio', 'arquivo', 'sticker') DEFAULT 'texto'
    `);

    await db.query(`
        ALTER TABLE mensagens
        MODIFY COLUMN mensagem LONGTEXT NOT NULL
    `);

    await db.query("CREATE INDEX IF NOT EXISTS idx_mensagens_sticker ON mensagens(sticker_id)");

    tipoMensagemAudioGarantido = true;
};

const buscarMensagemRespondida = async ({ mensagemId, conversaDiretaId = null, grupoId = null }) => {
    const respostaMensagemId = Number(mensagemId);

    if (!respostaMensagemId) return null;

    const filtroConversa = conversaDiretaId
        ? "m.conversa_direta_id = ?"
        : "m.grupo_id = ?";
    const filtroValor = conversaDiretaId || grupoId;

    const [rows] = await db.query(`
        SELECT
            m.id AS resposta_mensagem_id,
            m.remetente_id AS resposta_remetente_id,
            u.nome AS resposta_remetente_nome,
            m.tipo_mensagem AS resposta_tipo_mensagem,
            m.mensagem AS resposta_mensagem,
            m.anexo_nome AS resposta_anexo_nome,
            m.sticker_id AS resposta_sticker_id,
            CASE
                WHEN m.tipo_mensagem = 'imagem' THEN '[Imagem]'
                WHEN m.tipo_mensagem = 'audio' THEN '[Áudio]'
                WHEN m.tipo_mensagem = 'arquivo' THEN '[Arquivo]'
                WHEN m.tipo_mensagem = 'sticker' THEN 'Figurinha'
                ELSE LEFT(m.mensagem, 180)
            END AS resposta_previa
        FROM mensagens m
        JOIN usuarios u ON m.remetente_id = u.id
        WHERE m.id = ?
          AND ${filtroConversa}
          AND m.deletada_em IS NULL
        LIMIT 1
    `, [respostaMensagemId, filtroValor]);

    return rows[0] || null;
};

const garantirAuditoriaMensagens = async () => {
    await db.query(`
        ALTER TABLE mensagens
        ADD COLUMN IF NOT EXISTS deletada_por INT DEFAULT NULL
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS chat_message_audit (
            id INT AUTO_INCREMENT PRIMARY KEY,
            mensagem_id INT NOT NULL,
            usuario_id INT DEFAULT NULL,
            acao VARCHAR(40) NOT NULL,
            valor_antigo LONGTEXT DEFAULT NULL,
            valor_novo LONGTEXT DEFAULT NULL,
            criada_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ip VARCHAR(80) DEFAULT NULL,
            user_agent VARCHAR(255) DEFAULT NULL,
            FOREIGN KEY (mensagem_id) REFERENCES mensagens(id) ON DELETE CASCADE,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL,
            INDEX idx_audit_mensagem (mensagem_id),
            INDEX idx_audit_usuario (usuario_id),
            INDEX idx_audit_acao (acao),
            INDEX idx_audit_criada (criada_em)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);
};

const serializarAuditoria = (valor) => {
    if (valor === undefined || valor === null) return null;
    try {
        return JSON.stringify(valor);
    } catch {
        return String(valor);
    }
};

const registrarAuditoriaMensagem = async ({
    mensagemId,
    usuarioId = null,
    acao,
    valorAntigo = null,
    valorNovo = null,
    req = null,
}) => {
    try {
        await garantirAuditoriaMensagens();
        await db.query(`
            INSERT INTO chat_message_audit (
                mensagem_id,
                usuario_id,
                acao,
                valor_antigo,
                valor_novo,
                ip,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
            mensagemId,
            usuarioId,
            acao,
            serializarAuditoria(valorAntigo),
            serializarAuditoria(valorNovo),
            req?.ip || null,
            req?.get?.("user-agent") || null,
        ]);

        if (!CONTROLE_OPERACIONAL_ENABLED) return;

        const acaoCentral = {
            enviada: "ENVIAR_MENSAGEM",
            editada: "EDITAR_MENSAGEM",
            apagada: "REMOVER_MENSAGEM",
        }[acao] || `MENSAGEM_${String(acao || "acao").toUpperCase()}`;

        await registrarAuditoria({
            usuario: req?.user || null,
            usuarioId,
            acao: acaoCentral,
            entidade: "mensagem",
            entidadeId: mensagemId,
            tipo: AUDIT_TYPES.CHAT,
            nivel: acao === "apagada"
                ? AUDIT_LEVELS.CRITICAL
                : acao === "editada"
                    ? AUDIT_LEVELS.IMPORTANT
                    : AUDIT_LEVELS.NORMAL,
            origem: "CHAT_INTERNO",
            valorAnterior: valorAntigo,
            valorNovo,
            metadata: {
                mensagem_id: mensagemId,
                referencia: "chat_message_audit",
                nao_duplicar_conteudo_envio: acao === "enviada",
            },
            req,
        });
    } catch (err) {
        console.error("Erro ao registrar auditoria de mensagem:", err);
    }
};

const validarMensagem = ({ tipo_mensagem = "texto", mensagem, anexo_mime, sticker_id = null }) => {
    if (!["texto", "imagem", "audio", "arquivo", "sticker"].includes(tipo_mensagem)) {
        return "Tipo de mensagem inválido";
    }

    if (tipo_mensagem === "imagem") {
        if (!mensagem || !isAnexoDataUrlOuUpload(mensagem, IMAGE_DATA_URL_REGEX)) {
            return "Imagem inválida";
        }

        if (anexo_mime && !String(anexo_mime).toLowerCase().startsWith("image/")) {
            return "Formato de imagem não permitido";
        }

        if (!isUploadChatUrl(mensagem) && mensagem.length > MAX_IMAGE_DATA_URL_LENGTH) {
            return `Imagem muito grande. Envie arquivos de até ${MAX_UPLOAD_SIZE_MB} MB`;
        }

        return null;
    }

    if (tipo_mensagem === "audio") {
        if (!mensagem || !isAnexoDataUrlOuUpload(mensagem, AUDIO_DATA_URL_REGEX)) {
            return "Áudio inválido";
        }

        if (anexo_mime && !String(anexo_mime).toLowerCase().startsWith("audio/")) {
            return "Formato de áudio não permitido";
        }

        if (!isUploadChatUrl(mensagem) && mensagem.length > MAX_AUDIO_DATA_URL_LENGTH) {
            return `Áudio muito grande. Envie arquivos de até ${MAX_UPLOAD_SIZE_MB} MB`;
        }

        return null;
    }

    if (tipo_mensagem === "arquivo") {
        if (!mensagem || !isAnexoDataUrlOuUpload(mensagem, FILE_DATA_URL_REGEX)) {
            return "Arquivo inválido";
        }

        if (!isUploadChatUrl(mensagem) && mensagem.length > MAX_FILE_DATA_URL_LENGTH) {
            return `Arquivo muito grande. Envie arquivos de até ${MAX_UPLOAD_SIZE_MB} MB`;
        }

        return null;
    }

    if (tipo_mensagem === "sticker") {
        if (!Number(sticker_id) || !mensagem || !isUploadStickerUrl(mensagem)) {
            return "Figurinha inválida";
        }

        if (anexo_mime && String(anexo_mime).toLowerCase() !== "image/webp") {
            return "Formato de figurinha não permitido";
        }

        return null;
    }

    if (!mensagem || !mensagem.trim()) {
        return "Mensagem vazia";
    }

    return null;
};

const validarAvatar = (avatar) => {
    if (!avatar) {
        return null;
    }

    if (!IMAGE_DATA_URL_REGEX.test(avatar)) {
        return "Foto de perfil inválida";
    }

    if (avatar.length > MAX_IMAGE_DATA_URL_LENGTH) {
        return `Foto muito grande. Envie imagens de até ${MAX_UPLOAD_SIZE_MB} MB`;
    }

    return null;
};

const normalizarMencaoUsuario = (valor = "") => (
    String(valor)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]/g, "")
);

const textoNormalizadoParaMencoes = (valor = "") => (
    String(valor)
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
);

const montarHandlesMencaoUsuario = (nome = "") => {
    const partes = String(nome).trim().split(/\s+/).filter(Boolean);

    return [
        normalizarMencaoUsuario(nome),
        normalizarMencaoUsuario(partes[0] || ""),
    ].filter(Boolean);
};

const detectarMencoesGrupo = async ({ grupoId, mensagem, remetenteId }) => {
    if (!mensagem || typeof mensagem !== "string") {
        return [];
    }

    const texto = textoNormalizadoParaMencoes(mensagem);
    const [membros] = await db.query(`
        SELECT u.id, u.nome
        FROM grupo_membros gm
        JOIN usuarios u ON gm.usuario_id = u.id
        WHERE gm.grupo_id = ?
          AND u.deletado_em IS NULL
    `, [grupoId]);

    return membros
        .filter((membro) => Number(membro.id) !== Number(remetenteId))
        .map((membro) => ({
            id: membro.id,
            nome: membro.nome,
            handles: montarHandlesMencaoUsuario(membro.nome),
        }))
        .filter((membro) => (
            membro.handles.some((handle) => {
                const regex = new RegExp(`(^|[^a-z0-9_])@${handle}(?![a-z0-9_])`);
                return regex.test(texto);
            })
        ))
        .map(({ handles, ...membro }) => ({
            ...membro,
            handle: handles[0],
        }));
};

const requireAdmin = async (req, res, next) => {
    try {
        const [rows] = await db.query(`
            SELECT id, nome, email, empresa_id, perfil
            FROM usuarios
            WHERE id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [req.user.id]);

        const admin = rows[0];

        if (!admin || admin.perfil !== PERFIL_ADMIN) {
            return res.status(403).json({ error: "Acesso restrito ao administrador" });
        }

        req.admin = admin;
        next();
    } catch (err) {
        console.error("Erro ao validar administrador:", err);
        res.status(500).json({ error: "Erro ao validar administrador" });
    }
};

const requireSoundEffectAccess = async (req, res, next) => {
    try {
        const [rows] = await db.query(`
            SELECT id, nome, email, empresa_id, perfil
            FROM usuarios
            WHERE id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [req.user.id]);

        const usuario = rows[0];

        if (!usuario || !(await usuarioPodeUsarEfeitosSonoros(usuario))) {
            return res.status(403).json({ error: "Seu usuário não tem permissão para usar efeitos sonoros." });
        }

        req.soundEffectUser = usuario;
        next();
    } catch (err) {
        console.error("Erro ao validar permissão de efeitos sonoros:", err);
        res.status(500).json({ error: "Erro ao validar permissão de efeitos sonoros." });
    }
};

const requireSoundEffectManager = async (req, res, next) => {
    try {
        const [rows] = await db.query(`
            SELECT id, nome, email, empresa_id, perfil
            FROM usuarios
            WHERE id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [req.user.id]);

        const usuario = rows[0];

        if (!usuario || !(await usuarioPodeGerenciarEfeitosSonoros(usuario))) {
            return res.status(403).json({ error: "Seu usuário não tem permissão para gerenciar efeitos sonoros." });
        }

        req.soundEffectUser = usuario;
        next();
    } catch (err) {
        console.error("Erro ao validar gerência de efeitos sonoros:", err);
        res.status(500).json({ error: "Erro ao validar gerência de efeitos sonoros." });
    }
};

const requireEditorBibliotecaAtendimento = async (req, res, next) => {
    try {
        const [rows] = await db.query(`
            SELECT id, nome, email, empresa_id, perfil
            FROM usuarios
            WHERE id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [req.user.id]);

        const editor = rows[0];

        if (!editor || !PERFIS_EDITOR_BIBLIOTECA_ATENDIMENTO.includes(editor.perfil)) {
            return res.status(403).json({
                error: "Acesso restrito aos administradores e administradores comerciais.",
            });
        }

        req.admin = editor;
        req.editorBibliotecaAtendimento = editor;
        next();
    } catch (err) {
        console.error("Erro ao validar editor da biblioteca de atendimento:", err);
        res.status(500).json({ error: "Erro ao validar editor da biblioteca de atendimento" });
    }
};

const requireEditorAvisosInternos = async (req, res, next) => {
    try {
        const [rows] = await db.query(`
            SELECT id, nome, email, empresa_id, perfil
            FROM usuarios
            WHERE id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [req.user.id]);

        const editor = rows[0];

        if (!editor || !PERFIS_EDITOR_AVISOS_INTERNOS.includes(editor.perfil)) {
            return res.status(403).json({ error: "Acesso restrito a quem pode editar avisos internos" });
        }

        req.editorAvisosInternos = editor;
        next();
    } catch (err) {
        console.error("Erro ao validar editor de avisos internos:", err);
        res.status(500).json({ error: "Erro ao validar editor de avisos internos" });
    }
};

// Exige login e ignora o parâmetro da URL: cada usuário só lista setores da própria empresa (antes era público
// e permitia enumerar qualquer empresa). Nenhuma tela de login depende desta rota (só Chat.jsx, já logado).
route.post("/setores/:empresa_id", authMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT * FROM setores WHERE empresa_id=?",
            [req.user.empresa_id]
        );

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar setores:", err);
        res.status(500).json({ error: "Erro ao listar setores" });
    }
});

// Troca o token ainda válido por um novo (renovação silenciosa feita pelo app). O limite absoluto da sessão vale aqui.
route.post("/auth/renovar", authMiddleware, (req, res) => {
    try {
        if (!podeRenovar(req.user, Math.floor(Date.now() / 1000), maximoDeDias())) {
            return res.status(401).json({ error: "A sessão chegou ao limite de duração. Entre novamente." });
        }

        const payload = montarPayloadRenovado(req.user, req.user);
        const token = jwt.sign(payload, getSecret(), { expiresIn: JWT_EXPIRES_IN });
        const { exp } = jwt.decode(token);
        res.set("Cache-Control", "no-store").json({ token, exp });
    } catch (err) {
        console.error("Erro ao renovar a sessão:", err);
        res.status(500).json({ error: "Não foi possível renovar a sessão." });
    }
});

// Limite de tentativas por IP e por e-mail (em memória, com backoff). Ver src/security/loginRateLimit.js.
const limitadorLogin = criarLimitadorLogin();
const HASH_FALSO_LOGIN = bcrypt.hashSync("senha-inexistente-para-igualar-tempo", 10);
const MENSAGEM_CREDENCIAIS_INVALIDAS = "Credenciais inválidas";

route.post("/login", async (req, res) => {
    try {
        const emailInformado = typeof req.body?.email === "string" ? req.body.email.trim() : "";
        const senha = typeof req.body?.senha === "string" ? req.body.senha : "";
        const chaveLimite = { ip: req.ip, email: emailInformado };

        const limite = limitadorLogin.verificar(chaveLimite);
        if (!limite.permitido) {
            res.set("Retry-After", String(limite.tentarEmSeg));
            return res.status(429).json({
                error: `Muitas tentativas de login. Tente novamente em ${Math.max(1, Math.ceil(limite.tentarEmSeg / 60))} min.`,
            });
        }

        if (!emailInformado || !senha || emailInformado.length > 254 || senha.length > 1024) {
            limitadorLogin.registrarFalha(chaveLimite);
            return res.status(401).json({ error: MENSAGEM_CREDENCIAIS_INVALIDAS });
        }

        const [rows] = await db.query(`
    SELECT 
      u.*,
      e.nome AS empresa_nome,
      s.nome AS setor_nome
    FROM usuarios u
    JOIN empresas e ON u.empresa_id = e.id
    LEFT JOIN setores s ON u.setor_id = s.id
    WHERE u.email = ? AND u.deletado_em IS NULL
  `, [emailInformado]);

        const user = rows[0];

        // Sempre roda o bcrypt (hash falso se o usuário não existe): mesma mensagem e mesmo tempo, sem enumeração de e-mails.
        const valid = await bcrypt.compare(senha, user?.senha || HASH_FALSO_LOGIN);

        if (!user || !valid) {
            limitadorLogin.registrarFalha(chaveLimite);
            return res.status(401).json({ error: MENSAGEM_CREDENCIAIS_INVALIDAS });
        }

        limitadorLogin.registrarSucesso(chaveLimite);

        const token = jwt.sign(
            {
                id: user.id,
                nome: user.nome,
                empresa_id: user.empresa_id,
                setor_id: user.setor_id,
                perfil: user.perfil,
            },
            getSecret(),
            { expiresIn: JWT_EXPIRES_IN }
        );

        res.json({
            token,
            user: {
                id: user.id,
                nome: user.nome,
                email: user.email,
                empresa_id: user.empresa_id,
                empresa_nome: user.empresa_nome,
                setor_id: user.setor_id,
                setor_nome: user.setor_nome,
                avatar: user.avatar,
                perfil: user.perfil,
            },
        });
    } catch (err) {
        console.error("Erro no login:", err);
        res.status(500).json({ error: "Erro ao entrar. Tente novamente." });
    }
});

// Exige login e ignora o parâmetro da URL (ver /setores/:empresa_id).
route.post("/usuarios/:empresa_id", authMiddleware, async (req, res) => {
    try {
        const [rows] = await db.query(
            "SELECT id, nome FROM usuarios WHERE empresa_id=? AND deletado_em IS NULL",
            [req.user.empresa_id]
        );

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar usuários:", err);
        res.status(500).json({ error: "Erro ao listar usuários" });
    }
});


// REGISTER: só administrador autenticado cria usuário (a tela do Admin usa POST /admin/usuarios; esta rota
// ficou por compatibilidade). A empresa é sempre a do administrador; o empresa_id do corpo é ignorado.
route.post("/register", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const nome = typeof req.body?.nome === "string" ? req.body.nome.trim() : "";
        const email = typeof req.body?.email === "string" ? req.body.email.trim().toLowerCase() : "";
        const senha = typeof req.body?.senha === "string" ? req.body.senha : "";
        const setorId = Number(req.body?.setor_id);
        const empresaId = req.admin.empresa_id;

        if (!nome || nome.length > 150) {
            return res.status(400).json({ error: "Nome inválido" });
        }

        if (!email || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ error: "E-mail inválido" });
        }

        if (senha.length < 6 || senha.length > 128) {
            return res.status(400).json({ error: "A senha precisa ter entre 6 e 128 caracteres" });
        }

        if (!Number.isInteger(setorId) || setorId <= 0) {
            return res.status(400).json({ error: "Setor inválido para essa empresa" });
        }

        const [setor] = await db.query(
            "SELECT id FROM setores WHERE id=? AND empresa_id=?",
            [setorId, empresaId]
        );

        if (setor.length === 0) {
            return res
                .status(400)
                .json({ error: "Setor inválido para essa empresa" });
        }

        // Inclui usuários removidos: o e-mail é único na tabela e reativação é feita por POST /admin/usuarios.
        const [existente] = await db.query("SELECT id FROM usuarios WHERE email=? LIMIT 1", [email]);

        if (existente.length) {
            return res.status(409).json({ error: "Já existe um usuário com esse e-mail" });
        }

        const hash = await bcrypt.hash(senha, 10);

        try {
            await db.query(
                "INSERT INTO usuarios (nome,email,senha,empresa_id,setor_id) VALUES (?,?,?,?,?)",
                [nome, email, hash, empresaId, setorId]
            );
        } catch (err) {
            if (err?.code === "ER_DUP_ENTRY") {
                return res.status(409).json({ error: "Já existe um usuário com esse e-mail" });
            }
            throw err;
        }

        res.status(201).json({ success: true });
    } catch (err) {
        console.error("Erro ao registrar usuário:", err);
        res.status(500).json({ error: "Erro ao registrar usuário" });
    }
});

// USER LOGADO
route.get("/me", authMiddleware, async (req, res) => {
    const [rows] = await db.query(`
    SELECT 
      u.id,
      u.nome,
      u.email,
      u.empresa_id,
      e.nome AS empresa_nome,
      u.setor_id,
      s.nome AS setor_nome,
      u.avatar,
      u.status,
      u.ultimo_acesso,
      u.perfil
    FROM usuarios u
    JOIN empresas e ON u.empresa_id = e.id
    LEFT JOIN setores s ON u.setor_id = s.id
    WHERE u.id = ? AND u.deletado_em IS NULL
  `, [req.user.id]);

    const usuario = rows[0];

    if (!usuario) {
        return res.status(404).json({ error: "Usuário não encontrado" });
    }

    const [usuarioComGrupos] = await anexarGruposAUsuarios([usuario], usuario.empresa_id);
    res.json(usuarioComGrupos);
});

route.put("/profile", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const {
            nome,
            avatar,
            email,
            senha_atual,
            nova_senha,
        } = req.body;

        const fields = [];
        const values = [];

        if (nome !== undefined) {
            const nomeNormalizado = (nome || "").trim();

            if (nomeNormalizado.length < 2) {
                return res.status(400).json({ error: "Nome precisa ter pelo menos 2 caracteres" });
            }

            fields.push("nome = ?");
            values.push(nomeNormalizado);
        }

        if (avatar !== undefined) {
            const erroAvatar = validarAvatar(avatar);

            if (erroAvatar) {
                return res.status(400).json({ error: erroAvatar });
            }

            fields.push("avatar = ?");
            values.push(avatar || null);
        }

        if (nova_senha) {
            if (nova_senha.length < 6) {
                return res.status(400).json({ error: "A nova senha precisa ter pelo menos 6 caracteres" });
            }

            const [rows] = await db.query(`
                SELECT senha
                FROM usuarios
                WHERE id = ? AND deletado_em IS NULL
                LIMIT 1
            `, [userId]);

            const usuario = rows[0];

            if (!usuario) {
                return res.status(404).json({ error: "Usuário não encontrado" });
            }

            const senhaValida = await bcrypt.compare(senha_atual || "", usuario.senha);

            if (!senhaValida) {
                return res.status(401).json({ error: "Senha atual inválida" });
            }

            const hash = await bcrypt.hash(nova_senha, 10);
            fields.push("senha = ?");
            values.push(hash);
        }

        if (email !== undefined) {
            // O e-mail é o login: a troca exige a senha atual e não pode repetir o de outro usuário.
            const novoEmail = String(email || "").trim().toLowerCase();

            if (novoEmail.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(novoEmail)) {
                return res.status(400).json({ error: "Informe um e-mail válido" });
            }

            const [atuais] = await db.query(`
                SELECT email, senha
                FROM usuarios
                WHERE id = ? AND deletado_em IS NULL
                LIMIT 1
            `, [userId]);

            const atual = atuais[0];

            if (!atual) {
                return res.status(404).json({ error: "Usuário não encontrado" });
            }

            if (novoEmail !== String(atual.email || "").trim().toLowerCase()) {
                const senhaConfere = await bcrypt.compare(senha_atual || "", atual.senha);

                if (!senhaConfere) {
                    return res.status(401).json({ error: "Senha atual inválida" });
                }

                const [emUso] = await db.query(
                    "SELECT id FROM usuarios WHERE email = ? AND id <> ? LIMIT 1",
                    [novoEmail, userId]
                );

                if (emUso.length) {
                    return res.status(409).json({ error: "Este e-mail já está em uso por outro usuário" });
                }

                fields.push("email = ?");
                values.push(novoEmail);
            }
        }

        if (!fields.length) {
            return res.status(400).json({ error: "Nada para atualizar" });
        }

        values.push(userId);

        await db.query(`
            UPDATE usuarios
            SET ${fields.join(", ")}
            WHERE id = ? AND deletado_em IS NULL
        `, values);

        const [updated] = await db.query(`
            SELECT 
              u.id,
              u.nome,
              u.email,
              u.empresa_id,
              e.nome AS empresa_nome,
              u.setor_id,
              s.nome AS setor_nome,
              u.avatar,
              u.status,
              u.ultimo_acesso,
              u.perfil
            FROM usuarios u
            JOIN empresas e ON u.empresa_id = e.id
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE u.id = ? AND u.deletado_em IS NULL
            LIMIT 1
        `, [userId]);

        const usuarioAtualizado = updated[0];
        const [usuarioComGrupos] = await anexarGruposAUsuarios([usuarioAtualizado], usuarioAtualizado.empresa_id);

        res.json(usuarioComGrupos);
    } catch (err) {
        if (err?.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ error: "Este e-mail já está em uso por outro usuário" });
        }

        console.error("Erro ao atualizar perfil:", err);
        res.status(500).json({ error: "Erro ao atualizar perfil" });
    }
});

route.get("/me/quick-access", authMiddleware, async (req, res) => {
    try {
        const acessos = await listarAcessosRapidosUsuario(req.user);
        res.json(acessos);
    } catch (err) {
        console.error("Erro ao listar acessos rápidos do usuário:", err);
        res.status(500).json({ error: "Erro ao listar acessos rápidos." });
    }
});

route.post("/me/quick-access", authMiddleware, async (req, res) => {
    try {
        const quickAccessId = normalizarQuickAccessId(req.body?.quick_access_id);
        const acesso = await buscarQuickAccessDisponivel(req.user, quickAccessId);

        if (!acesso) {
            return res.status(400).json({ error: "Acesso rápido inválido ou indisponível para este usuário." });
        }

        await garantirTabelaAcessosRapidosUsuario();

        const [posicaoRows] = await db.query(`
            SELECT COALESCE(MAX(\`position\`), 0) + 10 AS proxima_posicao
            FROM user_quick_access
            WHERE user_id = ?
        `, [req.user.id]);

        await db.query(`
            INSERT INTO user_quick_access (user_id, quick_access_id, \`position\`)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE quick_access_id = VALUES(quick_access_id)
        `, [
            req.user.id,
            acesso.id,
            Number(posicaoRows[0]?.proxima_posicao || 10),
        ]);

        const acessos = await listarAcessosRapidosUsuario(req.user);
        res.status(201).json(acessos);
    } catch (err) {
        console.error("Erro ao adicionar acesso rápido do usuário:", err);
        res.status(500).json({ error: "Erro ao adicionar acesso rápido." });
    }
});

route.delete("/me/quick-access/:quickAccessId", authMiddleware, async (req, res) => {
    try {
        const quickAccessId = normalizarQuickAccessId(req.params.quickAccessId);

        await garantirTabelaAcessosRapidosUsuario();
        await db.query(`
            DELETE FROM user_quick_access
            WHERE user_id = ?
              AND quick_access_id = ?
        `, [req.user.id, quickAccessId]);

        const acessos = await listarAcessosRapidosUsuario(req.user);
        res.json(acessos);
    } catch (err) {
        console.error("Erro ao remover acesso rápido do usuário:", err);
        res.status(500).json({ error: "Erro ao remover acesso rápido." });
    }
});

route.put("/me/quick-access/order", authMiddleware, async (req, res) => {
    const connection = await db.getConnection();

    try {
        const idsSolicitados = Array.isArray(req.body?.quick_access_ids)
            ? req.body.quick_access_ids
            : Array.isArray(req.body?.items)
                ? req.body.items.map((item) => item?.quick_access_id ?? item?.id)
                : [];

        const quickAccessIds = [...new Set(
            idsSolicitados
                .map(normalizarQuickAccessId)
                .filter(Boolean)
        )];

        if (!quickAccessIds.length) {
            const acessos = await listarAcessosRapidosUsuario(req.user);
            return res.json(acessos);
        }

        const acessosDisponiveis = await listarQuickAccessDisponiveis(req.user);
        const acessosDisponiveisSet = new Set(acessosDisponiveis.map((item) => item.id));
        const idsIndisponiveis = quickAccessIds.filter((quickAccessId) => (
            !acessosDisponiveisSet.has(quickAccessId)
        ));

        if (idsIndisponiveis.length) {
            return res.status(400).json({ error: "Há acessos rápidos inválidos ou indisponíveis." });
        }

        await garantirTabelaAcessosRapidosUsuario();

        const [salvos] = await db.query(`
            SELECT quick_access_id
            FROM user_quick_access
            WHERE user_id = ?
              AND quick_access_id IN (?)
        `, [req.user.id, quickAccessIds]);

        const salvosSet = new Set(salvos.map((item) => item.quick_access_id));

        if (quickAccessIds.some((quickAccessId) => !salvosSet.has(quickAccessId))) {
            return res.status(400).json({ error: "Só é possível ordenar acessos já adicionados." });
        }

        await connection.beginTransaction();

        for (const [index, quickAccessId] of quickAccessIds.entries()) {
            await connection.query(`
                UPDATE user_quick_access
                SET \`position\` = ?
                WHERE user_id = ?
                  AND quick_access_id = ?
            `, [(index + 1) * 10, req.user.id, quickAccessId]);
        }

        await connection.commit();

        const acessos = await listarAcessosRapidosUsuario(req.user);
        return res.json(acessos);
    } catch (err) {
        try {
            await connection.rollback();
        } catch (rollbackErr) {
            console.error("Erro ao desfazer ordenação de acessos rápidos:", rollbackErr);
        }

        console.error("Erro ao ordenar acessos rápidos do usuário:", err);
        return res.status(500).json({ error: "Erro ao ordenar acessos rápidos." });
    } finally {
        connection.release();
    }
});

// ========================================
// PERSONALIZAÇÃO VISUAL DO CHAT (self-only)
// ========================================

route.get("/chat/appearance", authMiddleware, async (req, res) => {
    try {
        const preferences = await obterChatUserAppearance(req.user.id);
        res.json({ preferences });
    } catch (err) {
        console.error("Erro ao carregar personalização do chat:", err);
        res.status(500).json({ error: "Erro ao carregar personalização do chat." });
    }
});

route.put("/chat/appearance", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaChatUserAppearance();

        const dados = validarPayloadChatUserAppearance(req.body);

        await db.query(`
            INSERT INTO chat_user_appearance (
                user_id, theme, accent_color, background_color, panel_color,
                own_message_color, received_message_color, text_color, secondary_text_color, link_color,
                wallpaper_type, wallpaper_url, wallpaper_color, wallpaper_color2, wallpaper_angle,
                wallpaper_mode, wallpaper_intensity, wallpaper_blur,
                message_radius, message_density, font_size, bubble_opacity,
                show_timestamp, show_avatar, show_date_separator, show_wallpaper, animations_enabled
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?, ?
            )
            ON DUPLICATE KEY UPDATE
                theme = VALUES(theme),
                accent_color = VALUES(accent_color),
                background_color = VALUES(background_color),
                panel_color = VALUES(panel_color),
                own_message_color = VALUES(own_message_color),
                received_message_color = VALUES(received_message_color),
                text_color = VALUES(text_color),
                secondary_text_color = VALUES(secondary_text_color),
                link_color = VALUES(link_color),
                wallpaper_type = VALUES(wallpaper_type),
                wallpaper_url = VALUES(wallpaper_url),
                wallpaper_color = VALUES(wallpaper_color),
                wallpaper_color2 = VALUES(wallpaper_color2),
                wallpaper_angle = VALUES(wallpaper_angle),
                wallpaper_mode = VALUES(wallpaper_mode),
                wallpaper_intensity = VALUES(wallpaper_intensity),
                wallpaper_blur = VALUES(wallpaper_blur),
                message_radius = VALUES(message_radius),
                message_density = VALUES(message_density),
                font_size = VALUES(font_size),
                bubble_opacity = VALUES(bubble_opacity),
                show_timestamp = VALUES(show_timestamp),
                show_avatar = VALUES(show_avatar),
                show_date_separator = VALUES(show_date_separator),
                show_wallpaper = VALUES(show_wallpaper),
                animations_enabled = VALUES(animations_enabled)
        `, [
            req.user.id, dados.theme, dados.accent_color, dados.background_color, dados.panel_color,
            dados.own_message_color, dados.received_message_color, dados.text_color, dados.secondary_text_color, dados.link_color,
            dados.wallpaper_type, dados.wallpaper_url, dados.wallpaper_color, dados.wallpaper_color2, dados.wallpaper_angle,
            dados.wallpaper_mode, dados.wallpaper_intensity, dados.wallpaper_blur,
            dados.message_radius, dados.message_density, dados.font_size, dados.bubble_opacity,
            dados.show_timestamp, dados.show_avatar, dados.show_date_separator, dados.show_wallpaper, dados.animations_enabled,
        ]);

        const preferences = await obterChatUserAppearance(req.user.id);
        res.json({ preferences });
    } catch (err) {
        console.error("Erro ao salvar personalização do chat:", err);
        res.status(500).json({ error: "Erro ao salvar personalização do chat." });
    }
});

route.delete("/chat/appearance", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaChatUserAppearance();

        await db.query(`
            DELETE FROM chat_user_appearance
            WHERE user_id = ?
        `, [req.user.id]);

        res.json({ preferences: { ...CHAT_APPEARANCE_DEFAULTS } });
    } catch (err) {
        console.error("Erro ao restaurar personalização do chat:", err);
        res.status(500).json({ error: "Erro ao restaurar personalização do chat." });
    }
});

route.post("/chat/appearance/wallpaper", authMiddleware, uploadWallpaperMiddleware, async (req, res) => {
    try {
        const resultado = await criarWallpaperAPartirDeUpload({ file: req.file, usuario: req.user });
        res.status(201).json(resultado);
    } catch (err) {
        const status = err.status || 500;
        if (status >= 500) {
            console.error("Erro ao enviar wallpaper:", err);
        }
        res.status(status).json({ error: err.message || "Erro ao enviar papel de parede." });
    }
});

route.get("/chat/appearance/conversations/:tipo/:referenciaId", authMiddleware, async (req, res) => {
    try {
        const tipo = String(req.params.tipo || "");
        const referenciaId = Number(req.params.referenciaId);

        const temAcesso = await validarAcessoConversaAppearance({ tipo, referenciaId, userId: req.user.id });
        if (!temAcesso) {
            return res.status(404).json({ error: "Conversa não encontrada." });
        }

        await garantirTabelaChatConversationAppearance();

        const [rows] = await db.query(`
            SELECT *
            FROM chat_conversation_appearance
            WHERE user_id = ? AND tipo = ? AND referencia_id = ?
            LIMIT 1
        `, [req.user.id, tipo, referenciaId]);

        res.json({ preferences: formatarChatConversationAppearance(rows[0]) });
    } catch (err) {
        console.error("Erro ao carregar personalização da conversa:", err);
        res.status(500).json({ error: "Erro ao carregar personalização da conversa." });
    }
});

route.put("/chat/appearance/conversations/:tipo/:referenciaId", authMiddleware, async (req, res) => {
    try {
        const tipo = String(req.params.tipo || "");
        const referenciaId = Number(req.params.referenciaId);

        const temAcesso = await validarAcessoConversaAppearance({ tipo, referenciaId, userId: req.user.id });
        if (!temAcesso) {
            return res.status(404).json({ error: "Conversa não encontrada." });
        }

        await garantirTabelaChatConversationAppearance();

        const dados = validarPayloadChatConversationAppearance(req.body);

        await db.query(`
            INSERT INTO chat_conversation_appearance (
                user_id, tipo, referencia_id,
                wallpaper_type, wallpaper_url, wallpaper_color, wallpaper_color2, wallpaper_angle, wallpaper_mode,
                background_color, own_message_color, received_message_color, accent_color
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                wallpaper_type = VALUES(wallpaper_type),
                wallpaper_url = VALUES(wallpaper_url),
                wallpaper_color = VALUES(wallpaper_color),
                wallpaper_color2 = VALUES(wallpaper_color2),
                wallpaper_angle = VALUES(wallpaper_angle),
                wallpaper_mode = VALUES(wallpaper_mode),
                background_color = VALUES(background_color),
                own_message_color = VALUES(own_message_color),
                received_message_color = VALUES(received_message_color),
                accent_color = VALUES(accent_color)
        `, [
            req.user.id, tipo, referenciaId,
            dados.wallpaper_type, dados.wallpaper_url, dados.wallpaper_color, dados.wallpaper_color2, dados.wallpaper_angle, dados.wallpaper_mode,
            dados.background_color, dados.own_message_color, dados.received_message_color, dados.accent_color,
        ]);

        const [rows] = await db.query(`
            SELECT *
            FROM chat_conversation_appearance
            WHERE user_id = ? AND tipo = ? AND referencia_id = ?
            LIMIT 1
        `, [req.user.id, tipo, referenciaId]);

        res.json({ preferences: formatarChatConversationAppearance(rows[0]) });
    } catch (err) {
        console.error("Erro ao salvar personalização da conversa:", err);
        res.status(500).json({ error: "Erro ao salvar personalização da conversa." });
    }
});

route.delete("/chat/appearance/conversations/:tipo/:referenciaId", authMiddleware, async (req, res) => {
    try {
        const tipo = String(req.params.tipo || "");
        const referenciaId = Number(req.params.referenciaId);

        const temAcesso = await validarAcessoConversaAppearance({ tipo, referenciaId, userId: req.user.id });
        if (!temAcesso) {
            return res.status(404).json({ error: "Conversa não encontrada." });
        }

        await garantirTabelaChatConversationAppearance();

        await db.query(`
            DELETE FROM chat_conversation_appearance
            WHERE user_id = ? AND tipo = ? AND referencia_id = ?
        `, [req.user.id, tipo, referenciaId]);

        res.json({ preferences: null });
    } catch (err) {
        console.error("Erro ao remover personalização da conversa:", err);
        res.status(500).json({ error: "Erro ao remover personalização da conversa." });
    }
});

// ========================================
// TESTE DE CONECTIVIDADE POR SITES
// ========================================

route.get("/connectivity/sites", authMiddleware, async (req, res) => {
    try {
        const sites = await listarConnectivitySites(req.user.empresa_id);

        res.json({
            sites,
            canManage: req.user.perfil === PERFIL_ADMIN,
            timeoutMs: CONNECTIVITY_TEST_TIMEOUT_MS,
            concurrency: CONNECTIVITY_TEST_CONCURRENCY,
        });
    } catch (err) {
        console.error("Erro ao listar sites de conectividade:", err);
        res.status(500).json({ error: "Erro ao listar sites de conectividade." });
    }
});

route.post("/connectivity/sites", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const payload = normalizarConnectivitySitePayload(req.body);

        await garantirTabelasConnectivityTest();
        await semearConnectivitySitesPadrao(empresaId);

        const [duplicados] = await db.query(`
            SELECT id
            FROM connectivity_test_sites
            WHERE empresa_id = ?
              AND active = 1
              AND LOWER(url) = LOWER(?)
            LIMIT 1
        `, [empresaId, payload.url]);

        if (duplicados.length) {
            return res.status(409).json({ error: "Já existe um site cadastrado com essa URL." });
        }

        const [ordemRows] = await db.query(`
            SELECT COALESCE(MAX(display_order), 0) + 10 AS proxima_ordem
            FROM connectivity_test_sites
            WHERE empresa_id = ?
        `, [empresaId]);

        await db.query(`
            INSERT INTO connectivity_test_sites (empresa_id, name, url, is_default, display_order, created_by, active)
            VALUES (?, ?, ?, 0, ?, ?, 1)
        `, [
            empresaId,
            payload.name,
            payload.url,
            Number(ordemRows[0]?.proxima_ordem || 1000),
            req.admin.id,
        ]);

        const sites = await listarConnectivitySites(empresaId);
        res.status(201).json({ sites });
    } catch (err) {
        const statusCode = /obrigat|URL|válid|máximo/i.test(err.message || "") ? 400 : 500;
        console.error("Erro ao cadastrar site de conectividade:", err);
        res.status(statusCode).json({ error: err.message || "Erro ao cadastrar site." });
    }
});

route.put("/connectivity/sites/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const siteId = Number(req.params.id);
        const payload = normalizarConnectivitySitePayload(req.body);

        if (!Number.isInteger(siteId) || siteId <= 0) {
            return res.status(400).json({ error: "Site inválido." });
        }

        const site = await buscarConnectivitySiteAtivo(empresaId, siteId);

        if (!site) {
            return res.status(404).json({ error: "Site não encontrado." });
        }

        if (Number(site.is_default) === 1) {
            return res.status(400).json({ error: "Sites padrão não podem ser editados." });
        }

        const [duplicados] = await db.query(`
            SELECT id
            FROM connectivity_test_sites
            WHERE empresa_id = ?
              AND active = 1
              AND id <> ?
              AND LOWER(url) = LOWER(?)
            LIMIT 1
        `, [empresaId, siteId, payload.url]);

        if (duplicados.length) {
            return res.status(409).json({ error: "Já existe um site cadastrado com essa URL." });
        }

        await db.query(`
            UPDATE connectivity_test_sites
            SET name = ?,
                url = ?
            WHERE id = ?
              AND empresa_id = ?
        `, [payload.name, payload.url, siteId, empresaId]);

        const sites = await listarConnectivitySites(empresaId);
        res.json({ sites });
    } catch (err) {
        const statusCode = /obrigat|URL|válid|máximo/i.test(err.message || "") ? 400 : 500;
        console.error("Erro ao editar site de conectividade:", err);
        res.status(statusCode).json({ error: err.message || "Erro ao editar site." });
    }
});

route.delete("/connectivity/sites/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const siteId = Number(req.params.id);

        if (!Number.isInteger(siteId) || siteId <= 0) {
            return res.status(400).json({ error: "Site inválido." });
        }

        const site = await buscarConnectivitySiteAtivo(empresaId, siteId);

        if (!site) {
            return res.status(404).json({ error: "Site não encontrado." });
        }

        if (Number(site.is_default) === 1) {
            return res.status(400).json({ error: "Sites padrão não podem ser removidos." });
        }

        await db.query(`
            UPDATE connectivity_test_sites
            SET active = 0
            WHERE id = ?
              AND empresa_id = ?
        `, [siteId, empresaId]);

        const sites = await listarConnectivitySites(empresaId);
        res.json({ sites });
    } catch (err) {
        console.error("Erro ao remover site de conectividade:", err);
        res.status(500).json({ error: "Erro ao remover site." });
    }
});

route.post("/connectivity/test", authMiddleware, async (req, res) => {
    try {
        const sites = await listarConnectivitySites(req.user.empresa_id);
        const sitesAtivos = sites.filter((site) => site.active);

        const resultados = await testarConnectivitySitesComLimite(sitesAtivos);

        res.json({
            results: resultados,
            testedAt: new Date().toISOString(),
        });
    } catch (err) {
        console.error("Erro ao testar conectividade dos sites:", err);
        res.status(500).json({ error: "Erro ao executar teste de conectividade." });
    }
});

route.post("/connectivity/test-one", authMiddleware, async (req, res) => {
    try {
        const siteId = Number(req.body?.site_id ?? req.body?.id);

        if (!Number.isInteger(siteId) || siteId <= 0) {
            return res.status(400).json({ error: "Site inválido." });
        }

        const site = await buscarConnectivitySiteAtivo(req.user.empresa_id, siteId);

        if (!site) {
            return res.status(404).json({ error: "Site não encontrado." });
        }

        const resultado = await salvarConnectivityResult(await testarConnectivitySite(site));

        res.json({
            result: resultado,
            testedAt: resultado.testedAt,
        });
    } catch (err) {
        console.error("Erro ao testar site individual:", err);
        res.status(500).json({ error: "Erro ao executar teste do site." });
    }
});

route.get("/connectivity/packet-targets", authMiddleware, async (req, res) => {
    try {
        const targets = await listarConnectivityPacketTargets(req.user.empresa_id);

        res.json({
            targets,
            canManage: req.user.perfil === PERFIL_ADMIN,
            pingCount: PACKET_LOSS_PING_COUNT,
            timeoutSeconds: PACKET_LOSS_PING_TIMEOUT_SECONDS,
        });
    } catch (err) {
        console.error("Erro ao listar destinos de perda de pacotes:", err);
        res.status(500).json({ error: "Erro ao listar destinos de perda de pacotes." });
    }
});

route.post("/connectivity/packet-targets", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const payload = normalizarConnectivityPacketTargetPayload(req.body);

        await garantirTabelaConnectivityPacketTargets();
        await semearConnectivityPacketTargetsPadrao(empresaId);

        const [duplicados] = await db.query(`
            SELECT id
            FROM connectivity_packet_targets
            WHERE empresa_id = ?
              AND active = 1
              AND LOWER(host) = LOWER(?)
            LIMIT 1
        `, [empresaId, payload.host]);

        if (duplicados.length) {
            return res.status(409).json({ error: "Já existe um destino cadastrado com esse host ou IP." });
        }

        await db.query(`
            INSERT INTO connectivity_packet_targets (empresa_id, name, host, is_default, active, created_by)
            VALUES (?, ?, ?, 0, 1, ?)
        `, [
            empresaId,
            payload.name,
            payload.host,
            req.admin.id,
        ]);

        const targets = await listarConnectivityPacketTargets(empresaId);
        res.status(201).json({ targets });
    } catch (err) {
        const statusCode = /obrigat|host|IP|válid|máximo/i.test(err.message || "") ? 400 : 500;
        console.error("Erro ao cadastrar destino de perda de pacotes:", err);
        res.status(statusCode).json({ error: err.message || "Erro ao cadastrar destino." });
    }
});

route.put("/connectivity/packet-targets/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const targetId = Number(req.params.id);
        const payload = normalizarConnectivityPacketTargetPayload(req.body);

        if (!Number.isInteger(targetId) || targetId <= 0) {
            return res.status(400).json({ error: "Destino inválido." });
        }

        const target = await buscarConnectivityPacketTargetAtivo(empresaId, targetId);

        if (!target) {
            return res.status(404).json({ error: "Destino não encontrado." });
        }

        if (Number(target.is_default) === 1) {
            return res.status(400).json({ error: "Destinos padrão não podem ser editados." });
        }

        const [duplicados] = await db.query(`
            SELECT id
            FROM connectivity_packet_targets
            WHERE empresa_id = ?
              AND active = 1
              AND id <> ?
              AND LOWER(host) = LOWER(?)
            LIMIT 1
        `, [empresaId, targetId, payload.host]);

        if (duplicados.length) {
            return res.status(409).json({ error: "Já existe um destino cadastrado com esse host ou IP." });
        }

        await db.query(`
            UPDATE connectivity_packet_targets
            SET name = ?,
                host = ?
            WHERE id = ?
              AND empresa_id = ?
        `, [payload.name, payload.host, targetId, empresaId]);

        const targets = await listarConnectivityPacketTargets(empresaId);
        res.json({ targets });
    } catch (err) {
        const statusCode = /obrigat|host|IP|válid|máximo/i.test(err.message || "") ? 400 : 500;
        console.error("Erro ao editar destino de perda de pacotes:", err);
        res.status(statusCode).json({ error: err.message || "Erro ao editar destino." });
    }
});

route.delete("/connectivity/packet-targets/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const targetId = Number(req.params.id);

        if (!Number.isInteger(targetId) || targetId <= 0) {
            return res.status(400).json({ error: "Destino inválido." });
        }

        const target = await buscarConnectivityPacketTargetAtivo(empresaId, targetId);

        if (!target) {
            return res.status(404).json({ error: "Destino não encontrado." });
        }

        if (Number(target.is_default) === 1) {
            return res.status(400).json({ error: "Destinos padrão não podem ser removidos." });
        }

        await db.query(`
            UPDATE connectivity_packet_targets
            SET active = 0
            WHERE id = ?
              AND empresa_id = ?
        `, [targetId, empresaId]);

        const targets = await listarConnectivityPacketTargets(empresaId);
        res.json({ targets });
    } catch (err) {
        console.error("Erro ao remover destino de perda de pacotes:", err);
        res.status(500).json({ error: "Erro ao remover destino." });
    }
});

route.post("/connectivity/packet-loss-test", authMiddleware, async (req, res) => {
    try {
        const targetIdValor = req.body?.target_id ?? req.body?.id;
        const testarDestinoUnico = targetIdValor !== undefined && targetIdValor !== null && targetIdValor !== "";
        const targetId = Number(targetIdValor);
        let targets = [];

        if (testarDestinoUnico) {
            if (!Number.isInteger(targetId) || targetId <= 0) {
                return res.status(400).json({ error: "Destino inválido." });
            }

            const target = await buscarConnectivityPacketTargetAtivo(req.user.empresa_id, targetId);

            if (!target) {
                return res.status(404).json({ error: "Destino não encontrado." });
            }

            targets = [serializarConnectivityPacketTarget(target)];
        } else {
            targets = await listarConnectivityPacketTargets(req.user.empresa_id);
        }

        const resultados = await testarConnectivityPacketTargetsComLimite(
            targets.filter((target) => target.active)
        );

        res.json(resultados);
    } catch (err) {
        console.error("Erro ao testar perda de pacotes:", err);
        res.status(500).json({ error: "Erro ao executar teste de perda de pacotes." });
    }
});

// ========================================
// VENDAS - MATERIAIS E PROCESSOS
// ========================================

route.get("/vendas/materiais", authMiddleware, async (req, res) => {
    try {
        const canManage = usuarioPodeGerenciarMateriaisVendas(req.user);
        const incluirInativos = canManage && String(req.query.include_inactive || "") === "1";
        const materials = await listarMateriaisVendas(req.user.empresa_id, incluirInativos, req.user.id);

        res.json({
            materials,
            can_manage: canManage,
            allowed_cover_extensions: SALES_COVER_ALLOWED_EXTENSIONS,
            allowed_file_extensions: SALES_FILE_ALLOWED_EXTENSIONS,
            limite_mb: SALES_MATERIALS_MAX_SIZE_MB,
        });
    } catch (err) {
        console.error("Erro ao listar materiais de vendas:", err);
        res.status(500).json({ error: "Erro ao listar materiais de vendas." });
    }
});

route.get("/sales-materials", authMiddleware, async (req, res) => {
    try {
        const canManage = usuarioPodeGerenciarMateriaisVendas(req.user);
        const materials = await listarMateriaisVendas(req.user.empresa_id, canManage, req.user.id);

        res.json({
            materials,
            can_manage: canManage,
            allowed_cover_extensions: SALES_COVER_ALLOWED_EXTENSIONS,
            allowed_file_extensions: SALES_FILE_ALLOWED_EXTENSIONS,
            limite_mb: SALES_MATERIALS_MAX_SIZE_MB,
        });
    } catch (err) {
        console.error("Erro ao listar materiais de vendas:", err);
        res.status(500).json({ error: "Erro ao listar materiais de vendas." });
    }
});

route.get("/vendas/materiais/:id", authMiddleware, async (req, res) => {
    try {
        const materialId = Number(req.params.id);
        const canManage = usuarioPodeGerenciarMateriaisVendas(req.user);

        if (!Number.isInteger(materialId) || materialId <= 0) {
            return res.status(400).json({ error: "Material inválido." });
        }

        await garantirMateriaisVendasPadrao(req.user.empresa_id, req.user.id);

        const material = await buscarMaterialVendas(materialId, req.user.empresa_id, canManage);

        if (!material) {
            return res.status(404).json({ error: "Material não encontrado." });
        }

        return res.json({ material, can_manage: canManage });
    } catch (err) {
        console.error("Erro ao buscar material de vendas:", err);
        return res.status(500).json({ error: "Erro ao buscar material de vendas." });
    }
});

route.post(
    "/vendas/materiais",
    authMiddleware,
    requireSalesMaterialsManager,
    uploadSalesMaterialManagerMiddleware,
    async (req, res) => {
        try {
            await garantirMateriaisVendasPadrao(req.user.empresa_id, req.user.id);

            const payload = montarPayloadMaterialVendas(req);

            if (!payload.title) {
                removerUploadsTemporariosVendas(req.files);
                return res.status(400).json({ error: "Informe o título do material." });
            }

            const [result] = await db.query(`
                INSERT INTO sales_materials (
                    empresa_id,
                    title,
                    description,
                    category,
                    material_type,
                    cover_image_url,
                    file_url,
                    file_name,
                    file_mime,
                    file_size,
                    external_url,
                    display_order,
                    is_active,
                    created_by,
                    updated_by
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
                req.user.empresa_id,
                payload.title,
                payload.description,
                payload.category,
                payload.material_type,
                payload.cover_image_url,
                payload.file_url,
                payload.file_name,
                payload.file_mime,
                payload.file_size,
                payload.external_url,
                payload.display_order,
                payload.is_active,
                req.user.id,
                req.user.id,
            ]);

            const material = await buscarMaterialVendas(result.insertId, req.user.empresa_id, true);

            return res.status(201).json(material);
        } catch (err) {
            removerUploadsTemporariosVendas(req.files);
            console.error("Erro ao criar material de vendas:", err);
            return res.status(500).json({ error: "Erro ao criar material de vendas." });
        }
    }
);

route.put(
    "/vendas/materiais/:id",
    authMiddleware,
    requireSalesMaterialsManager,
    uploadSalesMaterialManagerMiddleware,
    async (req, res) => {
        try {
            const materialId = Number(req.params.id);

            if (!Number.isInteger(materialId) || materialId <= 0) {
                removerUploadsTemporariosVendas(req.files);
                return res.status(400).json({ error: "Material inválido." });
            }

            await garantirMateriaisVendasPadrao(req.user.empresa_id, req.user.id);

            const materialAtual = await buscarMaterialVendas(materialId, req.user.empresa_id, true);

            if (!materialAtual) {
                removerUploadsTemporariosVendas(req.files);
                return res.status(404).json({ error: "Material não encontrado." });
            }

            const payload = montarPayloadMaterialVendas(req, materialAtual);

            if (!payload.title) {
                removerUploadsTemporariosVendas(req.files);
                return res.status(400).json({ error: "Informe o título do material." });
            }

            await db.query(`
                UPDATE sales_materials
                SET
                    title = ?,
                    description = ?,
                    category = ?,
                    material_type = ?,
                    cover_image_url = ?,
                    file_url = ?,
                    file_name = ?,
                    file_mime = ?,
                    file_size = ?,
                    external_url = ?,
                    display_order = ?,
                    is_active = ?,
                    updated_by = ?
                WHERE id = ?
                  AND empresa_id = ?
            `, [
                payload.title,
                payload.description,
                payload.category,
                payload.material_type,
                payload.cover_image_url,
                payload.file_url,
                payload.file_name,
                payload.file_mime,
                payload.file_size,
                payload.external_url,
                payload.display_order,
                payload.is_active,
                req.user.id,
                materialId,
                req.user.empresa_id,
            ]);

            if (payload.coverFile && materialAtual.cover_image_url) {
                removerArquivoUploadVendasPorUrl(materialAtual.cover_image_url);
            }

            if (payload.materialFile && materialAtual.file_url) {
                removerArquivoUploadVendasPorUrl(materialAtual.file_url);
            }

            const material = await buscarMaterialVendas(materialId, req.user.empresa_id, true);

            return res.json(material);
        } catch (err) {
            removerUploadsTemporariosVendas(req.files);
            console.error("Erro ao editar material de vendas:", err);
            return res.status(500).json({ error: "Erro ao editar material de vendas." });
        }
    }
);

route.post(
    "/vendas/materiais/:id/upload-capa",
    authMiddleware,
    requireSalesMaterialsManager,
    uploadSalesMaterialManagerMiddleware,
    async (req, res) => {
        try {
            const materialId = Number(req.params.id);
            const coverFile = obterArquivoUploadVendas(req, "cover_image");

            if (!Number.isInteger(materialId) || materialId <= 0) {
                removerUploadsTemporariosVendas(req.files);
                return res.status(400).json({ error: "Material inválido." });
            }

            if (!coverFile) {
                return res.status(400).json({ error: "Envie uma imagem de capa." });
            }

            await garantirMateriaisVendasPadrao(req.user.empresa_id, req.user.id);

            const materialAtual = await buscarMaterialVendas(materialId, req.user.empresa_id, true);

            if (!materialAtual) {
                removerUploadsTemporariosVendas(req.files);
                return res.status(404).json({ error: "Material não encontrado." });
            }

            const coverImageUrl = obterUrlUploadVendas("cover_image", req.user.empresa_id, coverFile.filename);

            await db.query(`
                UPDATE sales_materials
                SET cover_image_url = ?, updated_by = ?
                WHERE id = ?
                  AND empresa_id = ?
            `, [coverImageUrl, req.user.id, materialId, req.user.empresa_id]);

            if (materialAtual.cover_image_url) {
                removerArquivoUploadVendasPorUrl(materialAtual.cover_image_url);
            }

            const material = await buscarMaterialVendas(materialId, req.user.empresa_id, true);

            return res.json(material);
        } catch (err) {
            removerUploadsTemporariosVendas(req.files);
            console.error("Erro ao trocar capa do material de vendas:", err);
            return res.status(500).json({ error: "Erro ao trocar imagem de capa." });
        }
    }
);

route.delete(
    "/vendas/materiais/:id",
    authMiddleware,
    requireSalesMaterialsManager,
    async (req, res) => {
        try {
            const materialId = Number(req.params.id);

            if (!Number.isInteger(materialId) || materialId <= 0) {
                return res.status(400).json({ error: "Material inválido." });
            }

            await garantirMateriaisVendasPadrao(req.user.empresa_id, req.user.id);

            const [result] = await db.query(`
                UPDATE sales_materials
                SET is_active = 0, updated_by = ?
                WHERE id = ?
                  AND empresa_id = ?
            `, [req.user.id, materialId, req.user.empresa_id]);

            if (result.affectedRows === 0) {
                return res.status(404).json({ error: "Material não encontrado." });
            }

            const material = await buscarMaterialVendas(materialId, req.user.empresa_id, true);

            return res.json(material);
        } catch (err) {
            console.error("Erro ao desativar material de vendas:", err);
            return res.status(500).json({ error: "Erro ao desativar material." });
        }
    }
);

// ========================================
// NOTAS RÁPIDAS - ENDPOINTS
// ========================================

route.get("/notes", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaNotasRapidas();

        const [notas] = await db.query(`
            SELECT DISTINCT
                n.id,
                COALESCE(n.owner_user_id, n.user_id) AS user_id,
                COALESCE(n.owner_user_id, n.user_id) AS owner_user_id,
                owner.nome AS owner_name,
                owner.email AS owner_email,
                owner_setor.nome AS owner_setor_nome,
                CASE WHEN COALESCE(n.owner_user_id, n.user_id) = ? THEN 'owner' ELSE 'shared' END AS access_type,
                CASE
                    WHEN COALESCE(n.owner_user_id, n.user_id) = ? THEN 'owner'
                    ELSE COALESCE(ns.permission, 'view')
                END AS permission,
                n.title,
                n.content,
                n.pinned,
                n.created_at,
                n.updated_at,
                editor.id AS last_edited_by_id,
                editor.nome AS last_edited_by_name,
                editor.email AS last_edited_by_email,
                editor_setor.nome AS last_edited_by_setor_nome
            FROM notes n
            JOIN usuarios owner ON owner.id = COALESCE(n.owner_user_id, n.user_id)
            LEFT JOIN setores owner_setor ON owner_setor.id = owner.setor_id
            LEFT JOIN note_shares ns
                ON ns.note_id = n.id
               AND ns.user_id = ?
            LEFT JOIN usuarios editor ON editor.id = n.last_edited_by
            LEFT JOIN setores editor_setor ON editor_setor.id = editor.setor_id
            WHERE (COALESCE(n.owner_user_id, n.user_id) = ? OR ns.user_id = ?)
              AND owner.empresa_id = ?
              AND owner.deletado_em IS NULL
            ORDER BY n.pinned DESC, n.updated_at DESC, n.id DESC
        `, [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, req.user.empresa_id]);

        res.json(await anexarCompartilhamentosNotas(notas));
    } catch (err) {
        console.error("Erro ao buscar notas rápidas:", err);
        res.status(500).json({ error: "Erro ao buscar notas rápidas" });
    }
});

route.get("/notes/:id", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaNotasRapidas();

        const noteId = Number(req.params.id);

        if (!Number.isInteger(noteId) || noteId <= 0) {
            return res.status(400).json({ error: "Nota inválida" });
        }

        const nota = await buscarNotaRapidaPorId(noteId, req.user.id, req.user.empresa_id);

        if (!nota) {
            return res.status(404).json({ error: "Nota não encontrada" });
        }

        res.json(nota);
    } catch (err) {
        console.error("Erro ao buscar nota rápida:", err);
        res.status(500).json({ error: "Erro ao buscar nota rápida" });
    }
});

route.post("/notes", authMiddleware, async (req, res) => {
    const connection = await db.getConnection();

    try {
        await garantirTabelaNotasRapidas();

        const title = limitarTexto(req.body.title, 180);
        const content = normalizarTextoLongo(req.body.content, 20000);
        const pinned = req.body.pinned === true || req.body.pinned === "true";
        const compartilhamentos = normalizarCompartilhamentosNota(
            req.body.sharedUsers ?? req.body.sharedUserIds,
            req.user.id
        );

        if (!title) {
            return res.status(400).json({ error: "Título é obrigatório" });
        }

        if (!compartilhamentos) {
            return res.status(400).json({ error: "Lista de compartilhamento inválida" });
        }

        await connection.beginTransaction();

        const [result] = await connection.query(`
            INSERT INTO notes (user_id, owner_user_id, title, content, pinned, last_edited_by)
            VALUES (?, ?, ?, ?, ?, ?)
        `, [req.user.id, req.user.id, title, content, pinned, req.user.id]);

        await salvarCompartilhamentosNota(
            connection,
            result.insertId,
            compartilhamentos,
            req.user.empresa_id
        );

        await connection.commit();

        const nota = await buscarNotaRapidaPorId(result.insertId, req.user.id, req.user.empresa_id, true);
        const usuariosComAcesso = await listarUsuariosComAcessoNotaRapida(result.insertId);

        emitirEventoNotaRapida(req, usuariosComAcesso, {
            action: "created",
            note_id: result.insertId,
            title: nota?.title || title,
            edited_by: formatarUsuarioNota(req.user),
            updated_at: nota?.updated_at || new Date(),
        });

        res.status(201).json(nota);
    } catch (err) {
        try {
            await connection.rollback();
        } catch (rollbackErr) {
            console.error("Erro ao desfazer criação da nota rápida:", rollbackErr);
        }

        console.error("Erro ao criar nota rápida:", err);
        res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : "Erro ao criar nota rápida" });
    } finally {
        connection.release();
    }
});

route.put("/notes/:id", authMiddleware, async (req, res) => {
    const connection = await db.getConnection();

    try {
        await garantirTabelaNotasRapidas();

        const noteId = Number(req.params.id);
        const title = limitarTexto(req.body.title, 180);
        const content = normalizarTextoLongo(req.body.content, 20000);
        const deveAtualizarFixacao = Object.prototype.hasOwnProperty.call(req.body, "pinned");
        const pinned = req.body.pinned === true || req.body.pinned === "true";
        const deveAtualizarCompartilhamentos = (
            Object.prototype.hasOwnProperty.call(req.body, "sharedUsers")
            || Object.prototype.hasOwnProperty.call(req.body, "sharedUserIds")
        );
        const compartilhamentos = deveAtualizarCompartilhamentos
            ? normalizarCompartilhamentosNota(
                req.body.sharedUsers ?? req.body.sharedUserIds,
                req.user.id
            )
            : [];

        if (!Number.isInteger(noteId) || noteId <= 0) {
            return res.status(400).json({ error: "Nota inválida" });
        }

        if (!title) {
            return res.status(400).json({ error: "Título é obrigatório" });
        }

        if (deveAtualizarCompartilhamentos && !compartilhamentos) {
            return res.status(400).json({ error: "Lista de compartilhamento inválida" });
        }

        await connection.beginTransaction();

        const acessoNota = await buscarAcessoNotaRapida(
            connection,
            noteId,
            req.user.id,
            req.user.empresa_id
        );

        if (!acessoNota?.has_access) {
            await connection.rollback();
            return res.status(404).json({ error: "Nota não encontrada" });
        }

        if (!acessoNota.can_edit) {
            await connection.rollback();
            return res.status(403).json({ error: "Você tem acesso apenas para visualizar esta nota." });
        }

        if (!acessoNota.can_manage && (deveAtualizarCompartilhamentos || deveAtualizarFixacao)) {
            await connection.rollback();
            return res.status(403).json({
                error: "Apenas o dono da nota pode alterar fixação ou compartilhamentos.",
            });
        }

        const usuariosAntes = await listarUsuariosComAcessoNotaRapida(noteId, connection);
        const pinnedFinal = acessoNota.can_manage && deveAtualizarFixacao
            ? pinned
            : Boolean(acessoNota.pinned);

        await connection.query(`
            UPDATE notes
            SET title = ?,
                content = ?,
                pinned = ?,
                last_edited_by = ?,
                updated_at = NOW()
            WHERE id = ?
        `, [title, content, pinnedFinal, req.user.id, noteId]);

        if (deveAtualizarCompartilhamentos) {
            await salvarCompartilhamentosNota(
                connection,
                noteId,
                compartilhamentos,
                req.user.empresa_id
            );
        }

        await connection.commit();

        const nota = await buscarNotaRapidaPorId(noteId, req.user.id, req.user.empresa_id);
        const usuariosDepois = await listarUsuariosComAcessoNotaRapida(noteId);
        const usuariosNotificacao = [...new Set([...usuariosAntes, ...usuariosDepois])];

        emitirEventoNotaRapida(req, usuariosNotificacao, {
            action: "updated",
            note_id: noteId,
            title: nota?.title || title,
            edited_by: formatarUsuarioNota(req.user),
            updated_at: nota?.updated_at || new Date(),
        });

        res.json(nota);
    } catch (err) {
        try {
            await connection.rollback();
        } catch (rollbackErr) {
            console.error("Erro ao desfazer edição da nota rápida:", rollbackErr);
        }

        console.error("Erro ao editar nota rápida:", err);
        res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : "Erro ao editar nota rápida" });
    } finally {
        connection.release();
    }
});

route.delete("/notes/:id", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaNotasRapidas();

        const noteId = Number(req.params.id);

        if (!Number.isInteger(noteId) || noteId <= 0) {
            return res.status(400).json({ error: "Nota inválida" });
        }

        const acessoNota = await buscarAcessoNotaRapida(db, noteId, req.user.id, req.user.empresa_id);

        if (!acessoNota?.has_access) {
            return res.status(404).json({ error: "Nota não encontrada" });
        }

        if (!acessoNota.can_manage) {
            return res.status(403).json({ error: "Apenas o dono pode excluir esta nota." });
        }

        const usuariosComAcesso = await listarUsuariosComAcessoNotaRapida(noteId);

        const [result] = await db.query(`
            DELETE FROM notes
            WHERE id = ? AND COALESCE(owner_user_id, user_id) = ?
        `, [noteId, req.user.id]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Nota não encontrada" });
        }

        emitirEventoNotaRapida(req, usuariosComAcesso, {
            action: "deleted",
            note_id: noteId,
            edited_by: formatarUsuarioNota(req.user),
            updated_at: new Date(),
        });

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao excluir nota rápida:", err);
        res.status(500).json({ error: "Erro ao excluir nota rápida" });
    }
});

route.patch("/notes/:id/pin", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaNotasRapidas();

        const noteId = Number(req.params.id);

        if (!Number.isInteger(noteId) || noteId <= 0) {
            return res.status(400).json({ error: "Nota inválida" });
        }

        const acessoNota = await buscarAcessoNotaRapida(db, noteId, req.user.id, req.user.empresa_id);

        if (!acessoNota?.has_access) {
            return res.status(404).json({ error: "Nota não encontrada" });
        }

        if (!acessoNota.can_manage) {
            return res.status(403).json({ error: "Apenas o dono pode fixar esta nota." });
        }

        const pinned = req.body.pinned === undefined
            ? !Boolean(acessoNota.pinned)
            : req.body.pinned === true || req.body.pinned === "true";

        await db.query(`
            UPDATE notes
            SET pinned = ?,
                last_edited_by = ?,
                updated_at = NOW()
            WHERE id = ? AND COALESCE(owner_user_id, user_id) = ?
        `, [pinned, req.user.id, noteId, req.user.id]);

        const nota = await buscarNotaRapidaPorId(noteId, req.user.id, req.user.empresa_id, true);
        const usuariosComAcesso = await listarUsuariosComAcessoNotaRapida(noteId);

        emitirEventoNotaRapida(req, usuariosComAcesso, {
            action: "updated",
            note_id: noteId,
            title: nota?.title || null,
            edited_by: formatarUsuarioNota(req.user),
            updated_at: nota?.updated_at || new Date(),
        });

        res.json(nota);
    } catch (err) {
        console.error("Erro ao fixar nota rápida:", err);
        res.status(500).json({ error: "Erro ao fixar nota rápida" });
    }
});

// ========================================
// SOLICITAÇÕES INTERNAS - ENDPOINTS
// ========================================

const buscarSolicitacaoInternaPorId = async (id, empresaId) => {
    const [rows] = await db.query(`
        SELECT
            si.*,
            u.nome AS usuario_nome,
            u.email AS usuario_email,
            s.nome AS usuario_setor_nome,
            responsavel.nome AS respondido_por_nome,
            responsavel_criacao.nome AS responsavel_criacao_nome,
            responsavel_execucao.nome AS responsavel_execucao_nome,
            concluido.nome AS concluido_por_nome
        FROM solicitacoes_internas si
        JOIN usuarios u ON u.id = si.usuario_id
        LEFT JOIN setores s ON s.id = u.setor_id
        LEFT JOIN usuarios responsavel ON responsavel.id = si.respondido_por
        LEFT JOIN usuarios responsavel_criacao ON responsavel_criacao.id = si.responsavel_criacao_id
        LEFT JOIN usuarios responsavel_execucao ON responsavel_execucao.id = si.responsavel_execucao_id
        LEFT JOIN usuarios concluido ON concluido.id = si.concluido_por
        WHERE si.id = ?
          AND si.empresa_id = ?
        LIMIT 1
    `, [id, empresaId]);

    return rows[0] ? formatarSolicitacaoInterna(rows[0]) : null;
};

const listarUsuariosSolicitacoesInternas = async (empresaId) => {
    const [rows] = await db.query(`
        SELECT
            u.id,
            u.nome,
            u.email,
            s.nome AS setor
        FROM usuarios u
        LEFT JOIN setores s ON s.id = u.setor_id
        WHERE u.empresa_id = ?
          AND u.deletado_em IS NULL
        ORDER BY u.nome ASC
    `, [empresaId]);

    return rows.map((usuario) => ({
        id: usuario.id,
        nome: usuario.nome,
        email: usuario.email || "",
        setor: usuario.setor || "",
    }));
};

const montarOpcoesSolicitacoesInternas = async (empresaId) => ({
    setores: SOLICITACOES_INTERNAS_SETORES,
    tipos: SOLICITACOES_INTERNAS_TIPOS,
    prioridades: SOLICITACOES_INTERNAS_PRIORIDADES,
    status: SOLICITACOES_INTERNAS_STATUS,
    limite_anexo_mb: INTERNAL_REQUEST_UPLOAD_MAX_SIZE_MB,
    usuarios: await listarUsuariosSolicitacoesInternas(empresaId),
});

route.get("/internal-requests", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaSolicitacoesInternas();

        const podeGerenciar = usuarioPodeGerenciarSolicitacoesInternas(req.user);
        const statusFiltro = req.query.status
            ? normalizarStatusSolicitacaoInterna(req.query.status, "")
            : "";
        const params = [req.user.empresa_id];
        const filtros = ["si.empresa_id = ?"];

        if (!podeGerenciar) {
            filtros.push(`(
                si.usuario_id = ?
                OR si.responsavel_criacao_id = ?
                OR si.responsavel_execucao_id = ?
            )`);
            params.push(req.user.id, req.user.id, req.user.id);
        }

        if (statusFiltro) {
            filtros.push("si.status = ?");
            params.push(statusFiltro);
        }

        const [rows] = await db.query(`
            SELECT
                si.*,
                u.nome AS usuario_nome,
                u.email AS usuario_email,
                s.nome AS usuario_setor_nome,
                responsavel.nome AS respondido_por_nome,
                responsavel_criacao.nome AS responsavel_criacao_nome,
                responsavel_execucao.nome AS responsavel_execucao_nome,
                concluido.nome AS concluido_por_nome
            FROM solicitacoes_internas si
            JOIN usuarios u ON u.id = si.usuario_id
            LEFT JOIN setores s ON s.id = u.setor_id
            LEFT JOIN usuarios responsavel ON responsavel.id = si.respondido_por
            LEFT JOIN usuarios responsavel_criacao ON responsavel_criacao.id = si.responsavel_criacao_id
            LEFT JOIN usuarios responsavel_execucao ON responsavel_execucao.id = si.responsavel_execucao_id
            LEFT JOIN usuarios concluido ON concluido.id = si.concluido_por
            WHERE ${filtros.join(" AND ")}
            ORDER BY
                FIELD(si.status, 'aberto', 'em_andamento', 'aguardando_retorno', 'resolvido', 'cancelado'),
                si.atualizado_em DESC,
                si.id DESC
            LIMIT 500
        `, params);

        res.json({
            can_manage: podeGerenciar,
            options: await montarOpcoesSolicitacoesInternas(req.user.empresa_id),
            requests: rows.map(formatarSolicitacaoInterna),
        });
    } catch (err) {
        console.error("Erro ao listar solicitações internas:", err);
        res.status(500).json({ error: "Erro ao listar solicitações internas." });
    }
});

route.post(
    "/internal-requests",
    authMiddleware,
    uploadInternalRequestMiddleware,
    async (req, res) => {
        try {
            await garantirTabelaSolicitacoesInternas();

            const empresaId = req.user.empresa_id;
            const usuarioId = req.user.id;
            const setor = normalizarOpcaoSolicitacaoInterna(
                req.body.setor,
                SOLICITACOES_INTERNAS_SETORES,
                "Outro"
            );
            const tipo = normalizarOpcaoSolicitacaoInterna(
                req.body.tipo,
                SOLICITACOES_INTERNAS_TIPOS,
                "Outro"
            );
            const prioridade = normalizarPrioridadeSolicitacaoInterna(req.body.prioridade);
            const titulo = limitarTexto(req.body.titulo, 180);
            const descricao = normalizarTextoLongo(req.body.descricao, 5000);
            const responsavelCriacaoId = await obterUsuarioResponsavelSolicitacaoInterna(
                req.body.responsavel_criacao_id,
                empresaId
            );
            const responsavelExecucaoId = await obterUsuarioResponsavelSolicitacaoInterna(
                req.body.responsavel_execucao_id,
                empresaId
            );

            if (!titulo || !descricao) {
                removerArquivoSolicitacaoInterna(req.file);
                return res.status(400).json({
                    error: "Informe o título e a descrição da solicitação.",
                });
            }

            const anexoUrl = req.file
                ? `/uploads/solicitacoes/${normalizarSegmentoUpload(empresaId)}/${req.file.filename}`
                : null;

            const [result] = await db.query(`
                INSERT INTO solicitacoes_internas (
                    empresa_id,
                    usuario_id,
                    setor,
                    tipo,
                    prioridade,
                    titulo,
                    descricao,
                    responsavel_criacao_id,
                    responsavel_execucao_id,
                    status,
                    anexo_url,
                    anexo_nome,
                    anexo_mime,
                    anexo_tamanho
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'aberto', ?, ?, ?, ?)
            `, [
                empresaId,
                usuarioId,
                setor,
                tipo,
                prioridade,
                titulo,
                descricao,
                responsavelCriacaoId,
                responsavelExecucaoId,
                anexoUrl,
                req.file?.originalname || null,
                req.file?.mimetype || null,
                req.file?.size || null,
            ]);

            const solicitacao = await buscarSolicitacaoInternaPorId(result.insertId, empresaId);

            res.status(201).json(solicitacao);
        } catch (err) {
            removerArquivoSolicitacaoInterna(req.file);
            console.error("Erro ao criar solicitação interna:", err);
            res.status(err.statusCode || 500).json({
                error: err.statusCode ? err.message : "Erro ao criar solicitação interna.",
            });
        }
    }
);

route.patch("/internal-requests/:id", authMiddleware, async (req, res) => {
    try {
        if (!usuarioPodeGerenciarSolicitacoesInternas(req.user)) {
            return res.status(403).json({ error: "Acesso restrito aos responsáveis." });
        }

        await garantirTabelaSolicitacoesInternas();

        const solicitacaoId = Number(req.params.id);

        if (!Number.isInteger(solicitacaoId) || solicitacaoId <= 0) {
            return res.status(400).json({ error: "Solicitação inválida." });
        }

        const atual = await buscarSolicitacaoInternaPorId(solicitacaoId, req.user.empresa_id);

        if (!atual) {
            return res.status(404).json({ error: "Solicitação não encontrada." });
        }

        const status = normalizarStatusSolicitacaoInterna(req.body.status, atual.status);
        const resposta = Object.prototype.hasOwnProperty.call(req.body, "resposta")
            ? normalizarTextoLongo(req.body.resposta, 5000)
            : atual.resposta;
        const responsavelCriacaoId = Object.prototype.hasOwnProperty.call(req.body, "responsavel_criacao_id")
            ? await obterUsuarioResponsavelSolicitacaoInterna(req.body.responsavel_criacao_id, req.user.empresa_id)
            : (atual.responsavel_criacao?.id || null);
        const responsavelExecucaoId = Object.prototype.hasOwnProperty.call(req.body, "responsavel_execucao_id")
            ? await obterUsuarioResponsavelSolicitacaoInterna(req.body.responsavel_execucao_id, req.user.empresa_id)
            : (atual.responsavel_execucao?.id || null);
        const respostaAlterada = resposta !== atual.resposta;

        await db.query(`
            UPDATE solicitacoes_internas
            SET
                status = ?,
                resposta = ?,
                responsavel_criacao_id = ?,
                responsavel_execucao_id = ?,
                concluido_por = CASE
                    WHEN ? <> 'resolvido' THEN NULL
                    ELSE concluido_por
                END,
                concluido_em = CASE
                    WHEN ? <> 'resolvido' THEN NULL
                    ELSE concluido_em
                END,
                respondido_por = CASE
                    WHEN ? THEN ?
                    ELSE respondido_por
                END,
                respondido_em = CASE
                    WHEN ? THEN NOW()
                    ELSE respondido_em
                END
            WHERE id = ?
              AND empresa_id = ?
        `, [
            status,
            resposta,
            responsavelCriacaoId,
            responsavelExecucaoId,
            status,
            status,
            respostaAlterada && Boolean(resposta),
            req.user.id,
            respostaAlterada && Boolean(resposta),
            solicitacaoId,
            req.user.empresa_id,
        ]);

        const solicitacao = await buscarSolicitacaoInternaPorId(solicitacaoId, req.user.empresa_id);

        res.json(solicitacao);
    } catch (err) {
        console.error("Erro ao atualizar solicitação interna:", err);
        res.status(err.statusCode || 500).json({
            error: err.statusCode ? err.message : "Erro ao atualizar solicitação interna.",
        });
    }
});

route.patch("/internal-requests/:id/complete", authMiddleware, async (req, res) => {
    try {
        await garantirTabelaSolicitacoesInternas();

        const solicitacaoId = Number(req.params.id);

        if (!Number.isInteger(solicitacaoId) || solicitacaoId <= 0) {
            return res.status(400).json({ error: "Solicitação inválida." });
        }

        const atual = await buscarSolicitacaoInternaPorId(solicitacaoId, req.user.empresa_id);

        if (!atual) {
            return res.status(404).json({ error: "Solicitação não encontrada." });
        }

        if (atual.status === "cancelado") {
            return res.status(400).json({ error: "Solicitação cancelada não pode ser concluída." });
        }

        const responsavelExecucaoId = Number(atual.responsavel_execucao?.id || 0);
        const podeConcluir = responsavelExecucaoId === Number(req.user.id)
            || usuarioPodeGerenciarSolicitacoesInternas(req.user);

        if (!podeConcluir) {
            return res.status(403).json({
                error: "Apenas o responsável por realizar esta solicitação pode concluir.",
            });
        }

        await db.query(`
            UPDATE solicitacoes_internas
            SET
                status = 'resolvido',
                concluido_por = ?,
                concluido_em = NOW()
            WHERE id = ?
              AND empresa_id = ?
        `, [req.user.id, solicitacaoId, req.user.empresa_id]);

        const solicitacao = await buscarSolicitacaoInternaPorId(solicitacaoId, req.user.empresa_id);

        res.json(solicitacao);
    } catch (err) {
        console.error("Erro ao concluir solicitação interna:", err);
        res.status(500).json({ error: "Erro ao concluir solicitação interna." });
    }
});

// ========================================
// TEXTOS PARA ATENDIMENTO - ENDPOINTS
// ========================================

const listarBibliotecaConteudo = async (config, empresaId, incluirInativos = false) => {
    await garantirTabelaBibliotecaConteudo(config);
    await garantirBibliotecaConteudoPadrao(config, empresaId);

    const filtroAtivo = incluirInativos ? "" : "AND t.is_active = 1";
    const [rows] = await db.query(`
        SELECT
            t.id,
            t.title,
            t.content,
            t.is_active,
            t.sort_order,
            t.created_by,
            criado.nome AS created_by_name,
            t.updated_by,
            atualizado.nome AS updated_by_name,
            t.created_at,
            t.updated_at
        FROM ${config.tableName} t
        LEFT JOIN usuarios criado ON criado.id = t.created_by
        LEFT JOIN usuarios atualizado ON atualizado.id = t.updated_by
        WHERE t.empresa_id = ?
          ${filtroAtivo}
        ORDER BY t.sort_order ASC, t.title ASC, t.id ASC
    `, [empresaId]);

    return rows.map(formatarTextoAtendimento);
};

const buscarBibliotecaConteudoAdmin = async (config, id, empresaId) => {
    await garantirTabelaBibliotecaConteudo(config);

    const [rows] = await db.query(`
        SELECT
            t.id,
            t.title,
            t.content,
            t.is_active,
            t.sort_order,
            t.created_by,
            criado.nome AS created_by_name,
            t.updated_by,
            atualizado.nome AS updated_by_name,
            t.created_at,
            t.updated_at
        FROM ${config.tableName} t
        LEFT JOIN usuarios criado ON criado.id = t.created_by
        LEFT JOIN usuarios atualizado ON atualizado.id = t.updated_by
        WHERE t.id = ?
          AND t.empresa_id = ?
        LIMIT 1
    `, [id, empresaId]);

    return rows[0] ? formatarTextoAtendimento(rows[0]) : null;
};

const listarTextosAtendimento = async (empresaId, incluirInativos = false) => (
    listarBibliotecaConteudo(TEXTOS_ATENDIMENTO_LIBRARY, empresaId, incluirInativos)
);

const buscarTextoAtendimentoAdmin = async (id, empresaId) => (
    buscarBibliotecaConteudoAdmin(TEXTOS_ATENDIMENTO_LIBRARY, id, empresaId)
);

const listarBoasPraticasAtendimento = async (empresaId, incluirInativos = false) => (
    listarBibliotecaConteudo(BOAS_PRATICAS_ATENDIMENTO_LIBRARY, empresaId, incluirInativos)
);

const buscarBoaPraticaAtendimentoAdmin = async (id, empresaId) => (
    buscarBibliotecaConteudoAdmin(BOAS_PRATICAS_ATENDIMENTO_LIBRARY, id, empresaId)
);

const normalizarTextoBuscaGlobal = (valor = "") => (
    String(valor || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
);

const limparHtmlBuscaGlobal = (valor = "") => (
    String(valor || "")
        .replace(/<style[\s\S]*?>[\s\S]*?<\/style>/gi, " ")
        .replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, " ")
        .replace(/<[^>]+>/g, " ")
        .replace(/&nbsp;/gi, " ")
        .replace(/&amp;/gi, "&")
        .replace(/&lt;/gi, "<")
        .replace(/&gt;/gi, ">")
        .replace(/\s+/g, " ")
        .trim()
);

const extrairTextosBuscaGlobal = (valor, textos = []) => {
    if (valor === null || valor === undefined) return textos;

    if (["string", "number", "boolean"].includes(typeof valor)) {
        const texto = limparHtmlBuscaGlobal(valor);
        if (texto) textos.push(texto);
        return textos;
    }

    if (Array.isArray(valor)) {
        valor.forEach((item) => extrairTextosBuscaGlobal(item, textos));
        return textos;
    }

    if (typeof valor === "object") {
        Object.values(valor).forEach((item) => extrairTextosBuscaGlobal(item, textos));
    }

    return textos;
};

const contemBuscaGlobal = (valor, termoNormalizado) => (
    normalizarTextoBuscaGlobal(
        Array.isArray(valor) ? valor.join(" ") : valor
    ).includes(termoNormalizado)
);

const criarSnippetBuscaGlobal = (valor, termo = "", tamanho = 220) => {
    const texto = limparHtmlBuscaGlobal(valor);

    if (!texto) return "";

    const termoNormalizado = normalizarTextoBuscaGlobal(termo);
    const textoNormalizado = normalizarTextoBuscaGlobal(texto);
    const indice = termoNormalizado ? textoNormalizado.indexOf(termoNormalizado) : -1;
    const inicio = indice > 48 ? indice - 48 : 0;
    const fim = Math.min(texto.length, inicio + tamanho);
    const prefixo = inicio > 0 ? "..." : "";
    const sufixo = fim < texto.length ? "..." : "";

    return `${prefixo}${texto.slice(inicio, fim).trim()}${sufixo}`;
};

const normalizarTermoBuscaGlobal = (valor = "") => (
    String(valor || "")
        .trim()
        .replace(/\s+/g, " ")
        .slice(0, 100)
);

const normalizarLimiteBuscaGlobal = (valor) => {
    const numero = Number.parseInt(valor, 10);

    if (!Number.isFinite(numero)) return 12;

    return Math.min(25, Math.max(5, numero));
};

const criarSecaoBuscaGlobal = (id, label, results) => ({
    id,
    label,
    total: results.length,
    results,
});

const mapearResultadoBibliotecaGlobal = ({
    item,
    termo,
    source,
    sourceLabel,
    url,
}) => ({
    id: `${source}-${item.id}`,
    source,
    source_label: sourceLabel,
    title: item.title,
    subtitle: sourceLabel,
    snippet: criarSnippetBuscaGlobal(`${item.title}\n${item.content}`, termo),
    url,
    date: item.updated_at || item.created_at || null,
});

const buscarBibliotecaConteudoGlobal = async ({
    config,
    empresaId,
    termo,
    limite,
    source,
    sourceLabel,
    url,
}) => {
    await garantirBibliotecaConteudoPadrao(config, empresaId);

    const termoLike = `%${termo}%`;
    const [rows] = await db.query(`
        SELECT id, title, content, created_at, updated_at
        FROM ${config.tableName}
        WHERE empresa_id = ?
          AND is_active = 1
          AND (title LIKE ? OR content LIKE ?)
        ORDER BY sort_order ASC, updated_at DESC, id ASC
        LIMIT ?
    `, [empresaId, termoLike, termoLike, limite]);

    return rows.map((item) => mapearResultadoBibliotecaGlobal({
        item,
        termo,
        source,
        sourceLabel,
        url: `${url}?busca=${encodeURIComponent(termo)}&item=${item.id}`,
    }));
};

const buscarMensagensGlobal = async ({ userId, empresaId, termo, limite }) => {
    await garantirTabelaMensagensOcultas();
    await garantirTabelaLeiturasMensagens();

    const termoLike = `%${termo}%`;

    const [diretas] = await db.query(`
        SELECT
            m.id,
            m.mensagem,
            m.tipo_mensagem,
            m.anexo_nome,
            m.criada_em,
            remetente.nome AS remetente_nome,
            outro.id AS usuario_outro_id,
            outro.nome AS usuario_outro_nome
        FROM mensagens m
        JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id
        JOIN usuarios remetente ON remetente.id = m.remetente_id
        JOIN usuarios outro ON outro.id = CASE
            WHEN cd.usuario1_id = ? THEN cd.usuario2_id
            ELSE cd.usuario1_id
        END
        WHERE outro.empresa_id = ?
          AND outro.deletado_em IS NULL
          AND (cd.usuario1_id = ? OR cd.usuario2_id = ?)
          AND m.deletada_em IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM mensagens_ocultas_usuario mou
              WHERE mou.mensagem_id = m.id
                AND mou.usuario_id = ?
          )
          AND (
              (m.tipo_mensagem = 'texto' AND m.mensagem LIKE ?)
              OR m.anexo_nome LIKE ?
          )
        ORDER BY m.criada_em DESC, m.id DESC
        LIMIT ?
    `, [userId, empresaId, userId, userId, userId, termoLike, termoLike, limite]);

    const [grupos] = await db.query(`
        SELECT
            m.id,
            m.mensagem,
            m.tipo_mensagem,
            m.anexo_nome,
            m.criada_em,
            remetente.nome AS remetente_nome,
            g.id AS grupo_id,
            g.nome AS grupo_nome
        FROM mensagens m
        JOIN grupos g ON g.id = m.grupo_id
        JOIN grupo_membros gm ON gm.grupo_id = g.id AND gm.usuario_id = ?
        JOIN usuarios remetente ON remetente.id = m.remetente_id
        WHERE g.empresa_id = ?
          AND g.deletado_em IS NULL
          AND m.deletada_em IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM mensagens_ocultas_usuario mou
              WHERE mou.mensagem_id = m.id
                AND mou.usuario_id = ?
          )
          AND (
              (m.tipo_mensagem = 'texto' AND m.mensagem LIKE ?)
              OR m.anexo_nome LIKE ?
          )
        ORDER BY m.criada_em DESC, m.id DESC
        LIMIT ?
    `, [userId, empresaId, userId, termoLike, termoLike, limite]);

    return [
        ...diretas.map((mensagem) => ({
            id: `mensagem-direta-${mensagem.id}`,
            source: "messages",
            source_label: "Mensagens",
            title: `Conversa com ${mensagem.usuario_outro_nome}`,
            subtitle: `Mensagem de ${mensagem.remetente_nome}`,
            snippet: criarSnippetBuscaGlobal(
                mensagem.tipo_mensagem === "texto"
                    ? mensagem.mensagem
                    : mensagem.anexo_nome || "[Arquivo]",
                termo
            ),
            url: `/chat?conversa=${mensagem.usuario_outro_id}&mensagem=${mensagem.id}`,
            date: mensagem.criada_em,
            meta: {
                chat_type: "direta",
                message_id: mensagem.id,
                user_id: mensagem.usuario_outro_id,
            },
        })),
        ...grupos.map((mensagem) => ({
            id: `mensagem-grupo-${mensagem.id}`,
            source: "messages",
            source_label: "Mensagens",
            title: mensagem.grupo_nome,
            subtitle: `Mensagem de ${mensagem.remetente_nome}`,
            snippet: criarSnippetBuscaGlobal(
                mensagem.tipo_mensagem === "texto"
                    ? mensagem.mensagem
                    : mensagem.anexo_nome || "[Arquivo]",
                termo
            ),
            url: `/chat?grupo=${mensagem.grupo_id}&mensagem=${mensagem.id}`,
            date: mensagem.criada_em,
            meta: {
                chat_type: "grupo",
                message_id: mensagem.id,
                group_id: mensagem.grupo_id,
            },
        })),
    ]
        .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
        .slice(0, limite);
};

const buscarAvisosInternosGlobal = async ({ empresaId, termo, limite }) => {
    const termoNormalizado = normalizarTextoBuscaGlobal(termo);
    const { conteudo, atualizado_em } = await buscarConteudoAvisosInternos(empresaId);
    const resultados = [];
    const adicionarSeCombinar = ({ id, title, subtitle, content, url = "/avisos-internos" }) => {
        const textos = extrairTextosBuscaGlobal({ title, subtitle, content });

        if (!contemBuscaGlobal(textos, termoNormalizado)) return;

        resultados.push({
            id: `avisos-${id}`,
            source: "internal_announcements",
            source_label: "Avisos Internos",
            title,
            subtitle,
            snippet: criarSnippetBuscaGlobal(textos.join(" "), termo),
            url,
            date: atualizado_em,
        });
    };

    adicionarSeCombinar({
        id: "cabecalho",
        title: conteudo.titulo,
        subtitle: "Avisos Internos",
        content: `${conteudo.kicker} ${conteudo.subtitulo}`,
    });

    (conteudo.resumo || []).forEach((item) => adicionarSeCombinar({
        id: `resumo-${item.id}`,
        title: item.valor || item.rotulo,
        subtitle: "Resumo dos avisos",
        content: `${item.rotulo} ${item.valor}`,
    }));

    (conteudo.comunicados || []).forEach((item) => adicionarSeCombinar({
        id: `comunicado-${item.id}`,
        title: item.titulo,
        subtitle: `${item.tipo || "Comunicado"}${item.status ? ` • ${item.status}` : ""}`,
        content: `${item.descricao} ${item.data}`,
    }));

    adicionarSeCombinar({
        id: "meta",
        title: conteudo.meta?.titulo,
        subtitle: conteudo.meta?.selo || "Meta",
        content: `${conteudo.meta?.texto || ""} ${conteudo.meta?.progresso_label || ""}`,
    });

    (conteudo.wiki?.itens || []).forEach((item) => adicionarSeCombinar({
        id: `wiki-${item.id}`,
        title: item.titulo,
        subtitle: item.categoria || conteudo.wiki?.titulo || "Wiki",
        content: item.descricao,
        url: "/wiki",
    }));

    return resultados.slice(0, limite);
};

const buscarWikiGlobal = async ({ empresaId, termo, limite }) => {
    const termoNormalizado = normalizarTextoBuscaGlobal(termo);
    const { conteudo, atualizado_em } = await buscarConteudoWikiInterna(empresaId);
    const resultados = [];
    const urlsAdicionadas = new Set();
    const titulosCursos = new Map();

    const adicionar = (resultado) => {
        if (!resultado?.title || !resultado?.url) return;

        const chave = `${resultado.url}-${resultado.title}`;
        if (urlsAdicionadas.has(chave)) return;

        urlsAdicionadas.add(chave);
        resultados.push({
            source: "wiki",
            source_label: "Wiki",
            date: atualizado_em,
            ...resultado,
        });
    };

    (conteudo.categorias || []).forEach((categoria) => {
        const textosCategoria = extrairTextosBuscaGlobal({
            titulo: categoria.titulo,
            subtitulo: categoria.subtitulo,
        });

        if (contemBuscaGlobal(textosCategoria, termoNormalizado)) {
            adicionar({
                id: `wiki-categoria-${categoria.id}`,
                title: categoria.titulo,
                subtitle: "Categoria da Wiki",
                snippet: criarSnippetBuscaGlobal(textosCategoria.join(" "), termo),
                url: `/wiki/${categoria.id}`,
            });
        }

        (categoria.cursos || []).forEach((curso) => {
            titulosCursos.set(curso.id, curso.titulo);
            const textosCurso = extrairTextosBuscaGlobal(curso);

            if (!contemBuscaGlobal(textosCurso, termoNormalizado)) return;

            adicionar({
                id: `wiki-curso-${curso.id}`,
                title: curso.titulo,
                subtitle: categoria.titulo,
                snippet: criarSnippetBuscaGlobal(textosCurso.join(" "), termo),
                url: `/wiki/curso/${curso.id}`,
            });
        });
    });

    await garantirWikiCursosConfigTabela();
    await garantirWikiAulasConfigTabela();

    const termoLike = `%${termo}%`;
    const [configsCursos] = await db.query(`
        SELECT curso_id, conteudo_json, atualizado_em
        FROM wiki_cursos_config
        WHERE empresa_id = ?
          AND (curso_id LIKE ? OR conteudo_json LIKE ?)
        ORDER BY atualizado_em DESC
        LIMIT ?
    `, [empresaId, termoLike, termoLike, limite]);

    configsCursos.forEach((row) => {
        let config = { modules: [] };

        try {
            config = normalizarConfigWikiCurso(JSON.parse(row.conteudo_json || "{}"));
        } catch {
            config = { modules: [] };
        }

        config.modules.forEach((modulo) => {
            const textosModulo = extrairTextosBuscaGlobal({
                title: modulo.title,
                description: modulo.description,
            });

            if (contemBuscaGlobal(textosModulo, termoNormalizado)) {
                adicionar({
                    id: `wiki-modulo-${row.curso_id}-${modulo.id}`,
                    title: modulo.title,
                    subtitle: titulosCursos.get(row.curso_id) || row.curso_id,
                    snippet: criarSnippetBuscaGlobal(textosModulo.join(" "), termo),
                    url: `/wiki/curso/${row.curso_id}`,
                    date: row.atualizado_em,
                });
            }

            (modulo.lessons || []).forEach((aula) => {
                const textosAula = extrairTextosBuscaGlobal(aula);

                if (!contemBuscaGlobal(textosAula, termoNormalizado)) return;

                adicionar({
                    id: `wiki-aula-${row.curso_id}-${aula.slug}`,
                    title: aula.title,
                    subtitle: `${titulosCursos.get(row.curso_id) || row.curso_id} • ${modulo.title}`,
                    snippet: criarSnippetBuscaGlobal(textosAula.join(" "), termo),
                    url: `/wiki/curso/${row.curso_id}/aula/${aula.slug}`,
                    date: row.atualizado_em,
                });
            });
        });
    });

    const [configsAulas] = await db.query(`
        SELECT curso_id, aula_chave, conteudo_json, atualizado_em
        FROM wiki_aulas_config
        WHERE empresa_id = ?
          AND (curso_id LIKE ? OR aula_chave LIKE ? OR conteudo_json LIKE ?)
        ORDER BY atualizado_em DESC
        LIMIT ?
    `, [empresaId, termoLike, termoLike, termoLike, limite]);

    configsAulas.forEach((row) => {
        let conteudoAula = {};

        try {
            conteudoAula = JSON.parse(row.conteudo_json || "{}");
        } catch {
            conteudoAula = {};
        }

        const textosAula = extrairTextosBuscaGlobal(conteudoAula);

        if (!contemBuscaGlobal([row.aula_chave, ...textosAula], termoNormalizado)) return;

        adicionar({
            id: `wiki-conteudo-aula-${row.curso_id}-${row.aula_chave}`,
            title: conteudoAula.title || row.aula_chave,
            subtitle: titulosCursos.get(row.curso_id) || row.curso_id,
            snippet: criarSnippetBuscaGlobal(textosAula.join(" "), termo),
            url: `/wiki/curso/${row.curso_id}/aula/${row.aula_chave}`,
            date: row.atualizado_em,
        });
    });

    return resultados
        .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
        .slice(0, limite);
};

const buscarDuvidasRespondidasGlobal = async ({ empresaId, termo, limite }) => {
    await garantirFeedbacksTabela();

    const termoLike = `%${termo}%`;
    const [rows] = await db.query(`
        SELECT
            f.id,
            f.nome,
            f.setor,
            f.descricao,
            f.resposta,
            f.resolvido_em,
            f.updated_at,
            ru.nome AS resolvido_por_nome
        FROM feedbacks f
        LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
        WHERE f.empresa_id = ?
          AND f.tipo = 'pergunta'
          AND f.pagina = ?
          AND f.status = 'resolvido'
          AND NULLIF(TRIM(COALESCE(f.resposta, '')), '') IS NOT NULL
          AND (
              f.nome LIKE ?
              OR f.setor LIKE ?
              OR f.descricao LIKE ?
              OR f.resposta LIKE ?
              OR ru.nome LIKE ?
          )
        ORDER BY COALESCE(f.resolvido_em, f.updated_at) DESC, f.created_at DESC, f.id DESC
        LIMIT ?
    `, [
        empresaId,
        BOAS_PRATICAS_DUVIDAS_PAGINA,
        termoLike,
        termoLike,
        termoLike,
        termoLike,
        termoLike,
        limite,
    ]);

    return rows.map((item) => ({
        id: `duvida-respondida-${item.id}`,
        source: "best_practices",
        source_label: "Boas Práticas",
        title: item.descricao,
        subtitle: item.setor ? `Dúvida respondida • ${item.setor}` : "Dúvida respondida",
        snippet: criarSnippetBuscaGlobal(`${item.descricao}\n${item.resposta}`, termo),
        url: `/boas-praticas-duvidas?busca=${encodeURIComponent(termo)}#pergunta-${item.id}`,
        date: item.resolvido_em || item.updated_at,
    }));
};

route.get("/search/global", authMiddleware, async (req, res) => {
    try {
        const termo = normalizarTermoBuscaGlobal(req.query.q || req.query.busca || "");
        const limite = normalizarLimiteBuscaGlobal(req.query.limit);

        if (termo.length < 2) {
            return res.json({
                query: termo,
                total: 0,
                sections: [
                    criarSecaoBuscaGlobal("messages", "Mensagens", []),
                    criarSecaoBuscaGlobal("wiki", "Wiki", []),
                    criarSecaoBuscaGlobal("attendance_texts", "Textos para Atendimento", []),
                    criarSecaoBuscaGlobal("internal_announcements", "Avisos Internos", []),
                    criarSecaoBuscaGlobal("best_practices", "Boas Práticas", []),
                ],
            });
        }

        const contexto = {
            userId: req.user.id,
            empresaId: req.user.empresa_id,
            termo,
            limite,
        };

        const [
            mensagens,
            wiki,
            textosAtendimento,
            avisosInternos,
            boasPraticas,
            duvidasRespondidas,
        ] = await Promise.all([
            buscarMensagensGlobal(contexto),
            buscarWikiGlobal(contexto),
            buscarBibliotecaConteudoGlobal({
                config: TEXTOS_ATENDIMENTO_LIBRARY,
                empresaId: req.user.empresa_id,
                termo,
                limite,
                source: "attendance_texts",
                sourceLabel: "Textos para Atendimento",
                url: "/textos-atendimento",
            }),
            buscarAvisosInternosGlobal(contexto),
            buscarBibliotecaConteudoGlobal({
                config: BOAS_PRATICAS_ATENDIMENTO_LIBRARY,
                empresaId: req.user.empresa_id,
                termo,
                limite,
                source: "best_practices",
                sourceLabel: "Boas Práticas",
                url: "/boas-praticas-atendimento",
            }),
            buscarDuvidasRespondidasGlobal(contexto),
        ]);

        const secoes = [
            criarSecaoBuscaGlobal("messages", "Mensagens", mensagens),
            criarSecaoBuscaGlobal("wiki", "Wiki", wiki),
            criarSecaoBuscaGlobal("attendance_texts", "Textos para Atendimento", textosAtendimento),
            criarSecaoBuscaGlobal("internal_announcements", "Avisos Internos", avisosInternos),
            criarSecaoBuscaGlobal(
                "best_practices",
                "Boas Práticas",
                [...boasPraticas, ...duvidasRespondidas]
                    .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
                    .slice(0, limite)
            ),
        ];

        res.json({
            query: termo,
            total: secoes.reduce((total, secao) => total + secao.total, 0),
            sections: secoes,
        });
    } catch (err) {
        console.error("Erro na busca global:", err);
        res.status(500).json({ error: "Erro ao executar busca global." });
    }
});

route.get("/attendance-texts", authMiddleware, async (req, res) => {
    try {
        const textos = await listarTextosAtendimento(req.user.empresa_id, false);
        res.json(textos);
    } catch (err) {
        console.error("Erro ao listar textos de atendimento:", err);
        res.status(500).json({ error: "Erro ao listar textos de atendimento." });
    }
});

route.get("/admin/attendance-texts", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const textos = await listarTextosAtendimento(req.admin.empresa_id, true);
        res.json(textos);
    } catch (err) {
        console.error("Erro ao listar textos de atendimento para admin:", err);
        res.status(500).json({ error: "Erro ao listar textos de atendimento." });
    }
});

route.post("/admin/attendance-texts", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const title = limitarTexto(req.body.title, 180);
        const content = normalizarTextoLongo(req.body.content, 50000);
        const isActive = normalizarBooleano(req.body.is_active, true);
        let sortOrder = normalizarOrdemTextoAtendimento(req.body.sort_order, null);

        if (!title) {
            return res.status(400).json({ error: "Informe o título do texto." });
        }

        if (!content) {
            return res.status(400).json({ error: "Informe o conteúdo do texto." });
        }

        await garantirTabelaTextosAtendimento();
        await garantirTextosAtendimentoPadrao(empresaId, req.admin.id);

        if (sortOrder === null) {
            const [ordemRows] = await db.query(`
                SELECT COALESCE(MAX(sort_order), 0) + 10 AS proxima_ordem
                FROM attendance_texts
                WHERE empresa_id = ?
            `, [empresaId]);

            sortOrder = Number(ordemRows[0]?.proxima_ordem || 10);
        }

        const [result] = await db.query(`
            INSERT INTO attendance_texts (
                empresa_id,
                title,
                content,
                is_active,
                sort_order,
                created_by,
                updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [empresaId, title, content, isActive, sortOrder, req.admin.id, req.admin.id]);

        const texto = await buscarTextoAtendimentoAdmin(result.insertId, empresaId);

        res.status(201).json(texto);
    } catch (err) {
        console.error("Erro ao criar texto de atendimento:", err);
        res.status(500).json({ error: "Erro ao criar texto de atendimento." });
    }
});

route.put("/admin/attendance-texts/:id", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const textoId = Number(req.params.id);
        const title = limitarTexto(req.body.title, 180);
        const content = normalizarTextoLongo(req.body.content, 50000);
        const isActive = normalizarBooleano(req.body.is_active, true);
        const sortOrder = normalizarOrdemTextoAtendimento(req.body.sort_order, 0);

        if (!Number.isInteger(textoId) || textoId <= 0) {
            return res.status(400).json({ error: "Texto inválido." });
        }

        if (!title) {
            return res.status(400).json({ error: "Informe o título do texto." });
        }

        if (!content) {
            return res.status(400).json({ error: "Informe o conteúdo do texto." });
        }

        await garantirTabelaTextosAtendimento();
        await garantirTextosAtendimentoPadrao(empresaId, req.admin.id);

        const [result] = await db.query(`
            UPDATE attendance_texts
            SET
                title = ?,
                content = ?,
                is_active = ?,
                sort_order = ?,
                updated_by = ?
            WHERE id = ?
              AND empresa_id = ?
        `, [title, content, isActive, sortOrder, req.admin.id, textoId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Texto não encontrado." });
        }

        const texto = await buscarTextoAtendimentoAdmin(textoId, empresaId);

        res.json(texto);
    } catch (err) {
        console.error("Erro ao editar texto de atendimento:", err);
        res.status(500).json({ error: "Erro ao editar texto de atendimento." });
    }
});

route.patch("/admin/attendance-texts/:id/toggle", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const textoId = Number(req.params.id);

        if (!Number.isInteger(textoId) || textoId <= 0) {
            return res.status(400).json({ error: "Texto inválido." });
        }

        await garantirTabelaTextosAtendimento();
        await garantirTextosAtendimentoPadrao(empresaId, req.admin.id);

        const textoAtual = await buscarTextoAtendimentoAdmin(textoId, empresaId);

        if (!textoAtual) {
            return res.status(404).json({ error: "Texto não encontrado." });
        }

        const proximoAtivo = Object.prototype.hasOwnProperty.call(req.body, "is_active")
            ? normalizarBooleano(req.body.is_active, textoAtual.is_active)
            : !textoAtual.is_active;

        await db.query(`
            UPDATE attendance_texts
            SET is_active = ?, updated_by = ?
            WHERE id = ?
              AND empresa_id = ?
        `, [proximoAtivo, req.admin.id, textoId, empresaId]);

        const texto = await buscarTextoAtendimentoAdmin(textoId, empresaId);

        res.json(texto);
    } catch (err) {
        console.error("Erro ao ativar/desativar texto de atendimento:", err);
        res.status(500).json({ error: "Erro ao alterar status do texto." });
    }
});

route.delete("/admin/attendance-texts/:id", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const textoId = Number(req.params.id);

        if (!Number.isInteger(textoId) || textoId <= 0) {
            return res.status(400).json({ error: "Texto inválido." });
        }

        await garantirTabelaTextosAtendimento();

        const [result] = await db.query(`
            DELETE FROM attendance_texts
            WHERE id = ?
              AND empresa_id = ?
        `, [textoId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Texto não encontrado." });
        }

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao excluir texto de atendimento:", err);
        res.status(500).json({ error: "Erro ao excluir texto de atendimento." });
    }
});

route.get("/attendance-best-practices", authMiddleware, async (req, res) => {
    try {
        const textos = await listarBoasPraticasAtendimento(req.user.empresa_id, false);
        res.json(textos);
    } catch (err) {
        console.error("Erro ao listar boas práticas de atendimento:", err);
        res.status(500).json({ error: "Erro ao listar boas práticas de atendimento." });
    }
});

route.get("/admin/attendance-best-practices", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const textos = await listarBoasPraticasAtendimento(req.admin.empresa_id, true);
        res.json(textos);
    } catch (err) {
        console.error("Erro ao listar boas práticas de atendimento para admin:", err);
        res.status(500).json({ error: "Erro ao listar boas práticas de atendimento." });
    }
});

route.post("/admin/attendance-best-practices", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const title = limitarTexto(req.body.title, 180);
        const content = normalizarTextoLongo(req.body.content, 50000);
        const isActive = normalizarBooleano(req.body.is_active, true);
        let sortOrder = normalizarOrdemTextoAtendimento(req.body.sort_order, null);

        if (!title) {
            return res.status(400).json({ error: "Informe o título da boa prática." });
        }

        if (!content) {
            return res.status(400).json({ error: "Informe o conteúdo da boa prática." });
        }

        await garantirTabelaBoasPraticasAtendimento();
        await garantirBoasPraticasAtendimentoPadrao(empresaId, req.admin.id);

        if (sortOrder === null) {
            const [ordemRows] = await db.query(`
                SELECT COALESCE(MAX(sort_order), 0) + 10 AS proxima_ordem
                FROM ${BOAS_PRATICAS_ATENDIMENTO_LIBRARY.tableName}
                WHERE empresa_id = ?
            `, [empresaId]);

            sortOrder = Number(ordemRows[0]?.proxima_ordem || 10);
        }

        const [result] = await db.query(`
            INSERT INTO ${BOAS_PRATICAS_ATENDIMENTO_LIBRARY.tableName} (
                empresa_id,
                title,
                content,
                is_active,
                sort_order,
                created_by,
                updated_by
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [empresaId, title, content, isActive, sortOrder, req.admin.id, req.admin.id]);

        const texto = await buscarBoaPraticaAtendimentoAdmin(result.insertId, empresaId);

        res.status(201).json(texto);
    } catch (err) {
        console.error("Erro ao criar boa prática de atendimento:", err);
        res.status(500).json({ error: "Erro ao criar boa prática de atendimento." });
    }
});

route.put("/admin/attendance-best-practices/:id", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const textoId = Number(req.params.id);
        const title = limitarTexto(req.body.title, 180);
        const content = normalizarTextoLongo(req.body.content, 50000);
        const isActive = normalizarBooleano(req.body.is_active, true);
        const sortOrder = normalizarOrdemTextoAtendimento(req.body.sort_order, 0);

        if (!Number.isInteger(textoId) || textoId <= 0) {
            return res.status(400).json({ error: "Boa prática inválida." });
        }

        if (!title) {
            return res.status(400).json({ error: "Informe o título da boa prática." });
        }

        if (!content) {
            return res.status(400).json({ error: "Informe o conteúdo da boa prática." });
        }

        await garantirTabelaBoasPraticasAtendimento();
        await garantirBoasPraticasAtendimentoPadrao(empresaId, req.admin.id);

        const [result] = await db.query(`
            UPDATE ${BOAS_PRATICAS_ATENDIMENTO_LIBRARY.tableName}
            SET
                title = ?,
                content = ?,
                is_active = ?,
                sort_order = ?,
                updated_by = ?
            WHERE id = ?
              AND empresa_id = ?
        `, [title, content, isActive, sortOrder, req.admin.id, textoId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Boa prática não encontrada." });
        }

        const texto = await buscarBoaPraticaAtendimentoAdmin(textoId, empresaId);

        res.json(texto);
    } catch (err) {
        console.error("Erro ao editar boa prática de atendimento:", err);
        res.status(500).json({ error: "Erro ao editar boa prática de atendimento." });
    }
});

route.patch("/admin/attendance-best-practices/:id/toggle", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const textoId = Number(req.params.id);

        if (!Number.isInteger(textoId) || textoId <= 0) {
            return res.status(400).json({ error: "Boa prática inválida." });
        }

        await garantirTabelaBoasPraticasAtendimento();
        await garantirBoasPraticasAtendimentoPadrao(empresaId, req.admin.id);

        const textoAtual = await buscarBoaPraticaAtendimentoAdmin(textoId, empresaId);

        if (!textoAtual) {
            return res.status(404).json({ error: "Boa prática não encontrada." });
        }

        const proximoAtivo = Object.prototype.hasOwnProperty.call(req.body, "is_active")
            ? normalizarBooleano(req.body.is_active, textoAtual.is_active)
            : !textoAtual.is_active;

        await db.query(`
            UPDATE ${BOAS_PRATICAS_ATENDIMENTO_LIBRARY.tableName}
            SET is_active = ?, updated_by = ?
            WHERE id = ?
              AND empresa_id = ?
        `, [proximoAtivo, req.admin.id, textoId, empresaId]);

        const texto = await buscarBoaPraticaAtendimentoAdmin(textoId, empresaId);

        res.json(texto);
    } catch (err) {
        console.error("Erro ao ativar/desativar boa prática de atendimento:", err);
        res.status(500).json({ error: "Erro ao alterar status da boa prática." });
    }
});

route.delete("/admin/attendance-best-practices/:id", authMiddleware, requireEditorBibliotecaAtendimento, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const textoId = Number(req.params.id);

        if (!Number.isInteger(textoId) || textoId <= 0) {
            return res.status(400).json({ error: "Boa prática inválida." });
        }

        await garantirTabelaBoasPraticasAtendimento();

        const [result] = await db.query(`
            DELETE FROM ${BOAS_PRATICAS_ATENDIMENTO_LIBRARY.tableName}
            WHERE id = ?
              AND empresa_id = ?
        `, [textoId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Boa prática não encontrada." });
        }

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao excluir boa prática de atendimento:", err);
        res.status(500).json({ error: "Erro ao excluir boa prática de atendimento." });
    }
});

// ========================================
// CHAT - ENDPOINTS
// ========================================

const formatarMensagemFavorita = (row = {}) => ({
    favorite_id: row.favorite_id,
    favorited_at: row.favorited_at,
    id: row.message_id,
    message_id: row.message_id,
    mensagem: row.mensagem || "",
    tipo_mensagem: row.tipo_mensagem || "texto",
    anexo_nome: row.anexo_nome || null,
    anexo_mime: row.anexo_mime || null,
    sticker_id: row.sticker_id || null,
    criada_em: row.criada_em,
    autor: {
        id: row.remetente_id,
        nome: row.remetente_nome || "Usuário",
    },
    origem: {
        tipo: row.tipo_origem,
        nome: row.origem_nome || (row.tipo_origem === "grupo" ? "Grupo" : "Conversa"),
        conversa_id: row.conversa_id || null,
        grupo_id: row.grupo_id || null,
        destinatario_id: row.destinatario_id || null,
    },
});

route.get("/messages/favorites", authMiddleware, async (req, res) => {
    try {
        const userId = Number(req.user.id);
        const empresaId = Number(req.user.empresa_id);

        await garantirTipoMensagemAudio();
        await garantirTabelaMessageFavorites();
        await garantirTabelaMensagensOcultas();

        const [rows] = await db.query(`
            SELECT *
            FROM (
                SELECT
                    mf.id AS favorite_id,
                    mf.created_at AS favorited_at,
                    m.id AS message_id,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.sticker_id,
                    m.criada_em,
                    m.remetente_id,
                    autor.nome AS remetente_nome,
                    'direta' AS tipo_origem,
                    cd.id AS conversa_id,
                    NULL AS grupo_id,
                    outro.id AS destinatario_id,
                    outro.nome AS origem_nome
                FROM message_favorites mf
                JOIN mensagens m ON m.id = mf.message_id
                JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id
                JOIN usuarios autor ON autor.id = m.remetente_id
                JOIN usuarios u1 ON u1.id = cd.usuario1_id
                JOIN usuarios u2 ON u2.id = cd.usuario2_id
                JOIN usuarios outro ON (
                    (cd.usuario1_id = ? AND outro.id = cd.usuario2_id)
                    OR (cd.usuario2_id = ? AND outro.id = cd.usuario1_id)
                )
                WHERE mf.user_id = ?
                  AND m.deletada_em IS NULL
                  AND (cd.usuario1_id = ? OR cd.usuario2_id = ?)
                  AND u1.empresa_id = ?
                  AND u2.empresa_id = ?
                  AND NOT EXISTS (
                      SELECT 1
                      FROM mensagens_ocultas_usuario mou
                      WHERE mou.mensagem_id = m.id
                        AND mou.usuario_id = ?
                  )
                UNION ALL
                SELECT
                    mf.id AS favorite_id,
                    mf.created_at AS favorited_at,
                    m.id AS message_id,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.sticker_id,
                    m.criada_em,
                    m.remetente_id,
                    autor.nome AS remetente_nome,
                    'grupo' AS tipo_origem,
                    NULL AS conversa_id,
                    g.id AS grupo_id,
                    NULL AS destinatario_id,
                    g.nome AS origem_nome
                FROM message_favorites mf
                JOIN mensagens m ON m.id = mf.message_id
                JOIN grupos g ON g.id = m.grupo_id
                JOIN grupo_membros gm ON gm.grupo_id = g.id AND gm.usuario_id = ?
                JOIN usuarios autor ON autor.id = m.remetente_id
                WHERE mf.user_id = ?
                  AND m.deletada_em IS NULL
                  AND g.empresa_id = ?
                  AND g.deletado_em IS NULL
                  AND NOT EXISTS (
                      SELECT 1
                      FROM mensagens_ocultas_usuario mou
                      WHERE mou.mensagem_id = m.id
                        AND mou.usuario_id = ?
                  )
            ) favoritos
            ORDER BY favorited_at DESC, message_id DESC
            LIMIT 500
        `, [
            userId,
            userId,
            userId,
            userId,
            userId,
            empresaId,
            empresaId,
            userId,
            userId,
            userId,
            empresaId,
            userId,
        ]);

        res.json({
            favorites: rows.map(formatarMensagemFavorita),
        });
    } catch (err) {
        console.error("Erro ao listar mensagens favoritas:", err);
        res.status(500).json({ error: "Erro ao listar mensagens favoritas." });
    }
});

route.post("/messages/:messageId/favorite", authMiddleware, async (req, res) => {
    try {
        const messageId = Number(req.params.messageId);

        if (!Number.isInteger(messageId) || messageId <= 0) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        await garantirTabelaMessageFavorites();

        const mensagem = await buscarMensagemVisivelParaUsuario(messageId, req.user);

        if (!mensagem) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        await db.query(`
            INSERT IGNORE INTO message_favorites (user_id, message_id)
            VALUES (?, ?)
        `, [req.user.id, messageId]);

        res.json({
            message_id: messageId,
            favorited: true,
        });
    } catch (err) {
        console.error("Erro ao favoritar mensagem:", err);
        res.status(500).json({ error: "Erro ao favoritar mensagem." });
    }
});

route.delete("/messages/:messageId/favorite", authMiddleware, async (req, res) => {
    try {
        const messageId = Number(req.params.messageId);

        if (!Number.isInteger(messageId) || messageId <= 0) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        await garantirTabelaMessageFavorites();

        await db.query(`
            DELETE FROM message_favorites
            WHERE user_id = ?
              AND message_id = ?
        `, [req.user.id, messageId]);

        res.json({
            message_id: messageId,
            favorited: false,
        });
    } catch (err) {
        console.error("Erro ao remover mensagem dos favoritos:", err);
        res.status(500).json({ error: "Erro ao remover mensagem dos favoritos." });
    }
});

route.post("/messages/:messageId/reactions/toggle", authMiddleware, async (req, res) => {
    try {
        const messageId = Number(req.params.messageId);
        const reaction = String(req.body?.reaction || "").trim();

        if (!Number.isInteger(messageId) || messageId <= 0) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        if (!MESSAGE_REACTIONS_PERMITIDAS.includes(reaction)) {
            return res.status(400).json({ error: "Reação inválida." });
        }

        const mensagem = await buscarMensagemVisivelParaUsuario(messageId, req.user);

        if (!mensagem) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        await garantirTabelaMessageReactions();

        const [existente] = await db.query(`
            SELECT id
            FROM message_reactions
            WHERE message_id = ?
              AND user_id = ?
              AND reaction = ?
            LIMIT 1
        `, [messageId, req.user.id, reaction]);

        if (existente.length) {
            await db.query(`
                DELETE FROM message_reactions
                WHERE message_id = ?
                  AND user_id = ?
                  AND reaction = ?
            `, [messageId, req.user.id, reaction]);
        } else {
            await db.query(`
                INSERT INTO message_reactions (message_id, user_id, reaction)
                VALUES (?, ?, ?)
            `, [messageId, req.user.id, reaction]);
        }

        const reacoesMap = await buscarReacoesPorMensagens([messageId], req.user.id);
        const reacoes = reacoesMap.get(messageId) || [];
        const io = req.app.get("io");

        if (io) {
            if (mensagem.grupo_id) {
                io.to(`grupo_${mensagem.grupo_id}`).emit("message_reactions_updated", {
                    message_id: messageId,
                    reacoes,
                });
            }

            if (mensagem.conversa_id) {
                io.to(`conversa_${mensagem.conversa_id}`).emit("message_reactions_updated", {
                    message_id: messageId,
                    reacoes,
                });
            }
        }

        res.json({
            message_id: messageId,
            reacoes,
        });
    } catch (err) {
        console.error("Erro ao alternar reação da mensagem:", err);
        res.status(500).json({ error: "Erro ao atualizar reação." });
    }
});

route.post("/messages/:messageId/pin", authMiddleware, async (req, res) => {
    try {
        const messageId = Number(req.params.messageId);

        if (!Number.isInteger(messageId) || messageId <= 0) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        const mensagem = await buscarMensagemVisivelParaUsuario(messageId, req.user);

        if (!mensagem) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        const tipo = mensagem.tipo_origem;
        const referenciaId = tipo === "grupo" ? mensagem.grupo_id : mensagem.conversa_id;

        await garantirTabelaPinnedMessages();

        await db.query(`
            INSERT INTO pinned_messages (tipo, referencia_id, message_id, pinned_by)
            VALUES (?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                message_id = VALUES(message_id),
                pinned_by = VALUES(pinned_by),
                updated_at = CURRENT_TIMESTAMP
        `, [tipo, referenciaId, messageId, req.user.id]);

        const pinnedMessage = await buscarMensagemFixada({
            tipo,
            referenciaId,
            userId: req.user.id,
        });

        emitirAtualizacaoMensagemFixada(req, mensagem, pinnedMessage);

        res.json({
            pinned_message: pinnedMessage,
        });
    } catch (err) {
        console.error("Erro ao fixar mensagem:", err);
        res.status(500).json({ error: "Erro ao fixar mensagem." });
    }
});

route.delete("/messages/:messageId/pin", authMiddleware, async (req, res) => {
    try {
        const messageId = Number(req.params.messageId);

        if (!Number.isInteger(messageId) || messageId <= 0) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        const mensagem = await buscarMensagemVisivelParaUsuario(messageId, req.user);

        if (!mensagem) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        const tipo = mensagem.tipo_origem;
        const referenciaId = tipo === "grupo" ? mensagem.grupo_id : mensagem.conversa_id;

        await garantirTabelaPinnedMessages();

        await db.query(`
            DELETE FROM pinned_messages
            WHERE tipo = ?
              AND referencia_id = ?
        `, [tipo, referenciaId]);

        emitirAtualizacaoMensagemFixada(req, mensagem, null);

        res.json({
            pinned_message: null,
        });
    } catch (err) {
        console.error("Erro ao desafixar mensagem:", err);
        res.status(500).json({ error: "Erro ao desafixar mensagem." });
    }
});

// GET conversas diretas do usuário
route.get("/chat/conversas-diretas", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;

        await garantirTabelaMensagensOcultas();
        await garantirTabelaConversasOcultas();
        await garantirTabelaChatFavoritos();

        const [rows] = await db.query(`
            SELECT 
                cd.id,
                CASE 
                    WHEN cd.usuario1_id = ? THEN cd.usuario2_id 
                    ELSE cd.usuario1_id 
                END AS usuario_outro_id,
                u.nome AS usuario_outro_nome,
                u.status AS usuario_outro_status,
                u.avatar AS usuario_outro_avatar,
                cd.atualizada_em,
                EXISTS (
                    SELECT 1
                    FROM chat_favoritos cf
                    WHERE cf.usuario_id = ?
                      AND cf.tipo = 'direta'
                      AND cf.referencia_id = cd.id
                ) AS favorito,
                (SELECT CASE
                    WHEN tipo_mensagem = 'imagem' THEN '[Imagem]'
                    WHEN tipo_mensagem = 'audio' THEN '[Áudio]'
                    WHEN tipo_mensagem = 'arquivo' THEN '[Arquivo]'
                    WHEN tipo_mensagem = 'sticker' THEN 'Figurinha'
                    ELSE mensagem
                 END FROM mensagens 
                 WHERE conversa_direta_id = cd.id 
                 AND deletada_em IS NULL
                 AND NOT EXISTS (
                    SELECT 1
                    FROM mensagens_ocultas_usuario mou
                    WHERE mou.mensagem_id = mensagens.id
                    AND mou.usuario_id = ?
                 )
                 ORDER BY criada_em DESC, id DESC LIMIT 1) AS ultima_mensagem,
                (SELECT criada_em
                 FROM mensagens
                 WHERE conversa_direta_id = cd.id
                 AND deletada_em IS NULL
                 AND NOT EXISTS (
                    SELECT 1
                    FROM mensagens_ocultas_usuario mou
                    WHERE mou.mensagem_id = mensagens.id
                    AND mou.usuario_id = ?
                 )
                 ORDER BY criada_em DESC, id DESC LIMIT 1) AS ultima_mensagem_em,
                (SELECT COUNT(*) FROM mensagens 
                 WHERE conversa_direta_id = cd.id 
                 AND remetente_id != ? 
                 AND deletada_em IS NULL
                 AND lida = FALSE
                 AND NOT EXISTS (
                    SELECT 1
                    FROM mensagens_ocultas_usuario mou
                    WHERE mou.mensagem_id = mensagens.id
                    AND mou.usuario_id = ?
                 )) AS nao_lidas
            FROM conversas_diretas cd
            JOIN usuarios u ON (
                (cd.usuario1_id = ? AND u.id = cd.usuario2_id) OR
                (cd.usuario2_id = ? AND u.id = cd.usuario1_id)
            )
            WHERE (cd.usuario1_id = ? OR cd.usuario2_id = ?)
            AND u.deletado_em IS NULL
            AND NOT EXISTS (
                SELECT 1
                FROM conversas_ocultas_usuario cou
                WHERE cou.conversa_direta_id = cd.id
                AND cou.usuario_id = ?
            )
            ORDER BY favorito DESC, COALESCE(ultima_mensagem_em, cd.atualizada_em) DESC
        `, [userId, userId, userId, userId, userId, userId, userId, userId, userId, userId, userId]);

        res.json(rows.map((row) => ({
            ...row,
            atualizada_em: row.ultima_mensagem_em || row.atualizada_em,
            favorito: Boolean(row.favorito),
        })));
    } catch (err) {
        console.error("Erro ao buscar conversas diretas:", err);
        res.status(500).json({ error: "Erro ao buscar conversas" });
    }
});

// DELETE ocultar conversa direta apenas para o usuário atual
route.delete("/chat/conversas-diretas/:conversa_id/ocultar", authMiddleware, async (req, res) => {
    try {
        const { conversa_id } = req.params;
        const userId = req.user.id;

        await garantirTabelaConversasOcultas();

        const [conversa] = await db.query(`
            SELECT id
            FROM conversas_diretas
            WHERE id = ?
              AND (usuario1_id = ? OR usuario2_id = ?)
            LIMIT 1
        `, [conversa_id, userId, userId]);

        if (!conversa.length) {
            return res.status(404).json({ error: "Conversa não encontrada" });
        }

        await db.query(`
            INSERT INTO conversas_ocultas_usuario (conversa_direta_id, usuario_id)
            VALUES (?, ?)
            ON DUPLICATE KEY UPDATE ocultada_em = CURRENT_TIMESTAMP
        `, [conversa_id, userId]);

        res.json({ ok: true });
    } catch (err) {
        console.error("Erro ao ocultar conversa:", err);
        res.status(500).json({ error: "Erro ao remover conversa da lista" });
    }
});

route.patch("/chat/favoritos", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const tipo = String(req.body.tipo || "").trim();
        const referenciaId = Number(req.body.referencia_id);
        const favorito = req.body.favorito === true || req.body.favorito === "true";

        if (!["direta", "grupo"].includes(tipo) || !Number.isInteger(referenciaId) || referenciaId <= 0) {
            return res.status(400).json({ error: "Favorito inválido." });
        }

        await garantirTabelaChatFavoritos();

        if (tipo === "direta") {
            const [conversa] = await db.query(`
                SELECT id
                FROM conversas_diretas
                WHERE id = ?
                  AND (usuario1_id = ? OR usuario2_id = ?)
                LIMIT 1
            `, [referenciaId, userId, userId]);

            if (!conversa.length) {
                return res.status(404).json({ error: "Conversa não encontrada." });
            }
        }

        if (tipo === "grupo") {
            const [grupo] = await db.query(`
                SELECT gm.grupo_id
                FROM grupo_membros gm
                JOIN grupos g ON gm.grupo_id = g.id
                WHERE gm.grupo_id = ?
                  AND gm.usuario_id = ?
                  AND g.deletado_em IS NULL
                LIMIT 1
            `, [referenciaId, userId]);

            if (!grupo.length) {
                return res.status(404).json({ error: "Grupo não encontrado." });
            }
        }

        if (favorito) {
            await db.query(`
                INSERT IGNORE INTO chat_favoritos (usuario_id, tipo, referencia_id)
                VALUES (?, ?, ?)
            `, [userId, tipo, referenciaId]);
        } else {
            await db.query(`
                DELETE FROM chat_favoritos
                WHERE usuario_id = ?
                  AND tipo = ?
                  AND referencia_id = ?
            `, [userId, tipo, referenciaId]);
        }

        res.json({
            tipo,
            referencia_id: referenciaId,
            favorito,
        });
    } catch (err) {
        console.error("Erro ao atualizar favorito:", err);
        res.status(500).json({ error: "Erro ao atualizar favorito." });
    }
});

// GET mensagens de uma conversa direta
route.get("/chat/conversa-direta/:usuario_id", authMiddleware, async (req, res) => {
    const inicio = Date.now();

    try {
        const { usuario_id } = req.params;
        const userId = req.user.id;
        const limite = normalizarLimiteMensagens(req.query.limit);
        const beforeId = Number.parseInt(req.query.before_id, 10) || null;

        console.log(`[CHAT][direta] usuario=${userId} destino=${usuario_id} carregando limit=${limite}`);

        const [destinatario] = await db.query(`
            SELECT id
            FROM usuarios
            WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [usuario_id, req.user.empresa_id]);

        if (!destinatario.length) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        // Buscar ou criar conversa
        let [conversa] = await db.query(`
            SELECT id FROM conversas_diretas 
            WHERE (usuario1_id = ? AND usuario2_id = ?) 
               OR (usuario1_id = ? AND usuario2_id = ?)
            LIMIT 1
        `, [userId, usuario_id, usuario_id, userId]);

        if (!conversa.length) {
            // Criar nova conversa
            await db.query(`
                INSERT INTO conversas_diretas (usuario1_id, usuario2_id) 
                VALUES (?, ?)
            `, [userId, usuario_id]);

            [conversa] = await db.query(`
                SELECT id FROM conversas_diretas 
                WHERE (usuario1_id = ? AND usuario2_id = ?) 
                   OR (usuario1_id = ? AND usuario2_id = ?)
            `, [userId, usuario_id, usuario_id, userId]);
        }

        const conversa_id = conversa[0].id;

        await garantirTipoMensagemAudio();
        await garantirTabelaMensagensOcultas();
        await garantirTabelaConversasOcultas();
        await garantirTabelaMessageFavorites();
        await garantirTabelaMessageReactions();
        await garantirTabelaPinnedMessages();
        await garantirIndicesChatPerformance();

        await db.query(`
            DELETE FROM conversas_ocultas_usuario
            WHERE conversa_direta_id = ?
              AND usuario_id = ?
        `, [conversa_id, userId]);

        const filtroBefore = beforeId ? 'AND m.id < ?' : '';
        const paramsMensagens = [userId, conversa_id, userId];

        if (beforeId) {
            paramsMensagens.push(beforeId);
        }

        paramsMensagens.push(limite + 1);

        // Buscar mensagens recentes pela API; o socket fica apenas para tempo real.
        const [mensagensRows] = await db.query(`
            SELECT *
            FROM (
                SELECT 
                    m.id,
                    m.remetente_id,
                    u.nome AS remetente_nome,
                    u.avatar AS remetente_avatar,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.sticker_id,
                    m.lida,
                    m.entregue_em,
                    m.lida_em,
                    m.criada_em,
                    m.editada_em,
                    CASE WHEN mf.id IS NULL THEN 0 ELSE 1 END AS favoritada,
                    m.resposta_mensagem_id,
                    rm.remetente_id AS resposta_remetente_id,
                    ru.nome AS resposta_remetente_nome,
                    rm.tipo_mensagem AS resposta_tipo_mensagem,
                    rm.mensagem AS resposta_mensagem,
                    rm.anexo_nome AS resposta_anexo_nome,
                    rm.sticker_id AS resposta_sticker_id,
                    CASE
                        WHEN rm.id IS NULL THEN NULL
                        WHEN rm.tipo_mensagem = 'imagem' THEN '[Imagem]'
                        WHEN rm.tipo_mensagem = 'audio' THEN '[Áudio]'
                        WHEN rm.tipo_mensagem = 'arquivo' THEN '[Arquivo]'
                        WHEN rm.tipo_mensagem = 'sticker' THEN 'Figurinha'
                        ELSE LEFT(rm.mensagem, 180)
                    END AS resposta_previa
                FROM mensagens m
                JOIN usuarios u ON m.remetente_id = u.id
                LEFT JOIN message_favorites mf ON mf.message_id = m.id AND mf.user_id = ?
                LEFT JOIN mensagens rm ON m.resposta_mensagem_id = rm.id AND rm.deletada_em IS NULL
                LEFT JOIN usuarios ru ON rm.remetente_id = ru.id
                WHERE m.conversa_direta_id = ? AND m.deletada_em IS NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM mensagens_ocultas_usuario mou
                    WHERE mou.mensagem_id = m.id
                    AND mou.usuario_id = ?
                )
                ${filtroBefore}
                ORDER BY m.criada_em DESC, m.id DESC
                LIMIT ?
            ) ultimas
            ORDER BY ultimas.criada_em ASC, ultimas.id ASC
        `, paramsMensagens);

        const temMais = mensagensRows.length > limite;
        const mensagens = temMais ? mensagensRows.slice(1) : mensagensRows;
        const mensagensComReacoes = await anexarReacoesMensagens(mensagens, userId);
        const pinnedMessage = await buscarMensagemFixada({
            tipo: "direta",
            referenciaId: conversa_id,
            userId,
        });

        console.log(
            `[CHAT][direta] usuario=${userId} conversa=${conversa_id} retornou=${mensagens.length} em ${Date.now() - inicio}ms`
        );

        res.json({
            conversa_id,
            usuario_id,
            mensagens: mensagensComReacoes,
            pinned_message: pinnedMessage,
            paginacao: {
                limit: limite,
                has_more: temMais,
                before_id: mensagens[0]?.id || null,
            },
        });
    } catch (err) {
        console.error(`Erro ao buscar mensagens (${Date.now() - inicio}ms):`, err);
        res.status(500).json({ error: "Erro ao buscar mensagens" });
    }
});

// GET grupos da empresa
route.get("/chat/grupos", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const empresaId = req.user.empresa_id;

        await garantirGruposFixos(empresaId);
        await garantirTipoMensagemAudio();
        await garantirTipoMensagemAudio();
        await garantirTabelaMensagensOcultas();
        await garantirTabelaLeiturasMensagens();
        await garantirTabelaLeiturasGrupos();
        await garantirIndicesChatPerformance();
        await garantirTabelaChatFavoritos();

        const [grupos] = await db.query(`
            SELECT 
                g.id,
                g.nome,
                g.descricao,
                g.avatar,
                g.criador_id,
                g.fixo,
                g.setor_id,
                g.mensagem_fixada_titulo,
                g.mensagem_fixada_conteudo,
                g.mensagem_fixada_ativo,
	                g.mensagem_fixada_atualizada_em,
	                g.mensagem_fixada_atualizada_por,
	                s.nome AS setor_nome,
	                gm_usuario.id IS NOT NULL AS tem_acesso,
	                CASE
	                    WHEN gm_usuario.id IS NOT NULL THEN EXISTS (
	                        SELECT 1
	                        FROM chat_favoritos cf
	                        WHERE cf.usuario_id = ?
	                          AND cf.tipo = 'grupo'
	                          AND cf.referencia_id = g.id
	                    )
	                    ELSE 0
	                END AS favorito,
	                (SELECT COUNT(*) FROM grupo_membros WHERE grupo_id = g.id) AS total_membros,
	                CASE
	                    WHEN gm_usuario.id IS NOT NULL THEN (
	                        SELECT COUNT(*) FROM mensagens m
	                        WHERE m.grupo_id = g.id
	                        AND m.remetente_id != ?
	                        AND m.deletada_em IS NULL
	                        AND NOT EXISTS (
	                            SELECT 1
	                            FROM mensagens_ocultas_usuario mou
	                            WHERE mou.mensagem_id = m.id
	                            AND mou.usuario_id = ?
	                        )
	                        AND m.id > COALESCE((
	                            SELECT gmr.last_read_message_id
	                            FROM group_message_reads gmr
	                            WHERE gmr.user_id = ?
	                              AND gmr.group_id = g.id
	                            LIMIT 1
	                        ), 0)
	                    )
	                    ELSE 0
	                END AS nao_lidas,
	                CASE
	                    WHEN gm_usuario.id IS NOT NULL THEN (
	                        SELECT CASE
	                            WHEN tipo_mensagem = 'imagem' THEN '[Imagem]'
	                            WHEN tipo_mensagem = 'audio' THEN '[Áudio]'
	                            WHEN tipo_mensagem = 'arquivo' THEN '[Arquivo]'
	                            WHEN tipo_mensagem = 'sticker' THEN 'Figurinha'
	                            ELSE mensagem
	                        END
	                        FROM mensagens
	                        WHERE grupo_id = g.id
	                        AND deletada_em IS NULL
	                        AND NOT EXISTS (
	                            SELECT 1
	                            FROM mensagens_ocultas_usuario mou
	                            WHERE mou.mensagem_id = mensagens.id
	                            AND mou.usuario_id = ?
	                        )
	                        ORDER BY criada_em DESC, id DESC LIMIT 1
	                    )
	                    ELSE NULL
	                END AS ultima_mensagem,
	                CASE
	                    WHEN gm_usuario.id IS NOT NULL THEN (
	                        SELECT criada_em
	                        FROM mensagens
	                        WHERE grupo_id = g.id
	                        AND deletada_em IS NULL
	                        AND NOT EXISTS (
	                            SELECT 1
	                            FROM mensagens_ocultas_usuario mou
	                            WHERE mou.mensagem_id = mensagens.id
	                            AND mou.usuario_id = ?
	                        )
	                        ORDER BY criada_em DESC, id DESC LIMIT 1
	                    )
	                    ELSE NULL
	                END AS ultima_mensagem_em,
	                g.atualizado_em
	            FROM grupos g
	            LEFT JOIN setores s ON g.setor_id = s.id
	            LEFT JOIN grupo_membros gm_usuario
	              ON gm_usuario.grupo_id = g.id
	             AND gm_usuario.usuario_id = ?
	            WHERE g.empresa_id = ? 
	            AND g.deletado_em IS NULL
	            ORDER BY tem_acesso DESC, favorito DESC, COALESCE(ultima_mensagem_em, g.atualizado_em) DESC, g.nome ASC
	        `, [userId, userId, userId, userId, userId, userId, userId, empresaId]);
	
	        const gruposNormalizados = grupos.map((grupo) => {
	            const temAcesso = Boolean(grupo.tem_acesso);
	            const naoLidas = temAcesso ? Number(grupo.nao_lidas || 0) : 0;

	            return {
	                ...grupo,
	                name: grupo.nome,
	                tem_acesso: temAcesso,
	                favorito: temAcesso && Boolean(grupo.favorito),
	                nao_lidas: naoLidas,
	                unreadCount: naoLidas,
	                mensagem_fixada_titulo: temAcesso ? grupo.mensagem_fixada_titulo : null,
	                mensagem_fixada_conteudo: temAcesso ? grupo.mensagem_fixada_conteudo : null,
	                mensagem_fixada_ativo: temAcesso && Boolean(grupo.mensagem_fixada_ativo),
	                mensagem_fixada_atualizada_em: temAcesso ? grupo.mensagem_fixada_atualizada_em : null,
	                mensagem_fixada_atualizada_por: temAcesso ? grupo.mensagem_fixada_atualizada_por : null,
	            };
	        });
	        const totalGroupUnreadCount = gruposNormalizados.reduce(
	            (total, grupo) => total + Number(grupo.unreadCount || 0),
	            0
	        );

	        res.json({
	            grupos: gruposNormalizados,
	            totalGroupUnreadCount,
	        });
    } catch (err) {
        console.error("Erro ao buscar grupos:", err);
        res.status(500).json({ error: "Erro ao buscar grupos" });
    }
});

// GET mensagens de um grupo
route.get("/chat/grupo/:grupo_id", authMiddleware, async (req, res) => {
    const inicio = Date.now();

    try {
        const { grupo_id } = req.params;
        const userId = req.user.id;
        const empresaId = req.user.empresa_id;
        const limite = normalizarLimiteMensagens(req.query.limit);
        const beforeId = Number.parseInt(req.query.before_id, 10) || null;

        console.log(`[CHAT][grupo] usuario=${userId} grupo=${grupo_id} carregando limit=${limite}`);

        const grupo = await buscarGrupoDaEmpresa(grupo_id, empresaId);

        if (!grupo) {
            console.warn(`[CHAT][grupo] grupo=${grupo_id} empresa=${empresaId} não encontrado`);
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        // Verificar se usuário é membro do grupo
        const [membro] = await db.query(`
            SELECT id FROM grupo_membros 
            WHERE grupo_id = ? AND usuario_id = ?
        `, [grupo_id, userId]);

        if (!membro.length) {
            console.warn(`[CHAT][grupo] acesso negado usuario=${userId} grupo=${grupo_id}`);
            return res.status(403).json({ error: "Você não tem acesso a este grupo" });
        }

        await garantirTabelaMensagensOcultas();
        await garantirTabelaLeiturasMensagens();
        await garantirTabelaMessageFavorites();
        await garantirTabelaMessageReactions();
        await garantirTabelaPinnedMessages();

        const filtroBefore = beforeId ? 'AND m.id < ?' : '';
        const paramsMensagens = [userId, grupo_id, userId];

        if (beforeId) {
            paramsMensagens.push(beforeId);
        }

        paramsMensagens.push(limite + 1);

        // Buscar mensagens recentes pela API; o socket fica apenas para tempo real.
        const [mensagensRows] = await db.query(`
            SELECT *
            FROM (
                SELECT 
                    m.id,
                    m.remetente_id,
                    u.nome AS remetente_nome,
                    u.avatar AS remetente_avatar,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.sticker_id,
                    m.lida,
                    m.criada_em,
                    m.editada_em,
                    CASE WHEN mf.id IS NULL THEN 0 ELSE 1 END AS favoritada,
                    m.resposta_mensagem_id,
                    rm.remetente_id AS resposta_remetente_id,
                    ru.nome AS resposta_remetente_nome,
                    rm.tipo_mensagem AS resposta_tipo_mensagem,
                    rm.mensagem AS resposta_mensagem,
                    rm.anexo_nome AS resposta_anexo_nome,
                    rm.sticker_id AS resposta_sticker_id,
                    CASE
                        WHEN rm.id IS NULL THEN NULL
                        WHEN rm.tipo_mensagem = 'imagem' THEN '[Imagem]'
                        WHEN rm.tipo_mensagem = 'audio' THEN '[Áudio]'
                        WHEN rm.tipo_mensagem = 'arquivo' THEN '[Arquivo]'
                        WHEN rm.tipo_mensagem = 'sticker' THEN 'Figurinha'
                        ELSE LEFT(rm.mensagem, 180)
                    END AS resposta_previa,
                    (SELECT COUNT(*) FROM leituras_mensagens WHERE mensagem_id = m.id AND (entregue_em IS NOT NULL OR lida_em IS NOT NULL)) AS total_entregas,
                    (SELECT COUNT(*) FROM leituras_mensagens WHERE mensagem_id = m.id AND lida_em IS NOT NULL) AS total_leituras
                FROM mensagens m
                JOIN usuarios u ON m.remetente_id = u.id
                LEFT JOIN message_favorites mf ON mf.message_id = m.id AND mf.user_id = ?
                LEFT JOIN mensagens rm ON m.resposta_mensagem_id = rm.id AND rm.deletada_em IS NULL
                LEFT JOIN usuarios ru ON rm.remetente_id = ru.id
                WHERE m.grupo_id = ? AND m.deletada_em IS NULL
                AND NOT EXISTS (
                    SELECT 1
                    FROM mensagens_ocultas_usuario mou
                    WHERE mou.mensagem_id = m.id
                    AND mou.usuario_id = ?
                )
                ${filtroBefore}
                ORDER BY m.criada_em DESC, m.id DESC
                LIMIT ?
            ) ultimas
            ORDER BY ultimas.criada_em ASC, ultimas.id ASC
        `, paramsMensagens);

        const temMais = mensagensRows.length > limite;
        const mensagens = temMais ? mensagensRows.slice(1) : mensagensRows;
        const mensagensComReacoes = await anexarReacoesMensagens(mensagens, userId);
        const pinnedMessage = await buscarMensagemFixada({
            tipo: "grupo",
            referenciaId: grupo_id,
            userId,
        });

        await marcarMensagensGrupoComoLidas(grupo_id, userId);

        console.log(
            `[CHAT][grupo] usuario=${userId} grupo=${grupo_id} retornou=${mensagens.length} em ${Date.now() - inicio}ms`
        );

        res.json({
            grupo_id,
            mensagens: mensagensComReacoes,
            pinned_message: pinnedMessage,
            paginacao: {
                limit: limite,
                has_more: temMais,
                before_id: mensagens[0]?.id || null,
            },
        });
    } catch (err) {
        console.error(`Erro ao buscar mensagens do grupo (${Date.now() - inicio}ms):`, err);
        res.status(500).json({ error: "Erro ao buscar mensagens" });
    }
});

// GET visualizacoes de uma mensagem de grupo
route.get("/chat/grupo/:grupo_id/mensagens/:mensagem_id/visualizacoes", authMiddleware, async (req, res) => {
    try {
        const { grupo_id, mensagem_id } = req.params;
        const userId = req.user.id;
        const empresaId = req.user.empresa_id;

        const grupo = await buscarGrupoDaEmpresa(grupo_id, empresaId);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        const [membro] = await db.query(`
            SELECT id
            FROM grupo_membros
            WHERE grupo_id = ? AND usuario_id = ?
            LIMIT 1
        `, [grupo_id, userId]);

        if (!membro.length) {
            return res.status(403).json({ error: "Acesso negado" });
        }

        const [mensagemRows] = await db.query(`
            SELECT id, remetente_id, grupo_id
            FROM mensagens
            WHERE id = ?
              AND grupo_id = ?
              AND deletada_em IS NULL
            LIMIT 1
        `, [mensagem_id, grupo_id]);

        if (!mensagemRows.length) {
            return res.status(404).json({ error: "Mensagem não encontrada" });
        }

        const mensagem = mensagemRows[0];

        await garantirTabelaLeiturasMensagens();
        await marcarMensagemGrupoComoLidaPeloAutor(mensagem.id, mensagem.remetente_id);

        const [membros] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.avatar,
                u.status,
                s.nome AS setor_nome,
                lm.entregue_em,
                lm.lida_em,
                CASE WHEN u.id = ? THEN 1 ELSE 0 END AS autor
            FROM grupo_membros gm
            JOIN usuarios u ON gm.usuario_id = u.id
            LEFT JOIN setores s ON u.setor_id = s.id
            LEFT JOIN leituras_mensagens lm
                ON lm.mensagem_id = ?
               AND lm.usuario_id = u.id
            WHERE gm.grupo_id = ?
              AND u.empresa_id = ?
              AND u.deletado_em IS NULL
            ORDER BY
              CASE WHEN u.id = ? THEN 0 ELSE 1 END,
              CASE
                WHEN lm.lida_em IS NOT NULL THEN 1
                WHEN lm.entregue_em IS NOT NULL THEN 2
                ELSE 3
              END,
              u.nome ASC
        `, [mensagem.remetente_id, mensagem.id, grupo_id, empresaId, mensagem.remetente_id]);

        const visualizacoes = membros.map((membroItem) => {
            const recebidoEm = membroItem.entregue_em || membroItem.lida_em || null;
            const lidoEm = membroItem.lida_em || null;
            const situacao = lidoEm
                ? "lido"
                : recebidoEm
                    ? "recebido"
                    : "pendente";

            return {
                id: membroItem.id,
                nome: membroItem.nome,
                email: membroItem.email,
                avatar: membroItem.avatar,
                status: membroItem.status,
                setor_nome: membroItem.setor_nome,
                autor: Boolean(membroItem.autor),
                recebido_em: recebidoEm,
                lido_em: lidoEm,
                situacao,
            };
        });

        const totais = visualizacoes.reduce((acc, item) => {
            if (item.recebido_em) acc.recebidos += 1;
            if (item.lido_em) acc.lidos += 1;
            if (!item.recebido_em && !item.lido_em) acc.pendentes += 1;
            return acc;
        }, {
            membros: visualizacoes.length,
            recebidos: 0,
            lidos: 0,
            pendentes: 0,
        });

        res.json({
            mensagem_id: Number(mensagem.id),
            grupo_id: Number(grupo_id),
            totais,
            visualizacoes,
        });
    } catch (err) {
        console.error("Erro ao buscar visualizações da mensagem:", err);
        res.status(500).json({ error: "Erro ao buscar visualizações da mensagem" });
    }
});

// GET membros de um grupo para membros do proprio grupo
route.get("/chat/grupo/:grupo_id/membros", authMiddleware, async (req, res) => {
    try {
        const { grupo_id } = req.params;
        const userId = req.user.id;
        const empresaId = req.user.empresa_id;

        const [membro] = await db.query(`
            SELECT id FROM grupo_membros
            WHERE grupo_id = ? AND usuario_id = ?
        `, [grupo_id, userId]);

        if (!membro.length) {
            return res.status(403).json({ error: "Acesso negado" });
        }

        const grupo = await buscarGrupoDaEmpresa(grupo_id, empresaId);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        const [membros] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.avatar,
                u.status,
                u.ultimo_acesso,
                s.nome AS setor_nome,
                gm.adicionado_em
            FROM grupo_membros gm
            JOIN usuarios u ON gm.usuario_id = u.id
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE gm.grupo_id = ?
              AND u.empresa_id = ?
              AND u.deletado_em IS NULL
            ORDER BY
              CASE u.status
                WHEN 'online' THEN 1
                WHEN 'away' THEN 2
                ELSE 3
              END,
              u.nome ASC
        `, [grupo_id, empresaId]);

        const membrosComGrupos = await anexarGruposAUsuarios(membros, empresaId);

        res.json({
            grupo,
            membros: membrosComGrupos,
        });
    } catch (err) {
        console.error("Erro ao buscar membros do grupo:", err);
        res.status(500).json({ error: "Erro ao buscar membros do grupo" });
    }
});

route.get("/integrations/atendimento/usuarios", requireAtendimentoIntegration, async (req, res) => {
    try {
        const empresaId = req.query.empresa_id ? Number(req.query.empresa_id) : null;
        const filters = ["u.deletado_em IS NULL"];
        const params = [];

        if (Number.isFinite(empresaId) && empresaId > 0) {
            filters.push("u.empresa_id = ?");
            params.push(empresaId);
        }

        const [usuarios] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.avatar,
                u.status,
                u.ultimo_acesso,
                u.perfil,
                u.empresa_id,
                s.nome AS setor_nome
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE ${filters.join(" AND ")}
            ORDER BY
              CASE u.status
                WHEN 'online' THEN 1
                WHEN 'away' THEN 2
                ELSE 3
              END,
              u.nome ASC
        `, params);

        res.json({ usuarios });
    } catch (err) {
        console.error("Erro ao buscar usuários para integração do atendimento:", err);
        res.status(500).json({ error: "Erro ao buscar usuários para integração" });
    }
});

route.post("/integrations/atendimento/sso/code", authMiddleware, async (req, res) => {
    try {
        limparCodigosSsoExpirados();

        const clientId = String(req.body?.clientId || req.body?.client_id || "").trim();
        const redirectUri = normalizarRedirectUriAtendimento(req.body?.redirectUri || req.body?.redirect_uri);
        const state = normalizarStateSso(req.body?.state);

        if (clientId !== ATENDIMENTO_SSO_CLIENT_ID) {
            return res.status(400).json({ error: "Cliente SSO inválido" });
        }

        if (!redirectUri) {
            return res.status(400).json({ error: "Retorno do atendimento não autorizado" });
        }

        if (!state) {
            return res.status(400).json({ error: "Estado SSO inválido" });
        }

        const usuario = await buscarUsuarioSsoAtendimento(req.user.id);

        if (!usuario) {
            return res.status(401).json({ error: "Usuário inválido" });
        }

        const code = gerarCodigoSso();
        atendimentoSsoCodes.set(hashCodigoSso(code), {
            clientId,
            redirectUri,
            state,
            usuarioId: usuario.id,
            expiresAt: Date.now() + ATENDIMENTO_SSO_CODE_TTL_MS,
        });

        res.json({
            code,
            state,
            expiresIn: Math.floor(ATENDIMENTO_SSO_CODE_TTL_MS / 1000),
        });
    } catch (err) {
        console.error("Erro ao emitir código SSO do atendimento:", err);
        res.status(500).json({ error: "Erro ao iniciar login do atendimento" });
    }
});

route.post("/integrations/atendimento/sso/exchange", requireAtendimentoIntegration, async (req, res) => {
    try {
        limparCodigosSsoExpirados();

        const code = String(req.body?.code || "").trim();
        const redirectUri = normalizarRedirectUriAtendimento(req.body?.redirectUri || req.body?.redirect_uri);

        if (!code || !redirectUri) {
            return res.status(400).json({ error: "Código SSO inválido" });
        }

        const hash = hashCodigoSso(code);
        const registro = atendimentoSsoCodes.get(hash);
        atendimentoSsoCodes.delete(hash);

        if (!registro || registro.redirectUri !== redirectUri || registro.expiresAt <= Date.now()) {
            return res.status(401).json({ error: "Código SSO expirado ou inválido" });
        }

        const usuario = await buscarUsuarioSsoAtendimento(registro.usuarioId);

        if (!usuario) {
            return res.status(401).json({ error: "Usuário inválido" });
        }

        res.json({
            user: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                avatar: usuario.avatar,
                status: usuario.status,
                ultimo_acesso: usuario.ultimo_acesso,
                perfil: usuario.perfil,
                empresa_id: usuario.empresa_id,
                setor_nome: usuario.setor_nome,
            },
        });
    } catch (err) {
        console.error("Erro ao trocar código SSO do atendimento:", err);
        res.status(500).json({ error: "Erro ao concluir login do atendimento" });
    }
});

// GET usuários da empresa para chat
route.get("/chat/usuarios", authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const empresaId = req.user.empresa_id;

        const [usuarios] = await db.query(`
            SELECT 
                u.id,
                u.nome,
                u.email,
                u.avatar,
                u.status,
                u.ultimo_acesso,
                s.nome AS setor_nome
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE u.empresa_id = ? AND u.id != ? AND u.deletado_em IS NULL
            ORDER BY u.status DESC, u.nome ASC
        `, [empresaId, userId]);

        const usuariosComGrupos = await anexarGruposAUsuarios(usuarios, empresaId);

        res.json(usuariosComGrupos);
    } catch (err) {
        console.error("Erro ao buscar usuários:", err);
        res.status(500).json({ error: "Erro ao buscar usuários" });
    }
});

route.post("/chat/upload", authMiddleware, uploadChatMiddleware, (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: "Nenhum arquivo enviado." });
    }

    const empresaDiretorio = normalizarSegmentoUpload(req.user?.empresa_id);
    const url = `/uploads/chat/${empresaDiretorio}/${req.file.filename}`;

    return res.status(201).json({
        url,
        nome: req.file.originalname,
        mime: obterMimeArquivoChat(req.file),
        tamanho: req.file.size,
        limite_mb: MAX_UPLOAD_SIZE_MB,
    });
});

route.get("/chat/stickers", authMiddleware, async (req, res) => {
    try {
        res.json(await buscarStickersUsuario(req.user));
    } catch (err) {
        console.error("Erro ao listar figurinhas:", err);
        res.status(500).json({ error: "Erro ao listar figurinhas." });
    }
});

route.post("/chat/stickers", authMiddleware, uploadStickerMiddleware, async (req, res) => {
    try {
        await garantirTabelasChatStickers();
        const sticker = await criarStickerAPartirDeUpload({
            file: req.file,
            usuario: req.user,
        });

        res.status(201).json({
            sticker,
            limits: {
                max_per_user: CHAT_STICKER_MAX_PER_USER,
                max_upload_mb: CHAT_STICKER_MAX_UPLOAD_SIZE_MB,
            },
        });
    } catch (err) {
        console.error("Erro ao criar figurinha:", err);
        res.status(err.status || 500).json({
            error: err.status ? err.message : "Erro ao criar figurinha.",
        });
    }
});

route.post("/chat/stickers/:stickerId/library", authMiddleware, async (req, res) => {
    try {
        const stickerId = Number(req.params.stickerId);
        const sticker = await adicionarStickerNaBibliotecaUsuario({
            stickerId,
            usuario: req.user,
            messageId: req.body?.message_id || null,
        });

        if (!sticker) {
            return res.status(404).json({ error: "Figurinha não encontrada." });
        }

        res.json({
            sticker: formatarSticker({
                ...sticker,
                user_id: req.user.id,
                in_library: 1,
                favorited: 0,
            }),
        });
    } catch (err) {
        console.error("Erro ao adicionar figurinha à biblioteca:", err);
        res.status(err.status || 500).json({
            error: err.status ? err.message : "Erro ao adicionar figurinha.",
        });
    }
});

route.delete("/chat/stickers/:stickerId/library", authMiddleware, async (req, res) => {
    try {
        const stickerId = Number(req.params.stickerId);

        if (!Number.isInteger(stickerId) || stickerId <= 0) {
            return res.status(400).json({ error: "Figurinha inválida." });
        }

        await garantirTabelasChatStickers();
        await db.query(`
            UPDATE user_stickers
            SET deleted_at = NOW()
            WHERE user_id = ?
              AND sticker_id = ?
              AND deleted_at IS NULL
        `, [req.user.id, stickerId]);

        res.json({
            sticker_id: stickerId,
            in_library: false,
        });
    } catch (err) {
        console.error("Erro ao remover figurinha da biblioteca:", err);
        res.status(500).json({ error: "Erro ao remover figurinha." });
    }
});

route.post("/chat/stickers/:stickerId/favorite", authMiddleware, async (req, res) => {
    try {
        const stickerId = Number(req.params.stickerId);
        const sticker = await usuarioPodeUsarSticker({
            stickerId,
            usuario: req.user,
            messageId: req.body?.message_id || null,
        });

        if (!sticker) {
            return res.status(404).json({ error: "Figurinha não encontrada." });
        }

        await db.query(`
            INSERT IGNORE INTO sticker_favorites (user_id, sticker_id)
            VALUES (?, ?)
        `, [req.user.id, sticker.id]);

        res.json({
            sticker_id: sticker.id,
            favorited: true,
        });
    } catch (err) {
        console.error("Erro ao favoritar figurinha:", err);
        res.status(500).json({ error: "Erro ao favoritar figurinha." });
    }
});

route.delete("/chat/stickers/:stickerId/favorite", authMiddleware, async (req, res) => {
    try {
        const stickerId = Number(req.params.stickerId);

        if (!Number.isInteger(stickerId) || stickerId <= 0) {
            return res.status(400).json({ error: "Figurinha inválida." });
        }

        await garantirTabelasChatStickers();
        await db.query(`
            DELETE FROM sticker_favorites
            WHERE user_id = ?
              AND sticker_id = ?
        `, [req.user.id, stickerId]);

        res.json({
            sticker_id: stickerId,
            favorited: false,
        });
    } catch (err) {
        console.error("Erro ao remover figurinha dos favoritos:", err);
        res.status(500).json({ error: "Erro ao remover figurinha dos favoritos." });
    }
});

// POST enviar mensagem direta
route.post("/chat/enviar-direto", authMiddleware, async (req, res) => {
    try {
        const {
            usuario_id,
            mensagem,
            tipo_mensagem = "texto",
            anexo_nome = null,
            anexo_mime = null,
            resposta_mensagem_id = null,
            sticker_id = null,
        } = req.body;
        const remetente_id = req.user.id;
        let mensagemFinal = mensagem;
        let anexoNomeFinal = anexo_nome;
        let anexoMimeFinal = anexo_mime;
        let stickerIdFinal = null;

        await garantirTipoMensagemAudio();

        if (tipo_mensagem === "sticker") {
            const sticker = await prepararStickerParaEnvio({
                stickerId: sticker_id,
                usuario: req.user,
            });

            stickerIdFinal = sticker.id;
            mensagemFinal = sticker.file_url;
            anexoNomeFinal = "Figurinha";
            anexoMimeFinal = sticker.mime || "image/webp";
        }

        const erroMensagem = validarMensagem({
            tipo_mensagem,
            mensagem: mensagemFinal,
            anexo_mime: anexoMimeFinal,
            sticker_id: stickerIdFinal,
        });

        if (!usuario_id || erroMensagem) {
            return res.status(400).json({ error: erroMensagem || "Dados inválidos" });
        }

        const [destinatario] = await db.query(`
            SELECT id
            FROM usuarios
            WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [usuario_id, req.user.empresa_id]);

        if (!destinatario.length) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        // Buscar ou criar conversa
        let [conversa] = await db.query(`
            SELECT id FROM conversas_diretas 
            WHERE (
                (usuario1_id = ? AND usuario2_id = ?) 
                OR (usuario1_id = ? AND usuario2_id = ?)
            )
        `, [remetente_id, usuario_id, usuario_id, remetente_id]);

        if (!conversa.length) {
            await db.query(`
                INSERT INTO conversas_diretas (usuario1_id, usuario2_id) 
                VALUES (?, ?)
            `, [remetente_id, usuario_id]);

            [conversa] = await db.query(`
                SELECT id FROM conversas_diretas 
                WHERE (usuario1_id = ? AND usuario2_id = ?) 
                   OR (usuario1_id = ? AND usuario2_id = ?)
            `, [remetente_id, usuario_id, usuario_id, remetente_id]);
        }

        const mensagemRespondida = await buscarMensagemRespondida({
            mensagemId: resposta_mensagem_id,
            conversaDiretaId: conversa[0].id,
        });

        if (resposta_mensagem_id && !mensagemRespondida) {
            return res.status(400).json({ error: "Mensagem respondida não encontrada" });
        }

        // Inserir mensagem
        const [result] = await db.query(`
            INSERT INTO mensagens (
                remetente_id,
                conversa_direta_id,
                mensagem,
                tipo_mensagem,
                anexo_nome,
                anexo_mime,
                sticker_id,
                resposta_mensagem_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            remetente_id,
            conversa[0].id,
            mensagemFinal,
            tipo_mensagem,
            anexoNomeFinal,
            anexoMimeFinal,
            stickerIdFinal,
            mensagemRespondida?.resposta_mensagem_id || null,
        ]);

        const mensagem_id = result.insertId;

        if (stickerIdFinal) {
            await registrarStickerRecente(remetente_id, stickerIdFinal);
        }

        await db.query(`
            UPDATE conversas_diretas
            SET atualizada_em = NOW()
            WHERE id = ?
        `, [conversa[0].id]);

        await garantirTabelaConversasOcultas();

        await db.query(`
            DELETE FROM conversas_ocultas_usuario
            WHERE conversa_direta_id = ?
              AND usuario_id IN (?, ?)
        `, [conversa[0].id, remetente_id, usuario_id]);

        await registrarAuditoriaMensagem({
            mensagemId: mensagem_id,
            usuarioId: remetente_id,
            acao: "enviada",
            valorNovo: {
                conversa_direta_id: conversa[0].id,
                destinatario_id: Number(usuario_id),
                tipo_mensagem,
                anexo_nome: anexoNomeFinal,
                sticker_id: stickerIdFinal,
                resposta_mensagem_id: mensagemRespondida?.resposta_mensagem_id || null,
            },
            req,
        });

        res.json({
            id: mensagem_id,
            remetente_id,
            mensagem: mensagemFinal,
            tipo_mensagem,
            anexo_nome: anexoNomeFinal,
            anexo_mime: anexoMimeFinal,
            sticker_id: stickerIdFinal,
            resposta_mensagem_id: mensagemRespondida?.resposta_mensagem_id || null,
            resposta_remetente_id: mensagemRespondida?.resposta_remetente_id || null,
            resposta_remetente_nome: mensagemRespondida?.resposta_remetente_nome || null,
            resposta_tipo_mensagem: mensagemRespondida?.resposta_tipo_mensagem || null,
            resposta_mensagem: mensagemRespondida?.resposta_mensagem || null,
            resposta_anexo_nome: mensagemRespondida?.resposta_anexo_nome || null,
            resposta_sticker_id: mensagemRespondida?.resposta_sticker_id || null,
            resposta_previa: mensagemRespondida?.resposta_previa || null,
            lida: false,
            entregue_em: null,
            lida_em: null,
            favoritada: false,
            reacoes: [],
            conversa_id: conversa[0].id,
            criada_em: new Date()
        });
    } catch (err) {
        console.error("Erro ao enviar mensagem:", err);
        res.status(err.status || 500).json({ error: err.status ? err.message : "Erro ao enviar mensagem" });
    }
});

// POST enviar mensagem em grupo
route.post("/chat/enviar-grupo", authMiddleware, async (req, res) => {
    try {
        const {
            grupo_id,
            mensagem,
            tipo_mensagem = "texto",
            anexo_nome = null,
            anexo_mime = null,
            resposta_mensagem_id = null,
            sticker_id = null,
        } = req.body;
        const remetente_id = req.user.id;
        let mensagemFinal = mensagem;
        let anexoNomeFinal = anexo_nome;
        let anexoMimeFinal = anexo_mime;
        let stickerIdFinal = null;

        await garantirTipoMensagemAudio();

        if (tipo_mensagem === "sticker") {
            const sticker = await prepararStickerParaEnvio({
                stickerId: sticker_id,
                usuario: req.user,
            });

            stickerIdFinal = sticker.id;
            mensagemFinal = sticker.file_url;
            anexoNomeFinal = "Figurinha";
            anexoMimeFinal = sticker.mime || "image/webp";
        }

        const erroMensagem = validarMensagem({
            tipo_mensagem,
            mensagem: mensagemFinal,
            anexo_mime: anexoMimeFinal,
            sticker_id: stickerIdFinal,
        });

        if (!grupo_id || erroMensagem) {
            return res.status(400).json({ error: erroMensagem || "Dados inválidos" });
        }

        const grupo = await buscarGrupoDaEmpresa(grupo_id, req.user.empresa_id);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        // Verificar se é membro
        const [membro] = await db.query(`
            SELECT id FROM grupo_membros 
            WHERE grupo_id = ? AND usuario_id = ?
        `, [grupo_id, remetente_id]);

        if (!membro.length) {
            return res.status(403).json({ error: "Acesso negado" });
        }

        const mencoes = tipo_mensagem === "texto"
            ? await detectarMencoesGrupo({ grupoId: grupo_id, mensagem: mensagemFinal, remetenteId: remetente_id })
            : [];

        const mensagemRespondida = await buscarMensagemRespondida({
            mensagemId: resposta_mensagem_id,
            grupoId: grupo_id,
        });

        if (resposta_mensagem_id && !mensagemRespondida) {
            return res.status(400).json({ error: "Mensagem respondida não encontrada" });
        }

        // Inserir mensagem
        const [result] = await db.query(`
            INSERT INTO mensagens (
                remetente_id,
                grupo_id,
                mensagem,
                tipo_mensagem,
                anexo_nome,
                anexo_mime,
                sticker_id,
                resposta_mensagem_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            remetente_id,
            grupo_id,
            mensagemFinal,
            tipo_mensagem,
            anexoNomeFinal,
            anexoMimeFinal,
            stickerIdFinal,
            mensagemRespondida?.resposta_mensagem_id || null,
        ]);

        await marcarMensagemGrupoComoLidaPeloAutor(result.insertId, remetente_id);

        if (stickerIdFinal) {
            await registrarStickerRecente(remetente_id, stickerIdFinal);
        }

        await registrarAuditoriaMensagem({
            mensagemId: result.insertId,
            usuarioId: remetente_id,
            acao: "enviada",
            valorNovo: {
                grupo_id: Number(grupo_id),
                tipo_mensagem,
                anexo_nome: anexoNomeFinal,
                sticker_id: stickerIdFinal,
                mencoes: mencoes.map((mencao) => mencao.id),
                resposta_mensagem_id: mensagemRespondida?.resposta_mensagem_id || null,
            },
            req,
        });

        res.json({
            id: result.insertId,
            remetente_id,
            grupo_id,
            mensagem: mensagemFinal,
            tipo_mensagem,
            anexo_nome: anexoNomeFinal,
            anexo_mime: anexoMimeFinal,
            sticker_id: stickerIdFinal,
            resposta_mensagem_id: mensagemRespondida?.resposta_mensagem_id || null,
            resposta_remetente_id: mensagemRespondida?.resposta_remetente_id || null,
            resposta_remetente_nome: mensagemRespondida?.resposta_remetente_nome || null,
            resposta_tipo_mensagem: mensagemRespondida?.resposta_tipo_mensagem || null,
            resposta_mensagem: mensagemRespondida?.resposta_mensagem || null,
            resposta_anexo_nome: mensagemRespondida?.resposta_anexo_nome || null,
            resposta_sticker_id: mensagemRespondida?.resposta_sticker_id || null,
            resposta_previa: mensagemRespondida?.resposta_previa || null,
            mencoes,
            total_entregas: 1,
            total_leituras: 1,
            favoritada: false,
            reacoes: [],
            criada_em: new Date()
        });
    } catch (err) {
        console.error("Erro ao enviar mensagem:", err);
        res.status(err.status || 500).json({ error: err.status ? err.message : "Erro ao enviar mensagem" });
    }
});

route.put("/chat/mensagens/:id", authMiddleware, async (req, res) => {
    try {
        const mensagemId = Number(req.params.id);
        const { mensagem } = req.body;
        const remetenteId = req.user.id;
        const usuarioEhAdmin = req.user?.perfil === PERFIL_ADMIN;

        if (!mensagem || !mensagem.trim()) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        const [rows] = await db.query(`
            SELECT
                m.id,
                m.tipo_mensagem,
                m.remetente_id,
                m.mensagem,
                m.criada_em,
                m.deletada_em,
                m.conversa_direta_id,
                m.grupo_id,
                u1.empresa_id AS usuario1_empresa_id,
                u2.empresa_id AS usuario2_empresa_id,
                g.empresa_id AS grupo_empresa_id
            FROM mensagens m
            LEFT JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id
            LEFT JOIN usuarios u1 ON u1.id = cd.usuario1_id
            LEFT JOIN usuarios u2 ON u2.id = cd.usuario2_id
            LEFT JOIN grupos g ON g.id = m.grupo_id
            WHERE m.id = ?
            LIMIT 1
        `, [mensagemId]);

        if (!rows.length) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        const msg = rows[0];
        const mensagemDaEmpresa =
            (msg.conversa_direta_id && Number(msg.usuario1_empresa_id) === Number(req.user.empresa_id) && Number(msg.usuario2_empresa_id) === Number(req.user.empresa_id)) ||
            (msg.grupo_id && Number(msg.grupo_empresa_id) === Number(req.user.empresa_id));

        if (!mensagemDaEmpresa) {
            return res.status(403).json({ error: "Acesso negado." });
        }

        if (Number(msg.remetente_id) !== Number(remetenteId) && !usuarioEhAdmin) {
            return res.status(403).json({ error: "Acesso negado." });
        }

        if (msg.deletada_em) {
            return res.status(400).json({ error: "Não é possível editar uma mensagem removida." });
        }

        if (msg.tipo_mensagem !== "texto") {
            return res.status(400).json({ error: "Apenas mensagens de texto podem ser editadas." });
        }

        await db.query(`
            UPDATE mensagens
            SET mensagem = ?, editada_em = NOW()
            WHERE id = ?
        `, [mensagem.trim(), mensagemId]);

        await registrarAuditoriaMensagem({
            mensagemId,
            usuarioId: remetenteId,
            acao: "editada",
            valorAntigo: { mensagem: msg.mensagem },
            valorNovo: { mensagem: mensagem.trim() },
            req,
        });

        const [updatedRows] = await db.query(`
            SELECT *
            FROM mensagens
            WHERE id = ?
        `, [mensagemId]);

        const mensagemAtualizada = updatedRows[0];
        const io = req.app.get("io");

        if (io) {
            const payload = {
                message_id: mensagemId,
                id: mensagemId,
                conversa_direta_id: mensagemAtualizada.conversa_direta_id || null,
                grupo_id: mensagemAtualizada.grupo_id || null,
                mensagem: mensagemAtualizada.mensagem,
                editada_em: mensagemAtualizada.editada_em,
                editada_por: remetenteId,
            };

            if (mensagemAtualizada.grupo_id) {
                io.to(`grupo_${mensagemAtualizada.grupo_id}`).emit("message_updated", payload);
            }

            if (mensagemAtualizada.conversa_direta_id) {
                io.to(`conversa_${mensagemAtualizada.conversa_direta_id}`).emit("message_updated", payload);
            }
        }

        res.json(mensagemAtualizada);
    } catch (err) {
        console.error("Erro ao editar mensagem:", err);
        res.status(500).json({ error: "Erro ao editar mensagem." });
    }
});

route.delete("/chat/mensagens/:id", authMiddleware, async (req, res) => {
    try {
        const mensagemId = Number(req.params.id);
        const escopo = req.body?.escopo || "mim";
        const userId = req.user.id;
        const usuarioEhAdmin = req.user?.perfil === PERFIL_ADMIN;

        if (!Number.isInteger(mensagemId)) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        if (!["mim", "todos"].includes(escopo)) {
            return res.status(400).json({ error: "Tipo de exclusão inválido." });
        }

        await garantirTabelaMensagensOcultas();

        const [rows] = await db.query(`
            SELECT
                m.id,
                m.remetente_id,
                m.conversa_direta_id,
                m.grupo_id,
                m.criada_em,
                m.deletada_em,
                cd.usuario1_id,
                cd.usuario2_id
            FROM mensagens m
            LEFT JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
            WHERE m.id = ?
            LIMIT 1
        `, [mensagemId]);

        if (!rows.length) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        const msg = rows[0];
        let temAcesso = false;

        if (msg.conversa_direta_id) {
            temAcesso =
                Number(msg.usuario1_id) === Number(userId) ||
                Number(msg.usuario2_id) === Number(userId);
        }

        if (msg.grupo_id) {
            const [membro] = await db.query(`
                SELECT id FROM grupo_membros
                WHERE grupo_id = ? AND usuario_id = ?
                LIMIT 1
            `, [msg.grupo_id, userId]);

            temAcesso = membro.length > 0;
        }

        if (!temAcesso) {
            return res.status(403).json({ error: "Acesso negado." });
        }

        if (escopo === "mim") {
            await db.query(`
                INSERT IGNORE INTO mensagens_ocultas_usuario (mensagem_id, usuario_id)
                VALUES (?, ?)
            `, [mensagemId, userId]);

            return res.json({
                id: mensagemId,
                escopo,
                conversa_direta_id: msg.conversa_direta_id,
                grupo_id: msg.grupo_id,
            });
        }

        if (msg.remetente_id !== userId && !usuarioEhAdmin) {
            return res.status(403).json({ error: "Você só pode apagar para todos mensagens enviadas por você." });
        }

        if (msg.deletada_em) {
            return res.status(400).json({ error: "Mensagem já apagada." });
        }

        await garantirAuditoriaMensagens();

        await db.query(`
            UPDATE mensagens
            SET deletada_em = COALESCE(deletada_em, NOW()),
                deletada_por = COALESCE(deletada_por, ?)
            WHERE id = ?
        `, [userId, mensagemId]);

        await registrarAuditoriaMensagem({
            mensagemId,
            usuarioId: userId,
            acao: "apagada",
            valorAntigo: { deletada_em: msg.deletada_em },
            valorNovo: { escopo: "todos" },
            req,
        });

        res.json({
            id: mensagemId,
            escopo,
            conversa_direta_id: msg.conversa_direta_id,
            grupo_id: msg.grupo_id,
        });
    } catch (err) {
        console.error("Erro ao apagar mensagem:", err);
        res.status(500).json({ error: "Erro ao apagar mensagem." });
    }
});

route.delete("/chat/conversa-direta/:usuario_id", authMiddleware, async (req, res) => {
    try {
        const { usuario_id } = req.params;
        const userId = req.user.id;

        const [conversa] = await db.query(`
            SELECT id
            FROM conversas_diretas
            WHERE (usuario1_id = ? AND usuario2_id = ?)
               OR (usuario1_id = ? AND usuario2_id = ?)
            LIMIT 1
        `, [userId, usuario_id, usuario_id, userId]);

        if (!conversa.length) {
            return res.json({ success: true, total_ocultadas: 0 });
        }

        await garantirTabelaMensagensOcultas();

        const [result] = await db.query(`
            INSERT IGNORE INTO mensagens_ocultas_usuario (mensagem_id, usuario_id)
            SELECT id, ?
            FROM mensagens
            WHERE conversa_direta_id = ?
              AND deletada_em IS NULL
        `, [userId, conversa[0].id]);

        res.json({
            success: true,
            conversa_id: conversa[0].id,
            total_ocultadas: result.affectedRows || 0,
        });
    } catch (err) {
        console.error("Erro ao limpar conversa:", err);
        res.status(500).json({ error: "Erro ao limpar conversa." });
    }
});

route.delete("/chat/grupo/:grupo_id/conversa", authMiddleware, async (req, res) => {
    try {
        const { grupo_id } = req.params;
        const userId = req.user.id;
        const empresaId = req.user.empresa_id;

        const grupo = await buscarGrupoDaEmpresa(grupo_id, empresaId);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado." });
        }

        const [membro] = await db.query(`
            SELECT id FROM grupo_membros
            WHERE grupo_id = ? AND usuario_id = ?
            LIMIT 1
        `, [grupo_id, userId]);

        if (!membro.length) {
            return res.status(403).json({ error: "Acesso negado." });
        }

        await garantirTabelaMensagensOcultas();

        const [result] = await db.query(`
            INSERT IGNORE INTO mensagens_ocultas_usuario (mensagem_id, usuario_id)
            SELECT id, ?
            FROM mensagens
            WHERE grupo_id = ?
              AND deletada_em IS NULL
        `, [userId, grupo_id]);

        res.json({
            success: true,
            grupo_id,
            total_ocultadas: result.affectedRows || 0,
        });
    } catch (err) {
        console.error("Erro ao limpar conversa do grupo:", err);
        res.status(500).json({ error: "Erro ao limpar conversa." });
    }
});

// PUT atualizar status online
route.put("/chat/status/:status", authMiddleware, async (req, res) => {
    try {
        const { status } = req.params;
        const userId = req.user.id;

        if (!['online', 'offline', 'away'].includes(status)) {
            return res.status(400).json({ error: "Status inválido" });
        }

        await db.query(`
            UPDATE usuarios SET status = ?, ultimo_acesso = NOW() WHERE id = ?
        `, [status, userId]);

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao atualizar status:", err);
        res.status(500).json({ error: "Erro ao atualizar status" });
    }
});

route.get("/aviso-geral/pendente", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;
        const userId = req.user.id;

        await garantirAvisoGeralPadrao(empresaId, userId);

        const [rows] = await db.query(`
            SELECT
                a.id,
                a.titulo,
                a.mensagem,
                a.image_url,
                a.summary,
                a.tipo,
                a.categoria,
                a.prioridade,
                a.detail_url,
                a.detail_button_text,
                a.show_new_badge,
                a.require_confirmation,
                a.allow_close,
                a.allow_snooze,
                a.criado_por,
                u.nome AS criado_por_nome,
                a.criado_em,
                a.atualizado_em
            FROM avisos_gerais a
            LEFT JOIN usuarios u ON u.id = a.criado_por
            LEFT JOIN avisos_gerais_confirmacoes c
              ON c.aviso_id = a.id
             AND c.usuario_id = ?
            WHERE a.empresa_id = ?
              AND a.ativo = 1
              AND c.id IS NULL
            ORDER BY a.criado_em DESC, a.id DESC
            LIMIT 1
        `, [userId, empresaId]);

        res.json(rows[0] || null);
    } catch (err) {
        console.error("Erro ao buscar aviso geral pendente:", err);
        res.status(500).json({ error: "Erro ao buscar aviso geral." });
    }
});

route.post("/aviso-geral/:id/confirmar", authMiddleware, async (req, res) => {
    try {
        const avisoId = Number(req.params.id);
        const empresaId = req.user.empresa_id;
        const userId = req.user.id;

        if (!avisoId) {
            return res.status(400).json({ error: "Aviso inválido." });
        }

        await garantirAvisoGeralTabela();

        const [avisos] = await db.query(`
            SELECT id
            FROM avisos_gerais
            WHERE id = ?
              AND empresa_id = ?
              AND ativo = 1
            LIMIT 1
        `, [avisoId, empresaId]);

        if (!avisos.length) {
            return res.status(404).json({ error: "Aviso não encontrado." });
        }

        await db.query(`
            INSERT IGNORE INTO avisos_gerais_confirmacoes (aviso_id, usuario_id)
            VALUES (?, ?)
        `, [avisoId, userId]);

        res.json({
            success: true,
            aviso_id: avisoId,
            confirmado_em: new Date(),
        });
    } catch (err) {
        console.error("Erro ao confirmar aviso geral:", err);
        res.status(500).json({ error: "Erro ao confirmar aviso geral." });
    }
});

route.get("/internal-notices/pending", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;
        const userId = req.user.id;

        await garantirAvisoGeralPadrao(empresaId, userId);

        const [rows] = await db.query(`
            SELECT
                a.id,
                a.titulo,
                a.mensagem,
                a.image_url,
                a.summary,
                a.tipo,
                a.categoria,
                a.prioridade,
                a.resume_text,
                a.changes_json,
                a.important_info_json,
                a.action_required_json,
                a.detail_url,
                a.detail_button_text,
                a.show_new_badge,
                a.require_confirmation,
                a.allow_close,
                a.allow_snooze,
                a.starts_at,
                a.ends_at,
                a.criado_por,
                u.nome AS criado_por_nome,
                a.criado_em,
                a.atualizado_em
            FROM avisos_gerais a
            LEFT JOIN usuarios u ON u.id = a.criado_por
            LEFT JOIN avisos_gerais_confirmacoes c
              ON c.aviso_id = a.id
             AND c.usuario_id = ?
            LEFT JOIN avisos_gerais_sonecas s
              ON s.aviso_id = a.id
             AND s.usuario_id = ?
             AND s.snoozed_until > NOW()
            WHERE a.empresa_id = ?
              AND a.ativo = 1
              AND c.id IS NULL
              AND s.id IS NULL
              AND (a.starts_at IS NULL OR a.starts_at <= NOW())
              AND (a.ends_at IS NULL OR a.ends_at >= NOW())
            ORDER BY
              CASE a.prioridade
                WHEN 'critica' THEN 1
                WHEN 'alta' THEN 2
                WHEN 'media' THEN 3
                WHEN 'baixa' THEN 4
                ELSE 5
              END,
              a.criado_em DESC,
              a.id DESC
        `, [userId, userId, empresaId]);

        res.json(rows.map(serializarAvisoInterno));
    } catch (err) {
        console.error("Erro ao buscar avisos internos pendentes:", err);
        res.status(500).json({ error: "Erro ao buscar avisos internos pendentes." });
    }
});

route.post("/internal-notices/:id/read", authMiddleware, async (req, res) => {
    try {
        const noticeId = Number(req.params.id);
        const empresaId = req.user.empresa_id;
        const userId = req.user.id;

        if (!noticeId) {
            return res.status(400).json({ error: "Aviso inválido." });
        }

        await garantirAvisoGeralTabela();

        const [avisos] = await db.query(`
            SELECT id
            FROM avisos_gerais
            WHERE id = ?
              AND empresa_id = ?
              AND ativo = 1
              AND (starts_at IS NULL OR starts_at <= NOW())
              AND (ends_at IS NULL OR ends_at >= NOW())
            LIMIT 1
        `, [noticeId, empresaId]);

        if (!avisos.length) {
            return res.status(404).json({ error: "Aviso não encontrado." });
        }

        await db.query(`
            INSERT IGNORE INTO avisos_gerais_confirmacoes (aviso_id, usuario_id)
            VALUES (?, ?)
        `, [noticeId, userId]);

        res.json({
            success: true,
            notice_id: noticeId,
            read_at: new Date(),
        });
    } catch (err) {
        console.error("Erro ao confirmar leitura do aviso interno:", err);
        res.status(500).json({ error: "Erro ao confirmar leitura do aviso." });
    }
});

route.post("/internal-notices/:id/snooze", authMiddleware, async (req, res) => {
    try {
        const noticeId = Number(req.params.id);
        const empresaId = req.user.empresa_id;
        const userId = req.user.id;
        const minutes = Math.min(
            Math.max(Number(req.body?.minutes || req.body?.minutos || 120), 15),
            1440
        );

        if (!noticeId) {
            return res.status(400).json({ error: "Aviso inválido." });
        }

        await garantirAvisoGeralTabela();

        const [avisos] = await db.query(`
            SELECT id, prioridade, allow_snooze
            FROM avisos_gerais
            WHERE id = ?
              AND empresa_id = ?
              AND ativo = 1
              AND (starts_at IS NULL OR starts_at <= NOW())
              AND (ends_at IS NULL OR ends_at >= NOW())
            LIMIT 1
        `, [noticeId, empresaId]);

        const aviso = avisos[0];

        if (!aviso) {
            return res.status(404).json({ error: "Aviso não encontrado." });
        }

        if (!aviso.allow_snooze || normalizarPrioridadeAvisoInterno(aviso.prioridade) === "critica") {
            return res.status(403).json({ error: "Este aviso exige confirmação de leitura." });
        }

        const snoozedUntil = new Date(Date.now() + minutes * 60 * 1000);

        await db.query(`
            INSERT INTO avisos_gerais_sonecas (aviso_id, usuario_id, snoozed_until)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                snoozed_until = VALUES(snoozed_until),
                criado_em = CURRENT_TIMESTAMP
        `, [noticeId, userId, snoozedUntil]);

        res.json({
            success: true,
            notice_id: noticeId,
            snoozed_until: snoozedUntil,
        });
    } catch (err) {
        console.error("Erro ao lembrar aviso interno depois:", err);
        res.status(500).json({ error: "Erro ao lembrar aviso depois." });
    }
});

route.get("/avisos-internos", authMiddleware, async (req, res) => {
    try {
        const {
            conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        } = await buscarConteudoAvisosInternos(req.user.empresa_id);

        res.json({
            ...conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        });
    } catch (err) {
        console.error("Erro ao buscar avisos internos:", err);
        res.status(500).json({ error: "Erro ao buscar avisos internos" });
    }
});

route.get("/wiki", authMiddleware, async (req, res) => {
    try {
        const {
            conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        } = await buscarConteudoWikiInterna(req.user.empresa_id);

        res.json({
            ...conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        });
    } catch (err) {
        console.error("Erro ao buscar wiki interna:", err);
        res.status(500).json({ error: "Erro ao buscar wiki interna" });
    }
});

route.put("/wiki", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const usuarioId = req.admin.id;
        const conteudo = normalizarConteudoWikiInterna(req.body || {});
        const conteudoJson = JSON.stringify(conteudo);

        await garantirWikiInternaTabela();

        await db.query(`
            INSERT INTO wiki_interna_config (empresa_id, conteudo_json, atualizado_por)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                conteudo_json = VALUES(conteudo_json),
                atualizado_por = VALUES(atualizado_por),
                atualizado_em = CURRENT_TIMESTAMP
        `, [empresaId, conteudoJson, usuarioId]);

        const wiki = await buscarConteudoWikiInterna(empresaId);

        res.json({
            success: true,
            ...wiki.conteudo,
            atualizado_em: wiki.atualizado_em,
            atualizado_por: usuarioId,
            atualizado_por_nome: req.admin.nome,
        });
    } catch (err) {
        console.error("Erro ao salvar wiki interna:", err);
        res.status(500).json({ error: "Erro ao salvar wiki interna" });
    }
});

route.get("/wiki/progresso", authMiddleware, async (req, res) => {
    try {
        const progresso = await buscarProgressoWikiUsuario(req.user.empresa_id, req.user.id);

        res.json(progresso);
    } catch (err) {
        console.error("Erro ao buscar progresso da wiki:", err);
        res.status(500).json({ error: "Erro ao buscar progresso da wiki" });
    }
});

route.get("/wiki/curso/:cursoId/config", authMiddleware, async (req, res) => {
    try {
        const cursoId = normalizarSlugWikiCurso(req.params.cursoId, "");

        if (!cursoId) {
            return res.status(400).json({ error: "Curso inválido" });
        }

        const resultado = await buscarConfigWikiCurso(req.user.empresa_id, cursoId);

        res.json(resultado);
    } catch (err) {
        console.error("Erro ao buscar configuração do curso da wiki:", err);
        res.status(500).json({ error: "Erro ao buscar configuração do curso" });
    }
});

route.put(
    "/wiki/curso/:cursoId/config",
    authMiddleware,
    requireAdmin,
    async (req, res) => {
        try {
            const cursoId = normalizarSlugWikiCurso(req.params.cursoId, "");

            if (!cursoId) {
                return res.status(400).json({ error: "Curso inválido" });
            }

            const empresaId = req.admin.empresa_id;
            const usuarioId = req.admin.id;
            const config = normalizarConfigWikiCurso(req.body || {});

            if (!config.modules.length) {
                return res.status(400).json({ error: "Informe ao menos um módulo" });
            }

            await garantirWikiCursosConfigTabela();
            await db.query(`
                INSERT INTO wiki_cursos_config (
                    empresa_id,
                    curso_id,
                    conteudo_json,
                    atualizado_por
                )
                VALUES (?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    conteudo_json = VALUES(conteudo_json),
                    atualizado_por = VALUES(atualizado_por),
                    atualizado_em = CURRENT_TIMESTAMP
            `, [empresaId, cursoId, JSON.stringify(config), usuarioId]);

            const resultado = await buscarConfigWikiCurso(empresaId, cursoId);

            res.json({
                success: true,
                ...resultado,
                atualizado_por: usuarioId,
                atualizado_por_nome: req.admin.nome,
            });
        } catch (err) {
            console.error("Erro ao salvar configuração do curso da wiki:", err);
            res.status(500).json({ error: "Erro ao salvar configuração do curso" });
        }
    }
);

route.get(
    "/wiki/curso/:cursoId/aula/:contentKey/config",
    authMiddleware,
    async (req, res) => {
        try {
            const cursoId = normalizarSlugWikiCurso(req.params.cursoId, "");
            const aulaChave = normalizarSlugWikiCurso(req.params.contentKey, "");

            if (!cursoId || !aulaChave) {
                return res.status(400).json({ error: "Curso ou aula inválidos" });
            }

            const resultado = await buscarConteudoWikiAula(
                req.user.empresa_id,
                cursoId,
                aulaChave
            );

            res.json(resultado);
        } catch (err) {
            console.error("Erro ao buscar conteúdo da aula da wiki:", err);
            res.status(500).json({ error: "Erro ao buscar conteúdo da aula" });
        }
    }
);

route.put(
    "/wiki/curso/:cursoId/aula/:contentKey/config",
    authMiddleware,
    requireAdmin,
    async (req, res) => {
        try {
            const cursoId = normalizarSlugWikiCurso(req.params.cursoId, "");
            const aulaChave = normalizarSlugWikiCurso(req.params.contentKey, "");

            if (!cursoId || !aulaChave) {
                return res.status(400).json({ error: "Curso ou aula inválidos" });
            }

            const empresaId = req.admin.empresa_id;
            const usuarioId = req.admin.id;
            const content = normalizarConteudoWikiAula(req.body || {});

            if (!content.summary) {
                return res.status(400).json({ error: "Informe o resumo da aula" });
            }

            await garantirWikiAulasConfigTabela();
            await db.query(`
                INSERT INTO wiki_aulas_config (
                    empresa_id,
                    curso_id,
                    aula_chave,
                    conteudo_json,
                    atualizado_por
                )
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    conteudo_json = VALUES(conteudo_json),
                    atualizado_por = VALUES(atualizado_por),
                    atualizado_em = CURRENT_TIMESTAMP
            `, [empresaId, cursoId, aulaChave, JSON.stringify(content), usuarioId]);

            const resultado = await buscarConteudoWikiAula(
                empresaId,
                cursoId,
                aulaChave
            );

            res.json({
                success: true,
                ...resultado,
                atualizado_por: usuarioId,
                atualizado_por_nome: req.admin.nome,
            });
        } catch (err) {
            console.error("Erro ao salvar conteúdo da aula da wiki:", err);
            res.status(500).json({ error: "Erro ao salvar conteúdo da aula" });
        }
    }
);

route.get("/wiki/curso/:cursoId/progresso", authMiddleware, async (req, res) => {
    try {
        const cursoId = normalizarSlugWikiCurso(req.params.cursoId, "");

        if (!cursoId) {
            return res.status(400).json({ error: "Curso inválido" });
        }

        const progresso = await buscarProgressoWikiCurso(
            req.user.empresa_id,
            req.user.id,
            cursoId
        );

        res.json(progresso);
    } catch (err) {
        console.error("Erro ao buscar progresso do curso da wiki:", err);
        res.status(500).json({ error: "Erro ao buscar progresso do curso" });
    }
});

route.put(
    "/wiki/curso/:cursoId/aula/:contentKey/progresso",
    authMiddleware,
    async (req, res) => {
        try {
            const cursoId = normalizarSlugWikiCurso(req.params.cursoId, "");
            const aulaChave = normalizarSlugWikiCurso(req.params.contentKey, "");

            if (!cursoId || !aulaChave) {
                return res.status(400).json({ error: "Curso ou aula inválidos" });
            }

            const empresaId = req.user.empresa_id;
            const usuarioId = req.user.id;
            const atualizaConclusao = typeof req.body?.concluida === "boolean";

            await garantirWikiAulasProgressoTabela();

            if (atualizaConclusao) {
                const concluida = req.body.concluida ? 1 : 0;

                await db.query(`
                    INSERT INTO wiki_aulas_progresso (
                        empresa_id,
                        usuario_id,
                        curso_id,
                        aula_chave,
                        concluida,
                        acessada_em,
                        concluida_em
                    )
                    VALUES (?, ?, ?, ?, ?, NOW(), ${concluida ? "NOW()" : "NULL"})
                    ON DUPLICATE KEY UPDATE
                        concluida = VALUES(concluida),
                        acessada_em = NOW(),
                        concluida_em = ${concluida ? "NOW()" : "NULL"},
                        atualizado_em = CURRENT_TIMESTAMP
                `, [empresaId, usuarioId, cursoId, aulaChave, concluida]);
            } else {
                await db.query(`
                    INSERT INTO wiki_aulas_progresso (
                        empresa_id,
                        usuario_id,
                        curso_id,
                        aula_chave,
                        acessada_em
                    )
                    VALUES (?, ?, ?, ?, NOW())
                    ON DUPLICATE KEY UPDATE
                        acessada_em = NOW(),
                        atualizado_em = CURRENT_TIMESTAMP
                `, [empresaId, usuarioId, cursoId, aulaChave]);
            }

            const progresso = await buscarProgressoWikiCurso(empresaId, usuarioId, cursoId);

            res.json({
                success: true,
                ...progresso,
            });
        } catch (err) {
            console.error("Erro ao salvar progresso do curso da wiki:", err);
            res.status(500).json({ error: "Erro ao salvar progresso da aula" });
        }
    }
);

route.post(
    "/wiki/curso/:cursoId/aula/:contentKey/upload",
    authMiddleware,
    requireAdmin,
    uploadWikiMediaMiddleware,
    async (req, res) => {
        if (!req.file) {
            return res.status(400).json({ error: "Nenhum arquivo enviado" });
        }

        const empresaDiretorio = normalizarSegmentoUpload(req.admin.empresa_id);
        const cursoDiretorio = normalizarSegmentoUpload(req.params.cursoId);
        const aulaDiretorio = normalizarSegmentoUpload(req.params.contentKey);
        const url = `/uploads/wiki/${empresaDiretorio}/${cursoDiretorio}/${aulaDiretorio}/${req.file.filename}`;
        const type = obterTipoArquivoWiki(req.file);

        try {
            if (["pdf", "powerpoint", "excel"].includes(type)) {
                const previewFilename = await converterDocumentoWikiParaPdf(req.file, type);
                const previewUrl = `/uploads/wiki/${empresaDiretorio}/${cursoDiretorio}/${aulaDiretorio}/${previewFilename}`;

                return res.status(201).json({
                    id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
                    type,
                    url,
                    previewUrl,
                    name: req.file.originalname,
                    mime: req.file.mimetype,
                    size: req.file.size,
                    limite_mb: WIKI_MEDIA_MAX_SIZE_MB,
                });
            }

            return res.status(201).json({
                id: `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
                type,
                url,
                name: req.file.originalname,
                caption: "",
                mime: req.file.mimetype,
                size: req.file.size,
                limite_mb: WIKI_MEDIA_MAX_SIZE_MB,
            });
        } catch (err) {
            console.error("Erro ao preparar documento da aula:", err);
            fs.rmSync(req.file.path, { force: true });
            return res.status(422).json({
                error: "Não foi possível preparar a visualização do documento.",
            });
        }
    }
);

route.get("/agenda-tecnicos/resumo", authMiddleware, (_req, res) => {
    res.set("Cache-Control", "no-store").json(obterResumoAgendaTecnicos());
});

route.get("/banner-home", authMiddleware, async (req, res) => {
    try {
        const banner = await buscarConteudoBannerHome(req.user.empresa_id);

        res.json({
            ...banner.conteudo,
            atualizado_em: banner.atualizado_em,
            atualizado_por: banner.atualizado_por,
            atualizado_por_nome: banner.atualizado_por_nome,
        });
    } catch (err) {
        console.error("Erro ao buscar banner da home:", err);
        res.status(500).json({ error: "Erro ao buscar banner da home" });
    }
});

route.put("/banner-home", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const usuarioId = req.admin.id;
        const conteudo = normalizarConteudoBannerHome(req.body || {});

        if (conteudo.modo === "imagem" && !conteudo.imagem_url) {
            return res.status(400).json({
                error: "Envie uma imagem antes de publicar o banner em modo imagem.",
            });
        }

        const conteudoJson = JSON.stringify(conteudo);

        await garantirBannerHomeTabela();

        await db.query(`
            INSERT INTO banner_home_config (empresa_id, conteudo_json, atualizado_por)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                conteudo_json = VALUES(conteudo_json),
                atualizado_por = VALUES(atualizado_por),
                atualizado_em = CURRENT_TIMESTAMP
        `, [empresaId, conteudoJson, usuarioId]);

        const banner = await buscarConteudoBannerHome(empresaId);

        res.json({
            success: true,
            ...banner.conteudo,
            atualizado_em: banner.atualizado_em,
            atualizado_por: usuarioId,
            atualizado_por_nome: req.admin.nome,
        });
    } catch (err) {
        console.error("Erro ao salvar banner da home:", err);
        res.status(500).json({ error: "Erro ao salvar banner da home" });
    }
});

route.post(
    "/banner-home/upload",
    authMiddleware,
    requireAdmin,
    uploadBannerHomeMiddleware,
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: "Envie uma imagem para o banner." });
            }

            const empresaDiretorio = normalizarSegmentoUpload(req.admin.empresa_id);
            const url = `/uploads/banner-home/${empresaDiretorio}/${req.file.filename}`;

            res.status(201).json({
                url,
                nome: req.file.originalname,
                mime: req.file.mimetype,
                tamanho: req.file.size,
                limite_mb: BANNER_HOME_IMAGE_MAX_SIZE_MB,
            });
        } catch (err) {
            console.error("Erro ao salvar imagem do banner da home:", err);
            if (req.file?.path) {
                fs.rmSync(req.file.path, { force: true });
            }
            res.status(500).json({ error: "Erro ao salvar imagem do banner da home" });
        }
    }
);

// ========================================
// GALERIA DE IMAGENS
// ========================================

route.get("/imagens", authMiddleware, async (req, res) => {
    try {
        await garantirImagensGaleriaTabela();

        const [imagens] = await db.query(`
            SELECT g.id, g.titulo, g.descricao, g.imagem_url, g.criado_em, g.criado_por, u.nome AS criado_por_nome
            FROM imagens_galeria g
            LEFT JOIN usuarios u ON u.id = g.criado_por
            WHERE g.empresa_id = ?
            ORDER BY g.criado_em DESC
        `, [req.user.empresa_id]);

        res.json({
            images: imagens,
            can_manage: req.user.perfil === PERFIL_ADMIN,
            limite_mb: IMAGENS_GALERIA_MAX_SIZE_MB,
        });
    } catch (err) {
        console.error("Erro ao listar imagens da galeria:", err);
        res.status(500).json({ error: "Erro ao listar imagens." });
    }
});

route.post(
    "/admin/imagens",
    authMiddleware,
    requireAdmin,
    uploadImagemGaleriaMiddleware,
    async (req, res) => {
        try {
            if (!req.file) {
                return res.status(400).json({ error: "Envie uma imagem." });
            }

            await garantirImagensGaleriaTabela();

            const empresaDiretorio = normalizarSegmentoUpload(req.admin.empresa_id);
            const imagemUrl = `/uploads/imagens/${empresaDiretorio}/${req.file.filename}`;
            const titulo = String(req.body?.titulo || "").trim().slice(0, 255);
            const descricao = String(req.body?.descricao || "").trim().slice(0, 2000) || null;

            const [result] = await db.query(`
                INSERT INTO imagens_galeria (empresa_id, titulo, descricao, imagem_url, criado_por)
                VALUES (?, ?, ?, ?, ?)
            `, [req.admin.empresa_id, titulo, descricao, imagemUrl, req.admin.id]);

            res.status(201).json({
                id: result.insertId,
                titulo,
                descricao,
                imagem_url: imagemUrl,
                criado_por: req.admin.id,
                criado_por_nome: req.admin.nome,
                criado_em: new Date().toISOString(),
            });
        } catch (err) {
            console.error("Erro ao salvar imagem da galeria:", err);
            if (req.file?.path) {
                fs.rmSync(req.file.path, { force: true });
            }
            res.status(500).json({ error: "Erro ao salvar imagem." });
        }
    }
);

route.delete("/admin/imagens/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const imagemId = Number(req.params.id);

        if (!Number.isInteger(imagemId) || imagemId <= 0) {
            return res.status(400).json({ error: "Imagem inválida." });
        }

        await garantirImagensGaleriaTabela();

        const [rows] = await db.query(`
            SELECT id, imagem_url
            FROM imagens_galeria
            WHERE id = ? AND empresa_id = ?
            LIMIT 1
        `, [imagemId, req.admin.empresa_id]);

        const imagem = rows[0];

        if (!imagem) {
            return res.status(404).json({ error: "Imagem não encontrada." });
        }

        await db.query(`DELETE FROM imagens_galeria WHERE id = ? AND empresa_id = ?`, [imagemId, req.admin.empresa_id]);

        if (imagem.imagem_url && IMAGENS_GALERIA_URL_REGEX.test(imagem.imagem_url)) {
            const relativo = imagem.imagem_url.replace(/^\/uploads\/imagens\//, "");
            const caminhoArquivo = path.join(IMAGENS_GALERIA_UPLOAD_ROOT, ...relativo.split("/"));
            fs.rm(caminhoArquivo, { force: true }, () => {});
        }

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao excluir imagem da galeria:", err);
        res.status(500).json({ error: "Erro ao excluir imagem." });
    }
});

route.get("/ccna-competition", authMiddleware, async (req, res) => {
    try {
        const incluirProvasAdmin = req.user.perfil === PERFIL_ADMIN;
        const { config, participants } = await montarParticipantesCompeticaoCcna({
            incluirProvasAdmin,
            currentUserId: req.user.id,
        });
        const currentUserParticipant = participants.find(
            (participant) => Number(participant.user_id) === Number(req.user.id)
        ) || null;

        res.json({
            config,
            modules: CCNA_COMPETITION_MODULES,
            participants,
            current_user_participant: currentUserParticipant,
            is_admin: incluirProvasAdmin,
            company_asn: "266468",
        });
    } catch (err) {
        console.error("Erro ao buscar competição CCNA:", err);
        res.status(500).json({ error: "Erro ao buscar competição CCNA" });
    }
});

route.post("/ccna-competition/join", authMiddleware, async (req, res) => {
    const connection = await db.getConnection();

    try {
        await connection.beginTransaction();
        await garantirCompeticaoCcnaTabelas(connection);

        const [configRows] = await connection.query(`
            SELECT status
            FROM ccna_competition_config
            WHERE id = 1
            LIMIT 1
        `);

        if (configRows[0]?.status !== "ativa") {
            await connection.rollback();
            return res.status(409).json({ error: "Competição não está ativa" });
        }

        await connection.query(`
            INSERT INTO ccna_competition_participants (user_id, empresa_id, status)
            VALUES (?, ?, 'nao_iniciado')
            ON DUPLICATE KEY UPDATE user_id = user_id
        `, [req.user.id, req.user.empresa_id || null]);

        const [participantRows] = await connection.query(`
            SELECT id
            FROM ccna_competition_participants
            WHERE user_id = ?
            LIMIT 1
        `, [req.user.id]);

        const participantId = participantRows[0]?.id;
        if (participantId) {
            await garantirModulosParticipanteCcna(participantId, connection);
        }

        await connection.commit();

        const { config, participants } = await montarParticipantesCompeticaoCcna({
            incluirProvasAdmin: req.user.perfil === PERFIL_ADMIN,
            currentUserId: req.user.id,
        });

        res.json({
            success: true,
            config,
            participants,
            current_user_participant: participants.find(
                (participant) => Number(participant.user_id) === Number(req.user.id)
            ) || null,
        });
    } catch (err) {
        await connection.rollback();
        console.error("Erro ao participar da competição CCNA:", err);
        res.status(500).json({ error: "Erro ao participar da competição CCNA" });
    } finally {
        connection.release();
    }
});

route.put("/ccna-competition/modules/:moduleId", authMiddleware, ccnaProofUploadMiddleware, async (req, res) => {
    try {
        await garantirCompeticaoCcnaTabelas();

        const moduleId = String(req.params.moduleId || "").trim();
        if (!CCNA_VALID_MODULE_IDS.includes(moduleId)) {
            return res.status(404).json({ error: "Módulo não encontrado" });
        }

        const [participantRows] = await db.query(`
            SELECT id
            FROM ccna_competition_participants
            WHERE user_id = ?
            LIMIT 1
        `, [req.user.id]);

        const participant = participantRows[0];
        if (!participant) {
            return res.status(403).json({ error: "Participe da competição antes de enviar comprovação" });
        }

        if (!req.file) {
            return res.status(400).json({ error: "Envie uma imagem de comprovação." });
        }

        const empresaDiretorio = normalizarSegmentoUpload(req.user?.empresa_id);
        const usuarioDiretorio = normalizarSegmentoUpload(req.user?.id);
        const proofUrl = `/uploads/ccna-competition/${empresaDiretorio}/${usuarioDiretorio}/${req.file.filename}`;

        await garantirModulosParticipanteCcna(participant.id);
        await db.query(`
            UPDATE ccna_competition_proofs
            SET
                proof_url = ?,
                status = 'enviado',
                submitted_at = NOW(),
                validated_by = NULL,
                validated_at = NULL,
                admin_note = NULL
            WHERE participant_id = ? AND module_id = ?
        `, [proofUrl, participant.id, moduleId]);

        const [proofRows] = await db.query(`
            SELECT status
            FROM ccna_competition_proofs
            WHERE participant_id = ?
        `, [participant.id]);

        const nextStatus = proofRows.some((proof) => proof.status === "enviado")
            ? "aguardando_validacao"
            : proofRows.some((proof) => proof.status !== "pendente")
                ? "em_andamento"
                : "nao_iniciado";

        await db.query(`
            UPDATE ccna_competition_participants
            SET status = ?
            WHERE id = ? AND status <> 'ganhador'
        `, [nextStatus, participant.id]);

        const { config, participants } = await montarParticipantesCompeticaoCcna({
            incluirProvasAdmin: req.user.perfil === PERFIL_ADMIN,
            currentUserId: req.user.id,
        });

        res.json({
            success: true,
            config,
            participants,
            current_user_participant: participants.find(
                (item) => Number(item.user_id) === Number(req.user.id)
            ) || null,
        });
    } catch (err) {
        console.error("Erro ao salvar módulo da competição CCNA:", err);
        res.status(500).json({ error: "Erro ao salvar módulo da competição CCNA" });
    }
});

route.patch("/ccna-competition/admin/modules/:participantId/:moduleId", authMiddleware, requireAdmin, async (req, res) => {
    try {
        await garantirCompeticaoCcnaTabelas();

        const participantId = Number(req.params.participantId);
        const moduleId = String(req.params.moduleId || "").trim();
        const status = String(req.body?.status || "").trim();
        const adminNote = String(req.body?.admin_note || "").trim().slice(0, 1000);

        if (!Number.isFinite(participantId) || participantId <= 0) {
            return res.status(400).json({ error: "Participante inválido" });
        }

        if (!CCNA_VALID_MODULE_IDS.includes(moduleId)) {
            return res.status(404).json({ error: "Módulo não encontrado" });
        }

        if (!["aprovado", "reprovado"].includes(status)) {
            return res.status(422).json({ error: "Status inválido" });
        }

        await garantirModulosParticipanteCcna(participantId);
        await db.query(`
            UPDATE ccna_competition_proofs
            SET
                status = ?,
                admin_note = ?,
                validated_by = ?,
                validated_at = NOW()
            WHERE participant_id = ? AND module_id = ?
        `, [status, adminNote || null, req.admin.id, participantId, moduleId]);

        const [proofRows] = await db.query(`
            SELECT status
            FROM ccna_competition_proofs
            WHERE participant_id = ?
        `, [participantId]);
        const approvedCount = proofRows.filter((proof) => proof.status === "aprovado").length;
        const sentCount = proofRows.filter((proof) => proof.status === "enviado").length;
        const nextStatus = approvedCount >= CCNA_COMPETITION_MODULES.length
            ? "validado"
            : sentCount > 0
                ? "aguardando_validacao"
                : "em_andamento";

        await db.query(`
            UPDATE ccna_competition_participants
            SET status = ?
            WHERE id = ? AND status <> 'ganhador'
        `, [nextStatus, participantId]);

        if (approvedCount >= CCNA_COMPETITION_MODULES.length) {
            await definirGanhadorCcnaSeNecessario(participantId, req.admin.id);
        }

        const { config, participants } = await montarParticipantesCompeticaoCcna({
            incluirProvasAdmin: true,
            currentUserId: req.user.id,
        });

        res.json({ success: true, config, participants });
    } catch (err) {
        console.error("Erro ao validar módulo CCNA:", err);
        res.status(500).json({ error: "Erro ao validar módulo CCNA" });
    }
});

route.patch("/ccna-competition/admin/participants/:participantId/status", authMiddleware, requireAdmin, async (req, res) => {
    try {
        await garantirCompeticaoCcnaTabelas();

        const participantId = Number(req.params.participantId);
        const status = String(req.body?.status || "").trim();

        if (!Number.isFinite(participantId) || participantId <= 0) {
            return res.status(400).json({ error: "Participante inválido" });
        }

        if (!CCNA_PARTICIPANT_STATUSES.includes(status)) {
            return res.status(422).json({ error: "Status inválido" });
        }

        if (status === "ganhador") {
            const [configRows] = await db.query(`
                SELECT winner_participant_id
                FROM ccna_competition_config
                WHERE id = 1
                LIMIT 1
            `);
            const winnerParticipantId = configRows[0]?.winner_participant_id;

            if (winnerParticipantId && Number(winnerParticipantId) !== Number(participantId)) {
                return res.status(409).json({ error: "A competição já possui ganhador definido" });
            }

            const [participantRows] = await db.query(`
                SELECT user_id
                FROM ccna_competition_participants
                WHERE id = ?
                LIMIT 1
            `, [participantId]);
            const participant = participantRows[0];

            if (!participant) {
                return res.status(404).json({ error: "Participante não encontrado" });
            }

            await db.query(`
                UPDATE ccna_competition_config
                SET
                    status = 'ganhador_definido',
                    winner_participant_id = ?,
                    winner_user_id = ?,
                    winner_defined_at = COALESCE(winner_defined_at, NOW()),
                    updated_by = ?
                WHERE id = 1
            `, [participantId, participant.user_id, req.admin.id]);
        }

        await db.query(`
            UPDATE ccna_competition_participants
            SET status = ?
            WHERE id = ?
        `, [status, participantId]);

        const { config, participants } = await montarParticipantesCompeticaoCcna({
            incluirProvasAdmin: true,
            currentUserId: req.user.id,
        });

        res.json({ success: true, config, participants });
    } catch (err) {
        console.error("Erro ao alterar status CCNA:", err);
        res.status(500).json({ error: "Erro ao alterar status CCNA" });
    }
});

route.put("/ccna-competition/admin/config", authMiddleware, requireAdmin, async (req, res) => {
    try {
        await garantirCompeticaoCcnaTabelas();

        const deadlineDate = String(req.body?.deadline_date || "").trim();
        const status = String(req.body?.status || "").trim();

        if (!/^\d{4}-\d{2}-\d{2}$/.test(deadlineDate)) {
            return res.status(422).json({ error: "Prazo inválido" });
        }

        if (!CCNA_COMPETITION_STATUSES.includes(status)) {
            return res.status(422).json({ error: "Status inválido" });
        }

        await db.query(`
            UPDATE ccna_competition_config
            SET deadline_date = ?, status = ?, updated_by = ?
            WHERE id = 1
        `, [deadlineDate, status, req.admin.id]);

        const { config, participants } = await montarParticipantesCompeticaoCcna({
            incluirProvasAdmin: true,
            currentUserId: req.user.id,
        });

        res.json({ success: true, config, participants });
    } catch (err) {
        console.error("Erro ao salvar configuração CCNA:", err);
        res.status(500).json({ error: "Erro ao salvar configuração CCNA" });
    }
});

route.get("/plantao-domingo", authMiddleware, async (req, res) => {
    try {
        const {
            conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        } = await buscarConteudoPlantaoDomingo(req.user.empresa_id);

        res.json({
            ...conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        });
    } catch (err) {
        console.error("Erro ao buscar plantão de domingo:", err);
        res.status(500).json({ error: "Erro ao buscar plantão de domingo" });
    }
});

route.put("/plantao-domingo", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const usuarioId = req.admin.id;
        const conteudo = normalizarConteudoPlantaoDomingo(req.body || {});
        const conteudoJson = JSON.stringify(conteudo);

        await garantirPlantaoDomingoTabela();

        await db.query(`
            INSERT INTO plantao_domingo_config (empresa_id, conteudo_json, atualizado_por)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                conteudo_json = VALUES(conteudo_json),
                atualizado_por = VALUES(atualizado_por),
                atualizado_em = CURRENT_TIMESTAMP
        `, [empresaId, conteudoJson, usuarioId]);

        const plantao = await buscarConteudoPlantaoDomingo(empresaId);

        res.json({
            success: true,
            ...plantao.conteudo,
            atualizado_em: plantao.atualizado_em,
            atualizado_por: usuarioId,
            atualizado_por_nome: req.admin.nome,
        });
    } catch (err) {
        console.error("Erro ao salvar plantão de domingo:", err);
        res.status(500).json({ error: "Erro ao salvar plantão de domingo" });
    }
});

// Mesma atualização global, mas só aceita pedidos feitos pelo próprio servidor (sem login): serve para o TI
// forçar o F5 das telas abertas depois de uma publicação. O endereço de origem de uma conexão TCP não se falsifica.
const enderecosDoServidor = () => new Set(Object.values(os.networkInterfaces()).flat().filter(Boolean).map((i) => i.address));
// Além do endereço, exige o segredo do header X-Local-Secret (env LOCAL_FORCE_REFRESH_SECRET). Sem o segredo
// configurado na env a rota fica desligada (503): qualquer processo da máquina podia chamá-la antes.
const segredoLocalConfere = (recebido) => {
    const esperado = String(process.env.LOCAL_FORCE_REFRESH_SECRET || "");
    if (esperado.length < 16) return null;
    const a = crypto.createHash("sha256").update(String(recebido || "")).digest();
    const b = crypto.createHash("sha256").update(esperado).digest();
    return crypto.timingSafeEqual(a, b);
};
route.post("/local/force-refresh-chat", async (req, res) => {
    const origem = String(req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
    if (!enderecosDoServidor().has(origem) || req.headers["x-forwarded-for"]) {
        return res.status(403).json({ error: "Comando disponível apenas no próprio servidor." });
    }
    const confere = segredoLocalConfere(req.headers["x-local-secret"]);
    if (confere === null) {
        return res.status(503).json({ error: "Comando desligado: defina LOCAL_FORCE_REFRESH_SECRET (mín. 16 caracteres) no servidor." });
    }
    if (!confere) {
        return res.status(403).json({ error: "Segredo inválido." });
    }
    const io = req.app.get("io");
    const payload = { reason: limitarTexto(req.body?.reason || "Atualizacao solicitada pelo servidor", 180), requested_by: "servidor", requested_at: new Date().toISOString() };
    io.emit("chat:force-refresh", payload);
    io.emit("system:force-refresh", payload);
    res.json({ success: true, sockets: io.engine?.clientsCount || 0, ...payload });
});

route.post("/admin/force-refresh-chat", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const io = req.app.get("io");
        const payload = {
            reason: limitarTexto(req.body?.reason || "Atualizacao solicitada pelo administrador", 180),
            requested_by: req.admin.nome,
            requested_at: new Date().toISOString(),
        };

        io.emit("chat:force-refresh", payload);
        io.emit("system:force-refresh", payload);

        res.json({
            success: true,
            sockets: io.engine?.clientsCount || 0,
            ...payload,
        });
    } catch (err) {
        console.error("Erro ao forçar atualização do chat:", err);
        res.status(500).json({ error: "Erro ao forçar atualização do chat" });
    }
});

route.post("/feedbacks", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;
        const usuarioId = req.user.id;
        const nome = limitarTexto(req.body.nome, 160);
        const tipo = limitarTexto(req.body.tipo, 20);
        const setor = limitarTexto(req.body.setor, 120) || null;
        const prioridade = limitarTexto(req.body.prioridade || "media", 20);
        const pagina = limitarTexto(req.body.pagina, 255) || null;
        const descricao = normalizarTextoLongo(req.body.descricao, 3000);

        if (!nome) {
            return res.status(400).json({ error: "Nome é obrigatório." });
        }

        if (!FEEDBACK_TIPOS.includes(tipo)) {
            return res.status(400).json({ error: "Tipo inválido." });
        }

        if (!FEEDBACK_PRIORIDADES.includes(prioridade)) {
            return res.status(400).json({ error: "Prioridade inválida." });
        }

        if (!descricao) {
            return res.status(400).json({ error: "Descrição é obrigatória." });
        }

        await garantirFeedbacksTabela();

        const [result] = await db.query(`
            INSERT INTO feedbacks (
                empresa_id,
                usuario_id,
                nome,
                tipo,
                setor,
                prioridade,
                pagina,
                descricao,
                resposta,
                status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 'aberto')
        `, [empresaId, usuarioId, nome, tipo, setor, prioridade, pagina, descricao]);

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.id = ? AND f.empresa_id = ?
            LIMIT 1
        `, [result.insertId, empresaId]);

        res.status(201).json(rows[0]);
    } catch (err) {
        console.error("Erro ao criar feedback:", err);
        res.status(500).json({ error: "Erro ao enviar feedback." });
    }
});

route.get("/feedbacks", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;

        await garantirFeedbacksTabela();

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.empresa_id = ?
            ORDER BY f.created_at DESC, f.id DESC
            LIMIT 300
        `, [empresaId]);

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar feedbacks:", err);
        res.status(500).json({ error: "Erro ao listar feedbacks." });
    }
});

route.get("/feedbacks/resolvidos", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;

        await garantirFeedbacksTabela();

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.empresa_id = ?
              AND f.status = 'resolvido'
              AND NULLIF(TRIM(COALESCE(f.resposta, '')), '') IS NOT NULL
            ORDER BY COALESCE(f.resolvido_em, f.updated_at) DESC, f.created_at DESC, f.id DESC
            LIMIT 100
        `, [empresaId]);

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar feedbacks resolvidos:", err);
        res.status(500).json({ error: "Erro ao listar feedbacks resolvidos." });
    }
});

route.post("/boas-praticas-duvidas/perguntas", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;
        const usuarioId = req.user.id;
        const nome = limitarTexto(req.body.nome || req.user.nome, 160);
        const setor = limitarTexto(req.body.setor, 120) || null;
        const descricao = normalizarTextoLongo(req.body.descricao, 3000);

        if (!nome) {
            return res.status(400).json({ error: "Nome é obrigatório." });
        }

        if (!descricao) {
            return res.status(400).json({ error: "Pergunta é obrigatória." });
        }

        await garantirFeedbacksTabela();

        const [result] = await db.query(`
            INSERT INTO feedbacks (
                empresa_id,
                usuario_id,
                nome,
                tipo,
                setor,
                prioridade,
                pagina,
                descricao,
                resposta,
                status
            )
            VALUES (?, ?, ?, 'pergunta', ?, 'media', ?, ?, NULL, 'aberto')
        `, [empresaId, usuarioId, nome, setor, BOAS_PRATICAS_DUVIDAS_PAGINA, descricao]);

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.id = ? AND f.empresa_id = ?
            LIMIT 1
        `, [result.insertId, empresaId]);

        res.status(201).json(rows[0]);
    } catch (err) {
        console.error("Erro ao criar pergunta de boas práticas:", err);
        res.status(500).json({ error: "Erro ao enviar pergunta." });
    }
});

route.get("/boas-praticas-duvidas/perguntas/respondidas", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;

        await garantirFeedbacksTabela();

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.empresa_id = ?
              AND f.tipo = 'pergunta'
              AND f.pagina = ?
              AND f.status = 'resolvido'
              AND NULLIF(TRIM(COALESCE(f.resposta, '')), '') IS NOT NULL
            ORDER BY COALESCE(f.resolvido_em, f.updated_at) DESC, f.created_at DESC, f.id DESC
            LIMIT 120
        `, [empresaId, BOAS_PRATICAS_DUVIDAS_PAGINA]);

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar perguntas respondidas:", err);
        res.status(500).json({ error: "Erro ao listar perguntas respondidas." });
    }
});

route.get("/admin/boas-praticas-duvidas/perguntas", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;

        await garantirFeedbacksTabela();

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.empresa_id = ?
              AND f.tipo = 'pergunta'
              AND f.pagina = ?
            ORDER BY FIELD(f.status, 'aberto', 'em_analise', 'resolvido', 'ignorado'), f.created_at DESC, f.id DESC
            LIMIT 300
        `, [empresaId, BOAS_PRATICAS_DUVIDAS_PAGINA]);

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar perguntas administrativas:", err);
        res.status(500).json({ error: "Erro ao listar perguntas administrativas." });
    }
});

route.patch("/admin/boas-praticas-duvidas/perguntas/:id/resposta", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const feedbackId = Number(req.params.id);
        const resposta = normalizarTextoLongo(req.body.resposta, 3000);

        if (!Number.isInteger(feedbackId)) {
            return res.status(400).json({ error: "Pergunta inválida." });
        }

        if (!resposta) {
            return res.status(400).json({ error: "Escreva uma resposta antes de publicar." });
        }

        await garantirFeedbacksTabela();

        const [feedbackRows] = await db.query(`
            SELECT id
            FROM feedbacks
            WHERE id = ?
              AND empresa_id = ?
              AND tipo = 'pergunta'
              AND pagina = ?
            LIMIT 1
        `, [feedbackId, empresaId, BOAS_PRATICAS_DUVIDAS_PAGINA]);

        if (!feedbackRows[0]) {
            return res.status(404).json({ error: "Pergunta não encontrada." });
        }

        await db.query(`
            UPDATE feedbacks
            SET
                resposta = ?,
                status = 'resolvido',
                resolvido_por = ?,
                resolvido_em = COALESCE(resolvido_em, NOW()),
                updated_at = NOW()
            WHERE id = ? AND empresa_id = ?
        `, [resposta, req.admin.id, feedbackId, empresaId]);

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.id = ? AND f.empresa_id = ?
            LIMIT 1
        `, [feedbackId, empresaId]);

        res.json(rows[0]);
    } catch (err) {
        console.error("Erro ao responder pergunta de boas práticas:", err);
        res.status(500).json({ error: "Erro ao responder pergunta." });
    }
});

route.get("/changelog", authMiddleware, async (req, res) => {
    try {
        const empresaId = req.user.empresa_id;

        await garantirChangelogTabela();

        const [rows] = await db.query(`
            SELECT
                c.id,
                c.categoria,
                c.titulo,
                c.versao,
                DATE_FORMAT(c.data_publicacao, '%Y-%m-%d') AS data,
                c.texto,
                c.criado_por,
                u.nome AS criado_por_nome,
                c.criado_em,
                c.atualizado_em
            FROM changelog_entries c
            LEFT JOIN usuarios u ON c.criado_por = u.id
            WHERE c.empresa_id = ?
            ORDER BY c.data_publicacao DESC, c.criado_em DESC, c.id DESC
            LIMIT 200
        `, [empresaId]);

        res.json(rows);
    } catch (err) {
        console.error("Erro ao listar changelog:", err);
        res.status(500).json({ error: "Erro ao listar changelog." });
    }
});

route.post("/admin/changelog", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const adminSelecionadoId = Number(req.body.criado_por || req.admin.id);
        const categoria = limitarTexto(req.body.categoria || "atualizacao", 20);
        const titulo = limitarTexto(req.body.titulo, 180);
        const versao = limitarTexto(req.body.versao, 40);
        const dataPublicacao = normalizarDataPublicacao(req.body.data);
        const texto = normalizarTextoLongo(req.body.texto, 5000);

        if (!CHANGELOG_CATEGORIAS.includes(categoria)) {
            return res.status(400).json({ error: "Categoria inválida." });
        }

        if (!titulo) {
            return res.status(400).json({ error: "Título é obrigatório." });
        }

        if (!versao) {
            return res.status(400).json({ error: "Versão é obrigatória." });
        }

        if (!dataPublicacao) {
            return res.status(400).json({ error: "Data inválida." });
        }

        if (!texto) {
            return res.status(400).json({ error: "Texto é obrigatório." });
        }

        if (!Number.isInteger(adminSelecionadoId)) {
            return res.status(400).json({ error: "Admin responsável inválido." });
        }

        await garantirChangelogTabela();

        const [adminRows] = await db.query(`
            SELECT id, nome
            FROM usuarios
            WHERE id = ?
              AND empresa_id = ?
              AND perfil = 'admin'
              AND deletado_em IS NULL
            LIMIT 1
        `, [adminSelecionadoId, empresaId]);

        const adminSelecionado = adminRows[0];

        if (!adminSelecionado) {
            return res.status(400).json({ error: "Admin responsável não encontrado." });
        }

        const [result] = await db.query(`
            INSERT INTO changelog_entries (
                empresa_id,
                categoria,
                titulo,
                versao,
                data_publicacao,
                texto,
                criado_por
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [empresaId, categoria, titulo, versao, dataPublicacao, texto, adminSelecionado.id]);

        const [rows] = await db.query(`
            SELECT
                c.id,
                c.categoria,
                c.titulo,
                c.versao,
                DATE_FORMAT(c.data_publicacao, '%Y-%m-%d') AS data,
                c.texto,
                c.criado_por,
                u.nome AS criado_por_nome,
                c.criado_em,
                c.atualizado_em
            FROM changelog_entries c
            LEFT JOIN usuarios u ON c.criado_por = u.id
            WHERE c.id = ? AND c.empresa_id = ?
            LIMIT 1
        `, [result.insertId, empresaId]);

        res.status(201).json(rows[0]);
    } catch (err) {
        console.error("Erro ao criar changelog:", err);
        res.status(500).json({ error: "Erro ao criar changelog." });
    }
});

route.patch("/feedbacks/:id/status", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const feedbackId = Number(req.params.id);
        const status = limitarTexto(req.body.status, 30);
        const resolvidoPorRecebido = req.body.resolvido_por ?? req.body.resolvedById ?? req.body.resolved_by;

        if (!Number.isInteger(feedbackId)) {
            return res.status(400).json({ error: "Feedback inválido." });
        }

        if (!FEEDBACK_STATUS.includes(status)) {
            return res.status(400).json({ error: "Status inválido." });
        }

        await garantirFeedbacksTabela();

        const [feedbackRows] = await db.query(`
            SELECT id, tipo, pagina, resposta, resolvido_por
            FROM feedbacks
            WHERE id = ? AND empresa_id = ?
            LIMIT 1
        `, [feedbackId, empresaId]);

        const feedbackAtual = feedbackRows[0];

        if (!feedbackAtual) {
            return res.status(404).json({ error: "Feedback não encontrado." });
        }

        let resolvidoPor = null;

        if (status === "resolvido") {
            resolvidoPor = Number(
                resolvidoPorRecebido
                || feedbackAtual.resolvido_por
                || req.admin.id
            );

            if (!Number.isInteger(resolvidoPor)) {
                return res.status(400).json({ error: "Responsável pela resolução inválido." });
            }

            const [responsavelRows] = await db.query(`
                SELECT id
                FROM usuarios
                WHERE id = ?
                  AND empresa_id = ?
                  AND perfil = 'admin'
                  AND deletado_em IS NULL
                LIMIT 1
            `, [resolvidoPor, empresaId]);

            if (!responsavelRows[0]) {
                return res.status(400).json({ error: "Responsável pela resolução precisa ser um administrador." });
            }
        }

        const respostaFoiInformada = Object.prototype.hasOwnProperty.call(req.body || {}, "resposta");
        const resposta = respostaFoiInformada
            ? normalizarTextoLongo(req.body.resposta, 3000)
            : normalizarTextoLongo(feedbackAtual.resposta, 3000);

        if (status === "resolvido" && ehPerguntaBoasPraticas(feedbackAtual) && !resposta) {
            return res.status(400).json({ error: "Escreva uma resposta antes de publicar a dúvida." });
        }

        const [result] = await db.query(`
            UPDATE feedbacks
            SET
                status = ?,
                resposta = ?,
                resolvido_por = ?,
                resolvido_em = CASE
                    WHEN ? = 'resolvido' THEN COALESCE(resolvido_em, NOW())
                    ELSE NULL
                END,
                updated_at = NOW()
            WHERE id = ? AND empresa_id = ?
        `, [status, resposta || null, resolvidoPor, status, feedbackId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Feedback não encontrado." });
        }

        const [rows] = await db.query(`
            SELECT
                f.id,
                f.nome,
                f.tipo,
                f.setor,
                f.prioridade,
                f.pagina,
                f.descricao,
                f.resposta,
                f.status,
                f.resolvido_por,
                ru.nome AS resolvido_por_nome,
                f.resolvido_em,
                f.created_at,
                f.updated_at
            FROM feedbacks f
            LEFT JOIN usuarios ru ON ru.id = f.resolvido_por
            WHERE f.id = ? AND f.empresa_id = ?
            LIMIT 1
        `, [feedbackId, empresaId]);

        res.json(rows[0]);
    } catch (err) {
        console.error("Erro ao atualizar status do feedback:", err);
        res.status(500).json({ error: "Erro ao atualizar status." });
    }
});

route.delete("/feedbacks/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const feedbackId = Number(req.params.id);

        if (!Number.isInteger(feedbackId)) {
            return res.status(400).json({ error: "Feedback inválido." });
        }

        await garantirFeedbacksTabela();

        const [result] = await db.query(`
            DELETE FROM feedbacks
            WHERE id = ? AND empresa_id = ?
        `, [feedbackId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Feedback não encontrado." });
        }

        res.json({ success: true, id: feedbackId });
    } catch (err) {
        console.error("Erro ao excluir feedback:", err);
        res.status(500).json({ error: "Erro ao excluir feedback." });
    }
});

route.get("/admin/aviso-geral", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const aviso = await buscarAvisoGeralAdmin(req.admin.empresa_id);
        res.json(aviso);
    } catch (err) {
        console.error("Erro ao buscar aviso geral administrativo:", err);
        res.status(500).json({ error: "Erro ao buscar aviso geral." });
    }
});

route.put("/admin/aviso-geral", authMiddleware, requireAdmin, uploadAvisoGeralImagemMiddleware, async (req, res) => {
    let uploadImagemPublicada = false;

    try {
        const empresaId = req.admin.empresa_id;
        const userId = req.admin.id;
        const titulo = limitarTexto(req.body.titulo, 180);
        const mensagem = normalizarTextoLongo(req.body.mensagem, 3000);
        const ativo = normalizarBooleanoAvisoInterno(req.body.ativo, false);
        const secoes = parseJsonAvisoInterno(req.body.sections ?? req.body.secoes, {});
        const prioridade = normalizarPrioridadeAvisoInterno(req.body.priority || req.body.prioridade);
        const tipo = limitarTexto(req.body.type || req.body.tipo || "Comunicado", 80);
        const categoria = limitarTexto(req.body.category || req.body.categoria || "Sistema", 80);
        const summary = limitarTexto(req.body.summary ?? req.body.resumo ?? mensagem, 320);
        const resumeText = normalizarTextoLongo(
            req.body.resume_text ?? req.body.resume ?? secoes.resume ?? "",
            1200
        );
        const changesJson = JSON.stringify(normalizarAlteracoesAvisoInterno(
            req.body.changes || req.body.alteracoes || secoes.changes
        ));
        const importantInfoJson = JSON.stringify(normalizarInformacoesAvisoInterno(
            req.body.important_info || req.body.importantInfo || req.body.informacoes_importantes || secoes.importantInfo
        ));
        const actionRequired = normalizarAcaoAvisoInterno(
            req.body.action_required || req.body.actionRequired || req.body.acao_necessaria || secoes.actionRequired
        );
        const actionRequiredJson = actionRequired ? JSON.stringify(actionRequired) : null;
        const detailUrl = limitarTexto(req.body.detail_url || req.body.detailUrl || "", 500);
        const detailButtonText = limitarTexto(req.body.detail_button_text || req.body.detailButtonText || "Ver detalhes", 80);
        const showNewBadge = normalizarBooleanoAvisoInterno(req.body.show_new_badge ?? req.body.showNewBadge, true);
        const requireConfirmation = prioridade === "critica"
            ? true
            : normalizarBooleanoAvisoInterno(req.body.require_confirmation ?? req.body.requireConfirmation, true);
        const allowCloseDefault = requireConfirmation ? false : true;
        const allowClose = prioridade !== "critica" && normalizarBooleanoAvisoInterno(req.body.allow_close ?? req.body.allowClose, allowCloseDefault);
        const allowSnooze = prioridade !== "critica" && normalizarBooleanoAvisoInterno(req.body.allow_snooze ?? req.body.allowSnooze, true);
        const startsAt = normalizarDataHoraAvisoInterno(req.body.starts_at || req.body.startsAt);
        const endsAt = normalizarDataHoraAvisoInterno(req.body.ends_at || req.body.endsAt);
        const removerImagem = normalizarBooleanoAvisoInterno(req.body.remove_image ?? req.body.remover_imagem, false);

        if (!titulo) {
            removerUploadTemporarioAvisoGeral(req);
            return res.status(400).json({ error: "Informe um título para o aviso." });
        }

        if (!mensagem) {
            removerUploadTemporarioAvisoGeral(req);
            return res.status(400).json({ error: "Informe a mensagem do aviso." });
        }

        await garantirAvisoGeralTabela();

        const avisoAtual = await buscarAvisoGeralAdmin(empresaId);
        const imagemAnteriorUrl = avisoAtual?.image_url || "";
        let imageUrl = imagemAnteriorUrl || null;
        let imagemParaRemoverUrl = "";

        if (req.file) {
            const empresaDiretorio = normalizarSegmentoUpload(empresaId);
            imageUrl = `/uploads/avisos/${empresaDiretorio}/${req.file.filename}`;
            imagemParaRemoverUrl = imagemAnteriorUrl && imagemAnteriorUrl !== imageUrl ? imagemAnteriorUrl : "";
        } else if (removerImagem) {
            imageUrl = null;
            imagemParaRemoverUrl = imagemAnteriorUrl;
        }

        await db.query(`
            UPDATE avisos_gerais
            SET ativo = 0
            WHERE empresa_id = ?
        `, [empresaId]);

        await db.query(`
            INSERT INTO avisos_gerais (
                empresa_id,
                titulo,
                mensagem,
                image_url,
                summary,
                tipo,
                categoria,
                prioridade,
                resume_text,
                changes_json,
                important_info_json,
                action_required_json,
                detail_url,
                detail_button_text,
                show_new_badge,
                require_confirmation,
                allow_close,
                allow_snooze,
                starts_at,
                ends_at,
                ativo,
                criado_por
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
            empresaId,
            titulo,
            mensagem,
            imageUrl,
            summary,
            tipo,
            categoria,
            prioridade,
            resumeText,
            changesJson,
            importantInfoJson,
            actionRequiredJson,
            detailUrl,
            detailButtonText,
            showNewBadge ? 1 : 0,
            requireConfirmation ? 1 : 0,
            allowClose ? 1 : 0,
            allowSnooze ? 1 : 0,
            startsAt,
            endsAt,
            ativo ? 1 : 0,
            userId,
        ]);
        uploadImagemPublicada = true;

        if (imagemParaRemoverUrl) {
            await db.query(`
                UPDATE avisos_gerais
                SET image_url = NULL
                WHERE empresa_id = ?
                  AND image_url = ?
            `, [empresaId, imagemParaRemoverUrl]);
            removerArquivoAvisoGeralPorUrl(imagemParaRemoverUrl);
        }

        const aviso = await buscarAvisoGeralAdmin(empresaId);
        res.json(aviso);
    } catch (err) {
        console.error("Erro ao salvar aviso geral administrativo:", err);
        if (req.file?.path && !uploadImagemPublicada) {
            removerUploadTemporarioAvisoGeral(req);
        }
        res.status(500).json({ error: "Erro ao salvar aviso geral." });
    }
});

const listarEfeitosSonorosHandler = async (req, res) => {
    try {
        const usuario = req.soundEffectUser || req.user;
        const permission = await obterPermissaoEfeitosSonoros(usuario);

        res.json({
            sounds: listAllowedSoundEffects(),
            permission,
            target_group: obterNomeGrupoAlvoEfeitosSonoros(),
            users: await listarUsuariosAlvoEfeitosSonoros(usuario),
        });
    } catch (err) {
        console.error("Erro ao listar efeitos sonoros:", err);
        res.status(500).json({ error: "Erro ao listar efeitos sonoros." });
    }
};

const uploadEfeitoSonoroHandler = async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: "Envie um arquivo de áudio." });
        }

        const extensao = normalizeSoundUploadExtension(req.file.originalname || req.file.filename);

        if (!validateUploadedAudioFile(req.file.path, extensao)) {
            removeUploadedSoundFile(req.file.filename);
            return res.status(400).json({ error: "O arquivo enviado não parece ser um áudio válido ou compatível com o navegador." });
        }

        const sound = registerUploadedSoundEffect({
            file: req.file,
            label: req.body?.label,
            admin: req.soundEffectUser || req.user,
        });

        const usuarioSom = req.soundEffectUser || req.user;
        console.log(`[SOUND_EFFECTS] ${usuarioSom.nome} enviou o áudio "${sound.label}" para efeitos sonoros.`);

        try {
            await registrarAuditoria({
                usuario: usuarioSom,
                acao: "UPLOAD_EFEITO_SONORO",
                entidade: "efeito_sonoro_remoto",
                entidadeId: sound.key,
                tipo: AUDIT_TYPES.CHAT,
                nivel: AUDIT_LEVELS.IMPORTANT,
                origem: "CHAT_INTERNO_EFEITOS_SONOROS",
                metadata: {
                    som: sound,
                    original_name: req.file.originalname,
                    size: req.file.size,
                    mime: req.file.mimetype,
                },
                req,
            });
        } catch (auditErr) {
            console.error("Erro ao registrar auditoria de upload de efeito sonoro:", auditErr);
        }

        res.status(201).json({
            sound,
            sounds: listAllowedSoundEffects(),
        });
    } catch (err) {
        if (req.file?.filename) {
            removeUploadedSoundFile(req.file.filename);
        }

        console.error("Erro ao enviar efeito sonoro:", err);
        res.status(500).json({ error: "Erro ao enviar efeito sonoro." });
    }
};

route.get("/sound-effects", authMiddleware, requireSoundEffectAccess, listarEfeitosSonorosHandler);
route.get("/admin/sound-effects", authMiddleware, requireSoundEffectAccess, listarEfeitosSonorosHandler);

route.post("/sound-effects/upload", authMiddleware, requireSoundEffectAccess, uploadSoundEffectMiddleware, uploadEfeitoSonoroHandler);
route.post("/admin/sound-effects/upload", authMiddleware, requireSoundEffectAccess, uploadSoundEffectMiddleware, uploadEfeitoSonoroHandler);

route.get("/sound-effects/permissions", authMiddleware, requireSoundEffectManager, async (req, res) => {
    try {
        res.json({
            users: await listarPermissoesEfeitosSonoros(req.soundEffectUser || req.user),
        });
    } catch (err) {
        console.error("Erro ao listar permissões de efeitos sonoros:", err);
        res.status(500).json({ error: "Erro ao listar permissões de efeitos sonoros." });
    }
});

route.put("/sound-effects/permissions/:userId", authMiddleware, requireSoundEffectManager, async (req, res) => {
    try {
        await definirPermissaoUsoEfeitosSonoros({
            usuario: req.soundEffectUser || req.user,
            targetUserId: req.params.userId,
            enabled: Boolean(req.body?.enabled),
        });

        res.json({
            users: await listarPermissoesEfeitosSonoros(req.soundEffectUser || req.user),
        });
    } catch (err) {
        console.error("Erro ao salvar permissão de efeitos sonoros:", err);
        res.status(err.status || 500).json({ error: err.message || "Erro ao salvar permissão de efeitos sonoros." });
    }
});

route.put("/sound-effects/permissions/:userId/max-volume", authMiddleware, requireSoundEffectManager, async (req, res) => {
    try {
        await definirVolumeMaximoEfeitosSonoros({
            usuario: req.soundEffectUser || req.user,
            targetUserId: req.params.userId,
            percent: req.body?.percent,
        });

        res.json({
            users: await listarPermissoesEfeitosSonoros(req.soundEffectUser || req.user),
        });
    } catch (err) {
        console.error("Erro ao salvar volume máximo de efeitos sonoros:", err);
        res.status(err.status || 500).json({ error: err.message || "Erro ao salvar o volume máximo." });
    }
});

route.put("/sound-effects/permissions/:userId/no-time-limit", authMiddleware, requireSoundEffectManager, async (req, res) => {
    try {
        await definirSemLimiteDeTempoEfeitosSonoros({
            usuario: req.soundEffectUser || req.user,
            targetUserId: req.params.userId,
            enabled: Boolean(req.body?.enabled),
        });

        res.json({
            users: await listarPermissoesEfeitosSonoros(req.soundEffectUser || req.user),
        });
    } catch (err) {
        console.error("Erro ao salvar o limite de tempo dos efeitos sonoros:", err);
        res.status(err.status || 500).json({ error: err.message || "Erro ao salvar o limite de tempo." });
    }
});

// ========================================
// ADMIN - ENDPOINTS
// ========================================

route.post("/admin/teste-venda", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const io = req.app.get("io");

        io?.to(`empresa_${req.admin.empresa_id}`).emit("sales_celebration_test", {
            teste: true,
            incremento: 1,
            criado_por: req.admin.nome,
            criado_em: new Date().toISOString(),
        });

        res.json({ ok: true });
    } catch (err) {
        console.error("Erro ao disparar teste de venda:", err);
        res.status(500).json({ error: "Erro ao disparar teste de venda" });
    }
});

route.get("/admin/resumo", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;

        await garantirGruposFixos(empresaId, req.admin.id);

        const [
            [usuariosResumo],
            [statusResumo],
            [gruposResumo],
            [diretasResumo],
            [gruposMensagensResumo],
        ] = await Promise.all([
            db.query(`
                SELECT COUNT(*) AS total_usuarios
                FROM usuarios
                WHERE empresa_id = ? AND deletado_em IS NULL
            `, [empresaId]),
            db.query(`
                SELECT status, COUNT(*) AS total
                FROM usuarios
                WHERE empresa_id = ? AND deletado_em IS NULL
                GROUP BY status
            `, [empresaId]),
            db.query(`
                SELECT COUNT(*) AS total_grupos
                FROM grupos
                WHERE empresa_id = ? AND deletado_em IS NULL
            `, [empresaId]),
            db.query(`
                SELECT COUNT(*) AS total_mensagens_diretas
                FROM mensagens m
                JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
                JOIN usuarios u1 ON cd.usuario1_id = u1.id
                JOIN usuarios u2 ON cd.usuario2_id = u2.id
                WHERE u1.empresa_id = ? AND u2.empresa_id = ?
            `, [empresaId, empresaId]),
            db.query(`
                SELECT COUNT(*) AS total_mensagens_grupos
                FROM mensagens m
                JOIN grupos g ON m.grupo_id = g.id
                WHERE g.empresa_id = ?
            `, [empresaId]),
        ]);

        const status = statusResumo.reduce((acc, item) => {
            acc[item.status || "offline"] = item.total;
            return acc;
        }, { online: 0, away: 0, offline: 0 });

        const totalMensagensDiretas = diretasResumo[0]?.total_mensagens_diretas || 0;
        const totalMensagensGrupos = gruposMensagensResumo[0]?.total_mensagens_grupos || 0;

        res.json({
            total_usuarios: usuariosResumo[0]?.total_usuarios || 0,
            total_grupos: gruposResumo[0]?.total_grupos || 0,
            total_mensagens: totalMensagensDiretas + totalMensagensGrupos,
            total_mensagens_diretas: totalMensagensDiretas,
            total_mensagens_grupos: totalMensagensGrupos,
            status,
        });
    } catch (err) {
        console.error("Erro ao buscar resumo administrativo:", err);
        res.status(500).json({ error: "Erro ao buscar resumo administrativo" });
    }
});

route.get("/admin/avisos-internos", authMiddleware, requireEditorAvisosInternos, async (req, res) => {
    try {
        const {
            conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        } = await buscarConteudoAvisosInternos(req.editorAvisosInternos.empresa_id);

        res.json({
            ...conteudo,
            atualizado_em,
            atualizado_por,
            atualizado_por_nome,
        });
    } catch (err) {
        console.error("Erro ao buscar avisos internos administrativos:", err);
        res.status(500).json({ error: "Erro ao buscar avisos internos" });
    }
});

route.put("/admin/avisos-internos", authMiddleware, requireEditorAvisosInternos, async (req, res) => {
    try {
        const empresaId = req.editorAvisosInternos.empresa_id;
        const conteudo = normalizarConteudoAvisosInternos(req.body || {});
        const conteudoJson = JSON.stringify(conteudo);

        await garantirAvisosInternosTabela();

        await db.query(`
            INSERT INTO avisos_internos_config (empresa_id, conteudo_json, atualizado_por)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                conteudo_json = VALUES(conteudo_json),
                atualizado_por = VALUES(atualizado_por),
                atualizado_em = CURRENT_TIMESTAMP
        `, [empresaId, conteudoJson, req.editorAvisosInternos.id]);

        const { atualizado_em } = await buscarConteudoAvisosInternos(empresaId);

        res.json({
            success: true,
            ...conteudo,
            atualizado_em,
            atualizado_por: req.editorAvisosInternos.id,
            atualizado_por_nome: req.editorAvisosInternos.nome,
        });
    } catch (err) {
        console.error("Erro ao salvar avisos internos administrativos:", err);
        res.status(500).json({ error: "Erro ao salvar avisos internos" });
    }
});

const montarHistoricoMensagensAdmin = (incluirConteudoCompleto = false) => {
    const mensagemSelect = incluirConteudoCompleto
        ? "m.mensagem"
        : "CASE WHEN m.tipo_mensagem IN ('imagem', 'audio', 'arquivo') THEN NULL ELSE m.mensagem END";

    return `
    SELECT
        m.id,
        'direta' AS tipo_conversa,
        ${mensagemSelect} AS mensagem,
        CASE
            WHEN m.tipo_mensagem = 'imagem' THEN '[Imagem]'
            WHEN m.tipo_mensagem = 'audio' THEN '[Áudio]'
            WHEN m.tipo_mensagem = 'arquivo' THEN '[Arquivo]'
            WHEN m.tipo_mensagem = 'sticker' THEN 'Figurinha'
            ELSE LEFT(m.mensagem, 180)
        END AS previa,
        m.tipo_mensagem,
        m.anexo_nome,
        m.anexo_mime,
        m.lida,
        m.criada_em,
        m.editada_em,
        m.deletada_em,
        m.deletada_por,
        CASE
            WHEN m.deletada_em IS NOT NULL THEN 'apagada'
            WHEN m.editada_em IS NOT NULL THEN 'editada'
            ELSE 'enviada'
        END AS status,
        m.remetente_id,
        ur.nome AS remetente_nome,
        ur.email AS remetente_email,
        cd.id AS conversa_id,
        ud.id AS destinatario_id,
        ud.nome AS destinatario_nome,
        ud.email AS destinatario_email,
        NULL AS grupo_id,
        NULL AS grupo_nome,
        up.nome AS apagada_por_nome
    FROM mensagens m
    JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
    JOIN usuarios ur ON m.remetente_id = ur.id
    JOIN usuarios ud ON ud.id = CASE
        WHEN cd.usuario1_id = m.remetente_id THEN cd.usuario2_id
        ELSE cd.usuario1_id
    END
    JOIN usuarios u1 ON cd.usuario1_id = u1.id
    JOIN usuarios u2 ON cd.usuario2_id = u2.id
    LEFT JOIN usuarios up ON m.deletada_por = up.id
    WHERE u1.empresa_id = ? AND u2.empresa_id = ?
    UNION ALL
    SELECT
        m.id,
        'grupo' AS tipo_conversa,
        ${mensagemSelect} AS mensagem,
        CASE
            WHEN m.tipo_mensagem = 'imagem' THEN '[Imagem]'
            WHEN m.tipo_mensagem = 'audio' THEN '[Áudio]'
            WHEN m.tipo_mensagem = 'arquivo' THEN '[Arquivo]'
            WHEN m.tipo_mensagem = 'sticker' THEN 'Figurinha'
            ELSE LEFT(m.mensagem, 180)
        END AS previa,
        m.tipo_mensagem,
        m.anexo_nome,
        m.anexo_mime,
        m.lida,
        m.criada_em,
        m.editada_em,
        m.deletada_em,
        m.deletada_por,
        CASE
            WHEN m.deletada_em IS NOT NULL THEN 'apagada'
            WHEN m.editada_em IS NOT NULL THEN 'editada'
            ELSE 'enviada'
        END AS status,
        m.remetente_id,
        ur.nome AS remetente_nome,
        ur.email AS remetente_email,
        NULL AS conversa_id,
        NULL AS destinatario_id,
        NULL AS destinatario_nome,
        NULL AS destinatario_email,
        g.id AS grupo_id,
        g.nome AS grupo_nome,
        up.nome AS apagada_por_nome
    FROM mensagens m
    JOIN grupos g ON m.grupo_id = g.id
    JOIN usuarios ur ON m.remetente_id = ur.id
    LEFT JOIN usuarios up ON m.deletada_por = up.id
    WHERE g.empresa_id = ?
`;
};

const montarFiltrosHistoricoMensagens = (query) => {
    const where = ["1 = 1"];
    const params = [];
    const search = (query.search || "").trim();

    if (search) {
        const termo = `%${search}%`;
        where.push(`(
            mensagem LIKE ?
            OR remetente_nome LIKE ?
            OR remetente_email LIKE ?
            OR COALESCE(destinatario_nome, '') LIKE ?
            OR COALESCE(destinatario_email, '') LIKE ?
            OR COALESCE(grupo_nome, '') LIKE ?
        )`);
        params.push(termo, termo, termo, termo, termo, termo);
    }

    if (query.remetente_id) {
        where.push("remetente_id = ?");
        params.push(Number(query.remetente_id));
    }

    if (query.destinatario_id) {
        where.push("destinatario_id = ?");
        params.push(Number(query.destinatario_id));
    }

    if (query.grupo_id) {
        where.push("grupo_id = ?");
        params.push(Number(query.grupo_id));
    }

    if (["direta", "grupo"].includes(query.tipo_conversa)) {
        where.push("tipo_conversa = ?");
        params.push(query.tipo_conversa);
    }

    if (["enviada", "editada", "apagada", "fixada", "favoritada"].includes(query.status)) {
        where.push("status = ?");
        params.push(query.status);
    }

    if (query.data_inicio) {
        where.push("criada_em >= ?");
        params.push(query.data_inicio);
    }

    if (query.data_fim) {
        where.push("criada_em <= ?");
        params.push(query.data_fim);
    }

    return {
        whereSql: where.join(" AND "),
        params,
    };
};

route.get("/admin/chat/messages", authMiddleware, requireAdmin, async (req, res) => {
    try {
        await garantirAuditoriaMensagens();

        const empresaId = req.admin.empresa_id;
        const page = Math.max(Number(req.query.page) || 1, 1);
        const limit = Math.min(Math.max(Number(req.query.limit) || 25, 1), 100);
        const offset = (page - 1) * limit;
        const baseSql = montarHistoricoMensagensAdmin(false);
        const baseParams = [empresaId, empresaId, empresaId];
        const { whereSql, params: filtrosParams } = montarFiltrosHistoricoMensagens(req.query);

        const [totalRows] = await db.query(`
            SELECT COUNT(*) AS total
            FROM (${baseSql}) historico
            WHERE ${whereSql}
        `, [...baseParams, ...filtrosParams]);

        const total = totalRows[0]?.total || 0;

        const [mensagens] = await db.query(`
            SELECT *
            FROM (${baseSql}) historico
            WHERE ${whereSql}
            ORDER BY criada_em DESC, id DESC
            LIMIT ? OFFSET ?
        `, [...baseParams, ...filtrosParams, limit, offset]);

        res.json({
            data: mensagens,
            pagination: {
                page,
                limit,
                total,
                total_pages: Math.max(Math.ceil(total / limit), 1),
            },
        });
    } catch (err) {
        console.error("Erro ao buscar histórico administrativo de mensagens:", err);
        res.status(500).json({ error: "Erro ao buscar histórico de mensagens." });
    }
});

route.get("/admin/chat/messages/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        await garantirAuditoriaMensagens();

        const empresaId = req.admin.empresa_id;
        const mensagemId = Number(req.params.id);

        if (!Number.isInteger(mensagemId)) {
            return res.status(400).json({ error: "Mensagem inválida." });
        }

        const baseSql = montarHistoricoMensagensAdmin(true);

        const [mensagens] = await db.query(`
            SELECT *
            FROM (${baseSql}) historico
            WHERE id = ?
            LIMIT 1
        `, [empresaId, empresaId, empresaId, mensagemId]);

        if (!mensagens.length) {
            return res.status(404).json({ error: "Mensagem não encontrada." });
        }

        const [auditoria] = await db.query(`
            SELECT
                a.id,
                a.mensagem_id,
                a.usuario_id,
                u.nome AS usuario_nome,
                u.email AS usuario_email,
                a.acao,
                a.valor_antigo,
                a.valor_novo,
                a.criada_em,
                a.ip,
                a.user_agent
            FROM chat_message_audit a
            LEFT JOIN usuarios u ON a.usuario_id = u.id
            WHERE a.mensagem_id = ?
            ORDER BY a.criada_em DESC, a.id DESC
        `, [mensagemId]);

        res.json({
            mensagem: mensagens[0],
            auditoria,
        });
    } catch (err) {
        console.error("Erro ao buscar detalhe administrativo de mensagem:", err);
        res.status(500).json({ error: "Erro ao buscar detalhes da mensagem." });
    }
});

route.get("/admin/mensagens", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const tipo = req.query.tipo || "todas";
        const busca = (req.query.busca || "").trim();
        const limit = Math.min(Math.max(Number(req.query.limit) || 100, 1), 500);
        const includeDeleted = req.query.incluir_deletadas === "true";

        const queries = [];
        const params = [];

        if (tipo === "todas" || tipo === "diretas") {
            let directQuery = `
                SELECT
                    m.id,
                    'direta' AS tipo,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.lida,
                    m.criada_em,
                    m.editada_em,
                    m.deletada_em,
                    m.remetente_id,
                    ur.nome AS remetente_nome,
                    ur.email AS remetente_email,
                    NULL AS grupo_id,
                    NULL AS grupo_nome,
                    cd.id AS conversa_id,
                    ud.id AS destinatario_id,
                    ud.nome AS destinatario_nome,
                    CONCAT('Direta: ', ur.nome, ' -> ', ud.nome) AS contexto
                FROM mensagens m
                JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
                JOIN usuarios ur ON m.remetente_id = ur.id
                JOIN usuarios ud ON ud.id = CASE
                    WHEN cd.usuario1_id = m.remetente_id THEN cd.usuario2_id
                    ELSE cd.usuario1_id
                END
                JOIN usuarios u1 ON cd.usuario1_id = u1.id
                JOIN usuarios u2 ON cd.usuario2_id = u2.id
                WHERE u1.empresa_id = ? AND u2.empresa_id = ?
            `;
            params.push(empresaId, empresaId);

            if (!includeDeleted) {
                directQuery += " AND m.deletada_em IS NULL";
            }

            if (busca) {
                directQuery += `
                    AND (
                        m.mensagem LIKE ?
                        OR ur.nome LIKE ?
                        OR ur.email LIKE ?
                        OR ud.nome LIKE ?
                        OR ud.email LIKE ?
                    )
                `;
                const termo = `%${busca}%`;
                params.push(termo, termo, termo, termo, termo);
            }

            queries.push(directQuery);
        }

        if (tipo === "todas" || tipo === "grupos") {
            let groupQuery = `
                SELECT
                    m.id,
                    'grupo' AS tipo,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.lida,
                    m.criada_em,
                    m.editada_em,
                    m.deletada_em,
                    m.remetente_id,
                    ur.nome AS remetente_nome,
                    ur.email AS remetente_email,
                    g.id AS grupo_id,
                    g.nome AS grupo_nome,
                    NULL AS conversa_id,
                    NULL AS destinatario_id,
                    NULL AS destinatario_nome,
                    CONCAT('Grupo: ', g.nome) AS contexto
                FROM mensagens m
                JOIN grupos g ON m.grupo_id = g.id
                JOIN usuarios ur ON m.remetente_id = ur.id
                WHERE g.empresa_id = ?
            `;
            params.push(empresaId);

            if (!includeDeleted) {
                groupQuery += " AND m.deletada_em IS NULL";
            }

            if (busca) {
                groupQuery += `
                    AND (
                        m.mensagem LIKE ?
                        OR ur.nome LIKE ?
                        OR ur.email LIKE ?
                        OR g.nome LIKE ?
                    )
                `;
                const termo = `%${busca}%`;
                params.push(termo, termo, termo, termo);
            }

            queries.push(groupQuery);
        }

        if (!queries.length) {
            return res.status(400).json({ error: "Tipo inválido" });
        }

        const sql = `
            SELECT *
            FROM (${queries.join(" UNION ALL ")}) mensagens_admin
            ORDER BY criada_em DESC
            LIMIT ${limit}
        `;

        const [mensagens] = await db.query(sql, params);
        res.json(mensagens);
    } catch (err) {
        console.error("Erro ao buscar mensagens administrativas:", err);
        res.status(500).json({ error: "Erro ao buscar mensagens administrativas" });
    }
});

route.get("/admin/usuarios/:id/mensagens", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const usuarioId = Number(req.params.id);

        const [usuarioRows] = await db.query(`
            SELECT id, nome, email, setor_id, perfil, status
            FROM usuarios
            WHERE id = ? AND empresa_id = ?
        `, [usuarioId, empresaId]);

        if (!usuarioRows.length) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }

        const usuario = usuarioRows[0];

        const [mensagens] = await db.query(`
            SELECT *
            FROM (
                SELECT
                    m.id,
                    'direta' AS tipo,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.lida,
                    m.criada_em,
                    m.editada_em,
                    m.deletada_em,
                    m.remetente_id,
                    ur.nome AS remetente_nome,
                    ur.email AS remetente_email,
                    NULL AS grupo_id,
                    NULL AS grupo_nome,
                    cd.id AS conversa_id,
                    ud.id AS destinatario_id,
                    ud.nome AS destinatario_nome,
                    CONCAT('Direta: ', ur.nome, ' -> ', ud.nome) AS contexto
                FROM mensagens m
                JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
                JOIN usuarios ur ON m.remetente_id = ur.id
                JOIN usuarios ud ON ud.id = CASE
                    WHEN cd.usuario1_id = m.remetente_id THEN cd.usuario2_id
                    ELSE cd.usuario1_id
                END
                JOIN usuarios u1 ON cd.usuario1_id = u1.id
                JOIN usuarios u2 ON cd.usuario2_id = u2.id
                WHERE m.remetente_id = ? AND u1.empresa_id = ? AND u2.empresa_id = ?
                UNION ALL
                SELECT
                    m.id,
                    'grupo' AS tipo,
                    m.mensagem,
                    m.tipo_mensagem,
                    m.anexo_nome,
                    m.anexo_mime,
                    m.lida,
                    m.criada_em,
                    m.editada_em,
                    m.deletada_em,
                    m.remetente_id,
                    ur.nome AS remetente_nome,
                    ur.email AS remetente_email,
                    g.id AS grupo_id,
                    g.nome AS grupo_nome,
                    NULL AS conversa_id,
                    NULL AS destinatario_id,
                    NULL AS destinatario_nome,
                    CONCAT('Grupo: ', g.nome) AS contexto
                FROM mensagens m
                JOIN grupos g ON m.grupo_id = g.id
                JOIN usuarios ur ON m.remetente_id = ur.id
                WHERE m.remetente_id = ? AND g.empresa_id = ?
            ) historico
            ORDER BY criada_em DESC
            LIMIT 500
        `, [usuarioId, empresaId, empresaId, usuarioId, empresaId]);

        res.json({ usuario, mensagens });
    } catch (err) {
        console.error("Erro ao buscar histórico de usuário:", err);
        res.status(500).json({ error: "Erro ao buscar histórico de mensagens do usuário." });
    }
});

route.delete("/admin/mensagens/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const { id } = req.params;

        await garantirAuditoriaMensagens();

        const [result] = await db.query(`
            UPDATE mensagens m
            LEFT JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
            LEFT JOIN usuarios u1 ON cd.usuario1_id = u1.id
            LEFT JOIN usuarios u2 ON cd.usuario2_id = u2.id
            LEFT JOIN grupos g ON m.grupo_id = g.id
            SET m.deletada_em = COALESCE(m.deletada_em, NOW()),
                m.deletada_por = COALESCE(m.deletada_por, ?)
            WHERE m.id = ?
            AND (
                (m.conversa_direta_id IS NOT NULL AND u1.empresa_id = ? AND u2.empresa_id = ?)
                OR (m.grupo_id IS NOT NULL AND g.empresa_id = ?)
            )
        `, [req.admin.id, id, empresaId, empresaId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Mensagem não encontrada" });
        }

        await registrarAuditoriaMensagem({
            mensagemId: Number(id),
            usuarioId: req.admin.id,
            acao: "apagada",
            valorNovo: { origem: "admin" },
            req,
        });

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao remover mensagem:", err);
        res.status(500).json({ error: "Erro ao remover mensagem" });
    }
});

const montarSnapshotUsuarioAdmin = (usuario = {}) => ({
    id: usuario.id,
    nome: usuario.nome,
    email: usuario.email,
    empresa_id: usuario.empresa_id,
    setor_id: usuario.setor_id,
    setor_nome: usuario.setor_nome || null,
    perfil: usuario.perfil,
    status: usuario.status,
    deletado_em: usuario.deletado_em || null,
});

const registrarAuditoriaAdminUsuario = async (req, dados = {}) => {
    if (!CONTROLE_OPERACIONAL_ENABLED) return;

    try {
        await registrarAuditoria({
            usuario: req.admin,
            tipo: AUDIT_TYPES.USUARIOS,
            origem: "CHAT_INTERNO_ADMIN",
            req,
            ...dados,
        });
    } catch (auditErr) {
        console.error("Erro ao registrar auditoria administrativa de usuario:", auditErr);
    }
};

// Computadores que usam o Workspace: quem, de onde, em qual versão e quando foi visto. Compara com a versão publicada.
route.get("/admin/workspace/dispositivos", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const publicada = lerVersaoPublicada();
        const online = dispositivosOnline(empresaId);
        const linhas = await listarDispositivos(empresaId);
        const dispositivos = linhas.map((d) => ({
            id: d.id,
            computador: d.computador || "(sem nome)",
            ip: d.ip,
            usuario: { id: d.usuario_id, nome: d.usuario_nome, email: d.usuario_email, setor: d.setor_nome || null },
            versao: d.versao,
            situacao: situacaoDaVersao(d.versao, publicada),
            online: online.has(`${d.usuario_id}:${String(d.dispositivo).toLowerCase()}`),
            primeiro_visto: d.primeiro_visto,
            ultimo_visto: d.ultimo_visto,
        }));
        res.set("Cache-Control", "no-store").json({ publicada, sinal: lerSinal(), dispositivos });
    } catch (err) {
        console.error("Erro ao listar computadores do Workspace:", err);
        res.status(500).json({ error: "Não foi possível listar os computadores." });
    }
});

// Manda os computadores atualizarem para a versão publicada: em silêncio (padrão) ou com aviso na tela.
route.post("/admin/workspace/forcar-atualizacao", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const sinal = gravarSinal({ obrigatoria: req.body?.obrigatoria === true, mensagem: req.body?.mensagem, ignorarRegra: req.body?.ignorarRegra === true });
        console.log(`[WORKSPACE] ${req.admin.nome} forçou a atualização para ${sinal.versao}${sinal.obrigatoria ? " (com aviso)" : " (silenciosa)"}${sinal.ignorarRegra ? ", IGNORANDO a regra de ligação/telefone aberto" : ""}.`);
        res.json({ sinal });
    } catch (err) {
        console.error("Erro ao forçar a atualização do Workspace:", err);
        res.status(err.status || 500).json({ error: err.message || "Não foi possível forçar a atualização." });
    }
});

route.delete("/admin/workspace/dispositivos/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        await removerDispositivo(req.admin.empresa_id, req.params.id);
        res.json({ ok: true });
    } catch (err) {
        console.error("Erro ao remover computador do Workspace:", err);
        res.status(500).json({ error: "Não foi possível remover o computador." });
    }
});

// Quem está com o aplicativo Acessa Workspace aberto agora (lista em memória, alimentada pelo socket).
route.get("/admin/workspace/online", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const online = listarWorkspace(empresaId);
        if (!online.length) return res.json([]);

        const [usuarios] = await db.query(`
            SELECT u.id, u.nome, u.email, u.avatar, u.perfil, s.nome AS setor_nome
            FROM usuarios u
            LEFT JOIN setores s ON s.id = u.setor_id
            WHERE u.empresa_id = ? AND u.deletado_em IS NULL AND u.id IN (?)
        `, [empresaId, online.map((o) => o.usuario_id)]);
        const porId = new Map(usuarios.map((u) => [Number(u.id), u]));

        res.json(online
            .filter((o) => porId.has(o.usuario_id))
            .map((o) => {
                const u = porId.get(o.usuario_id);
                return {
                    id: o.usuario_id,
                    nome: u.nome,
                    email: u.email,
                    avatar: u.avatar,
                    perfil: u.perfil,
                    setor_nome: u.setor_nome,
                    versao: o.versoes[0] || null,
                    desde: o.desde,
                    janelas: o.janelas,
                };
            })
            .sort((a, b) => String(a.nome).localeCompare(String(b.nome), "pt-BR")));
    } catch (err) {
        console.error("Erro ao listar quem usa o Workspace:", err);
        res.status(500).json({ error: "Erro ao listar quem está usando o aplicativo" });
    }
});

route.get("/admin/usuarios", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;

        const [usuarios] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.avatar,
                u.status,
                u.perfil,
                u.ultimo_acesso,
                u.setor_id,
                s.nome AS setor_nome,
                (
                    SELECT COUNT(*)
                    FROM mensagens m
                    WHERE m.remetente_id = u.id
                    AND m.deletada_em IS NULL
                ) AS mensagens_enviadas
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE u.empresa_id = ? AND u.deletado_em IS NULL
            ORDER BY u.perfil ASC, u.status DESC, u.nome ASC
        `, [empresaId]);

        res.json(usuarios);
    } catch (err) {
        console.error("Erro ao buscar usuários administrativos:", err);
        res.status(500).json({ error: "Erro ao buscar usuários" });
    }
});

// Painel de saúde (Admin): testa chat, banco, site, SGP e servidor de atualizações.
const servicoSaude = criarServicoSaude();
route.get("/admin/saude", authMiddleware, requireAdmin, async (_req, res) => {
    try {
        res.set("Cache-Control", "no-store").json(await servicoSaude.verificar());
    } catch (err) {
        console.error("Erro no painel de saúde:", err?.message);
        res.status(500).json({ error: "Não foi possível verificar agora." });
    }
});

// Relatório semanal da gestão (chat). Os destinatários são os mesmos do briefing diário (Admin > IA).
route.get("/admin/relatorio", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const [config, quem] = await Promise.all([lerConfigIa(empresaId), destinatariosDoBriefing(empresaId)]);
        res.json({ ...configDoRelatorio(config), destinatarios: quem.map((u) => u.nome) });
    } catch (err) {
        console.error("Erro ao ler o relatório semanal:", err?.message);
        res.status(500).json({ error: "Não foi possível carregar o relatório semanal." });
    }
});

route.put("/admin/relatorio", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const { ativo, dia, hora } = req.body || {};
        if (ativo !== undefined && typeof ativo !== "boolean") return res.status(400).json({ error: "Dados inválidos." });
        if (dia !== undefined && !(Number.isInteger(dia) && dia >= 0 && dia <= 6)) return res.status(400).json({ error: "Dia inválido." });
        if (hora !== undefined && !/^([01]\d|2[0-3]):[0-5]\d$/.test(String(hora))) return res.status(400).json({ error: "Hora inválida." });
        if (ativo !== undefined) await gravarConfigIa(empresaId, "relatorio_ativo", ativo ? "1" : "0");
        if (dia !== undefined) await gravarConfigIa(empresaId, "relatorio_dia", String(dia));
        if (hora !== undefined) await gravarConfigIa(empresaId, "relatorio_hora", String(hora));
        res.json(configDoRelatorio(await lerConfigIa(empresaId)));
    } catch (err) {
        console.error("Erro ao salvar o relatório semanal:", err?.message);
        res.status(500).json({ error: "Não foi possível salvar." });
    }
});

// Teste: manda o relatório da última semana só para quem clicou e devolve o texto.
route.post("/admin/relatorio/testar", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { enviados, texto } = await enviarRelatorio({ io: req.app.get("io"), empresaId: req.admin.empresa_id, para: req.admin.id });
        res.json({ enviados, texto });
    } catch (err) {
        console.error("Erro ao testar o relatório semanal:", err?.message);
        res.status(500).json({ error: "Não foi possível gerar o relatório agora." });
    }
});

// Índice de telefones (só números): estatística e atualização manual a partir da exportação do SGP.
route.get("/admin/telefones/indice", authMiddleware, requireAdmin, async (req, res) => {
    try { res.json(await indiceTelefones.estatisticas(req.admin.empresa_id)); }
    catch (err) { console.error("Erro no índice de telefones:", err?.message); res.status(500).json({ error: "Não foi possível ler o índice de telefones." }); }
});
route.post("/admin/telefones/indice/atualizar", authMiddleware, requireAdmin, async (req, res) => {
    try { res.status(202).json({ iniciado: indiceTelefones.iniciarAtualizacao(req.admin.empresa_id) }); }
    catch (err) {
        console.error("Erro ao atualizar o índice de telefones:", err?.message);
        res.status(500).json({ error: "Não foi possível atualizar o índice de telefones." });
    }
});

// Funções: o que cada setor vê no Workspace.
route.get("/me/funcoes", authMiddleware, async (req, res) => {
    try {
        res.json({ modulos: await modulosDoUsuario(req.user) });
    } catch (err) {
        console.error("Erro ao ler funções do usuário:", err?.message);
        res.status(500).json({ error: "Erro ao carregar permissões" });
    }
});

route.get("/admin/funcoes", authMiddleware, requireAdmin, async (req, res) => {
    try {
        res.json(await listarFuncoes(req.admin.empresa_id));
    } catch (err) {
        console.error("Erro ao listar funções:", err?.message);
        res.status(500).json({ error: "Erro ao carregar funções" });
    }
});

route.put("/admin/funcoes/:setorId", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const setorId = Number(req.params.setorId);
        const { modulos } = req.body || {};
        if (!Number.isInteger(setorId) || setorId <= 0 || (modulos !== null && !Array.isArray(modulos))) {
            return res.status(400).json({ error: "Dados inválidos." });
        }
        const salvo = await salvarFuncao(req.admin.empresa_id, setorId, modulos, req.admin.id);
        res.json({ ok: true, modulos: salvo });
    } catch (err) {
        if (err?.status) return res.status(err.status).json({ error: err.message });
        console.error("Erro ao salvar função:", err?.message);
        res.status(500).json({ error: "Erro ao salvar função" });
    }
});

route.get("/admin/setores", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;

        const [setores] = await db.query(`
            SELECT id, nome
            FROM setores
            WHERE empresa_id = ?
            ORDER BY nome ASC
        `, [empresaId]);

        res.json(setores);
    } catch (err) {
        console.error("Erro ao buscar setores administrativos:", err);
        res.status(500).json({ error: "Erro ao buscar setores" });
    }
});

route.post("/admin/usuarios", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const {
            nome,
            email,
            senha,
            setor_id,
            perfil = "usuario",
        } = req.body;

        const nomeNormalizado = (nome || "").trim();
        const emailNormalizado = (email || "").trim().toLowerCase();
        const senhaNormalizada = senha || "";

        if (!nomeNormalizado || !emailNormalizado || !senhaNormalizada || !setor_id) {
            return res.status(400).json({ error: "Nome, email, senha e setor são obrigatórios" });
        }

        if (senhaNormalizada.length < 6) {
            return res.status(400).json({ error: "A senha precisa ter pelo menos 6 caracteres" });
        }

        if (!PERFIS_VALIDOS.includes(perfil)) {
            return res.status(400).json({ error: "Perfil inválido" });
        }

        const [setor] = await db.query(`
            SELECT id, nome
            FROM setores
            WHERE id = ? AND empresa_id = ?
            LIMIT 1
        `, [setor_id, empresaId]);

        if (!setor.length) {
            return res.status(400).json({ error: "Setor inválido para essa empresa" });
        }

        const [existente] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.empresa_id,
                u.setor_id,
                s.nome AS setor_nome,
                u.perfil,
                u.status,
                u.deletado_em
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE u.email = ?
            LIMIT 1
        `, [emailNormalizado]);

        if (existente.length && !existente[0].deletado_em) {
            return res.status(409).json({ error: "Já existe um usuário com esse email" });
        }

        const hash = await bcrypt.hash(senhaNormalizada, 10);

        let userId;

        if (existente.length) {
            await db.query(`
                UPDATE usuarios
                SET nome = ?,
                    senha = ?,
                    empresa_id = ?,
                    setor_id = ?,
                    perfil = ?,
                    status = 'offline',
                    deletado_em = NULL
                WHERE id = ?
            `, [nomeNormalizado, hash, empresaId, setor_id, perfil, existente[0].id]);
            userId = existente[0].id;
        } else {
            const [result] = await db.query(`
                INSERT INTO usuarios (nome, email, senha, empresa_id, setor_id, perfil, status)
                VALUES (?, ?, ?, ?, ?, ?, 'offline')
            `, [nomeNormalizado, emailNormalizado, hash, empresaId, setor_id, perfil]);
            userId = result.insertId;
        }

        await garantirGruposFixos(empresaId, req.admin.id);
        await sincronizarGruposFixosDoUsuario(db, userId, empresaId);

        await registrarAuditoriaAdminUsuario(req, {
            acao: existente.length ? "REATIVAR_USUARIO" : "CRIAR_USUARIO",
            entidade: "usuario",
            entidadeId: userId,
            nivel: AUDIT_LEVELS.IMPORTANT,
            valorAnterior: existente.length ? montarSnapshotUsuarioAdmin(existente[0]) : null,
            valorNovo: {
                id: userId,
                nome: nomeNormalizado,
                email: emailNormalizado,
                empresa_id: empresaId,
                setor_id,
                setor_nome: setor[0].nome,
                perfil,
                status: "offline",
            },
            metadata: {
                senha_definida: true,
                grupos_fixos_sincronizados: true,
            },
        });

        res.status(201).json({
            id: userId,
            nome: nomeNormalizado,
            email: emailNormalizado,
            empresa_id: empresaId,
            setor_id,
            setor_nome: setor[0].nome,
            perfil,
            status: "offline",
            mensagens_enviadas: 0,
        });
    } catch (err) {
        console.error("Erro ao criar usuário administrativo:", err);
        res.status(500).json({ error: "Erro ao criar usuário" });
    }
});

route.put("/admin/usuarios/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const userId = Number(req.params.id);
        const { status, perfil, setor_id, senha } = req.body;

        if (!Number.isInteger(userId)) {
            return res.status(400).json({ error: "Usuário inválido" });
        }

        const fields = [];
        const values = [];
        let setorAtualizado = null;

        if (status !== undefined) {
            if (!["online", "offline", "away"].includes(status)) {
                return res.status(400).json({ error: "Status inválido" });
            }
            fields.push("status = ?");
            values.push(status);
        }

        if (perfil !== undefined) {
            if (!PERFIS_VALIDOS.includes(perfil)) {
                return res.status(400).json({ error: "Perfil inválido" });
            }
            if (userId === req.admin.id && perfil !== PERFIL_ADMIN) {
                return res.status(400).json({ error: "Você não pode remover seu próprio acesso admin" });
            }
            fields.push("perfil = ?");
            values.push(perfil);
        }

        if (setor_id !== undefined) {
            const [setor] = await db.query(`
                SELECT id, nome
                FROM setores
                WHERE id = ? AND empresa_id = ?
                LIMIT 1
            `, [setor_id, empresaId]);

            if (!setor.length) {
                return res.status(400).json({ error: "Setor inválido" });
            }

            setorAtualizado = setor[0];
            fields.push("setor_id = ?");
            values.push(setor_id);
        }

        if (senha !== undefined) {
            const senhaNormalizada = senha || "";

            if (senhaNormalizada.length < 6) {
                return res.status(400).json({ error: "A senha precisa ter pelo menos 6 caracteres" });
            }

            const hash = await bcrypt.hash(senhaNormalizada, 10);
            fields.push("senha = ?");
            values.push(hash);
        }

        if (!fields.length) {
            return res.status(400).json({ error: "Nada para atualizar" });
        }

        const [usuariosAntes] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.empresa_id,
                u.setor_id,
                s.nome AS setor_nome,
                u.perfil,
                u.status,
                u.deletado_em
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE u.id = ? AND u.empresa_id = ? AND u.deletado_em IS NULL
            LIMIT 1
        `, [userId, empresaId]);

        if (!usuariosAntes.length) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const usuarioAnterior = montarSnapshotUsuarioAdmin(usuariosAntes[0]);

        if (setor_id !== undefined) {
            await garantirGruposFixos(empresaId, req.admin.id);
        }

        values.push(userId, empresaId);

        const [result] = await db.query(`
            UPDATE usuarios
            SET ${fields.join(", ")}
            WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
        `, values);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        let sincronizacao = {
            grupos_adicionados: [],
            grupos_removidos: [],
        };

        if (setor_id !== undefined) {
            sincronizacao = await sincronizarGruposFixosDoUsuario(db, userId, empresaId);

            await notificarMudancaAcessoGrupos(req, {
                usuarioId: userId,
                gruposAdicionados: sincronizacao.grupos_adicionados,
                gruposRemovidos: sincronizacao.grupos_removidos,
            });
        }

        await registrarAuditoriaAdminUsuario(req, {
            acao: "ALTERAR_USUARIO",
            entidade: "usuario",
            entidadeId: userId,
            nivel: senha !== undefined || perfil !== undefined
                ? AUDIT_LEVELS.IMPORTANT
                : AUDIT_LEVELS.NORMAL,
            valorAnterior: usuarioAnterior,
            valorNovo: {
                ...usuarioAnterior,
                ...(status !== undefined ? { status } : {}),
                ...(perfil !== undefined ? { perfil } : {}),
                ...(setor_id !== undefined ? {
                    setor_id,
                    setor_nome: setorAtualizado?.nome || usuarioAnterior.setor_nome,
                } : {}),
            },
            metadata: {
                senha_alterada: senha !== undefined,
                grupos_fixos_sincronizados: setor_id !== undefined,
                grupos_adicionados: sincronizacao.grupos_adicionados,
                grupos_removidos: sincronizacao.grupos_removidos,
            },
        });

        res.json({
            success: true,
            setor_id: setorAtualizado?.id ?? setor_id,
            setor_nome: setorAtualizado?.nome,
            ...sincronizacao,
        });
    } catch (err) {
        console.error("Erro ao atualizar usuário:", err);
        res.status(500).json({ error: "Erro ao atualizar usuário" });
    }
});

route.delete("/admin/usuarios/:id", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const userId = Number(req.params.id);

        if (!Number.isInteger(userId)) {
            return res.status(400).json({ error: "Usuário inválido" });
        }

        if (userId === req.admin.id) {
            return res.status(400).json({ error: "Você não pode excluir seu próprio usuário" });
        }

        const [usuariosAntes] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.empresa_id,
                u.setor_id,
                s.nome AS setor_nome,
                u.perfil,
                u.status,
                u.deletado_em
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            WHERE u.id = ? AND u.empresa_id = ? AND u.deletado_em IS NULL
            LIMIT 1
        `, [userId, empresaId]);

        if (!usuariosAntes.length) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const usuarioAnterior = montarSnapshotUsuarioAdmin(usuariosAntes[0]);

        const [result] = await db.query(`
            UPDATE usuarios
            SET deletado_em = COALESCE(deletado_em, NOW()),
                status = 'offline'
            WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
        `, [userId, empresaId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Usuário não encontrado" });
        }

        const [gruposRemovidos] = await db.query(`
            DELETE gm
            FROM grupo_membros gm
            JOIN grupos g ON gm.grupo_id = g.id
            WHERE gm.usuario_id = ? AND g.empresa_id = ?
        `, [userId, empresaId]);

        await registrarAuditoriaAdminUsuario(req, {
            acao: "REMOVER_USUARIO",
            entidade: "usuario",
            entidadeId: userId,
            nivel: AUDIT_LEVELS.CRITICAL,
            valorAnterior: usuarioAnterior,
            valorNovo: {
                ...usuarioAnterior,
                status: "offline",
                deletado_em: true,
            },
            metadata: {
                grupos_removidos: gruposRemovidos.affectedRows || 0,
            },
        });

        res.json({ success: true });
    } catch (err) {
        console.error("Erro ao excluir usuário:", err);
        res.status(500).json({ error: "Erro ao excluir usuário" });
    }
});

route.get("/admin/grupos", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;

        await garantirGruposFixos(empresaId, req.admin.id);

        const [grupos] = await db.query(`
            SELECT
                g.id,
                g.nome,
                g.descricao,
                g.avatar,
                g.criador_id,
                g.fixo,
                g.setor_id,
                g.mensagem_fixada_titulo,
                g.mensagem_fixada_conteudo,
                g.mensagem_fixada_ativo,
                g.mensagem_fixada_atualizada_em,
                g.mensagem_fixada_atualizada_por,
                s.nome AS setor_nome,
                uc.nome AS criador_nome,
                g.criado_em,
                g.atualizado_em,
                (SELECT COUNT(*) FROM grupo_membros gm WHERE gm.grupo_id = g.id) AS total_membros,
                (
                    SELECT COUNT(*)
                    FROM mensagens m
                    WHERE m.grupo_id = g.id
                    AND m.deletada_em IS NULL
                ) AS total_mensagens
            FROM grupos g
            LEFT JOIN setores s ON g.setor_id = s.id
            LEFT JOIN usuarios uc ON g.criador_id = uc.id
            WHERE g.empresa_id = ?
              AND g.deletado_em IS NULL
            ORDER BY g.atualizado_em DESC
        `, [empresaId]);

        res.json(grupos.map((grupo) => ({
            ...grupo,
            fixo: Boolean(grupo.fixo),
            mensagem_fixada_ativo: Boolean(grupo.mensagem_fixada_ativo),
        })));
    } catch (err) {
        console.error("Erro ao buscar grupos administrativos:", err);
        res.status(500).json({ error: "Erro ao buscar grupos" });
    }
});

route.post("/admin/grupos", authMiddleware, requireAdmin, async (req, res) => {
    const connection = await db.getConnection();

    try {
        const empresaId = req.admin.empresa_id;
        const adminId = req.admin.id;
        const nome = String(req.body.nome || "").trim().replace(/\s+/g, " ");
        const descricao = req.body.descricao
            ? String(req.body.descricao).trim()
            : null;
        const usuarioIdsInformados = Array.isArray(req.body.usuario_ids)
            ? req.body.usuario_ids.map(Number)
            : [];

        if (usuarioIdsInformados.some((id) => !Number.isInteger(id))) {
            return res.status(400).json({ error: "Lista de usuários inválida." });
        }

        const usuarioIds = [
            ...new Set([...usuarioIdsInformados, adminId]),
        ].filter((id) => Number.isInteger(id));

        if (nome.length < 2 || nome.length > 80) {
            return res.status(400).json({ error: "Informe um nome de 2 a 80 caracteres." });
        }

        if (descricao && descricao.length > 255) {
            return res.status(400).json({ error: "A descrição deve ter até 255 caracteres." });
        }

        await garantirGruposFixos(empresaId, adminId);
        await garantirMetadadosGrupos(connection);

        const chaveGrupo = normalizarCategoria(nome);

        if (!chaveGrupo) {
            return res.status(400).json({ error: "Informe um nome válido para o grupo." });
        }

        const [gruposExistentes] = await connection.query(`
            SELECT id, nome, setor_id, deletado_em
            FROM grupos
            WHERE empresa_id = ?
        `, [empresaId]);
        const grupoComMesmoNome = gruposExistentes.find((grupo) => (
            normalizarCategoria(grupo.nome) === chaveGrupo
        ));

        if (grupoComMesmoNome && !grupoComMesmoNome.deletado_em) {
            return res.status(409).json({ error: "Já existe um grupo com esse nome." });
        }

        if (usuarioIds.length) {
            const [usuariosValidos] = await connection.query(`
                SELECT id
                FROM usuarios
                WHERE empresa_id = ?
                  AND deletado_em IS NULL
                  AND id IN (?)
            `, [empresaId, usuarioIds]);

            if (usuariosValidos.length !== usuarioIds.length) {
                return res.status(400).json({ error: "Há usuários inválidos para essa empresa." });
            }
        }

        await connection.beginTransaction();

        let grupoId;

        if (grupoComMesmoNome?.deletado_em) {
            grupoId = grupoComMesmoNome.id;

            await connection.query(`
                UPDATE grupos
                SET nome = ?,
                    descricao = ?,
                    criador_id = COALESCE(criador_id, ?),
                    fixo = 0,
                    setor_id = NULL,
                    deletado_em = NULL,
                    atualizado_em = NOW()
                WHERE id = ? AND empresa_id = ?
            `, [nome, descricao, adminId, grupoId, empresaId]);
        } else {
            const [result] = await connection.query(`
                INSERT INTO grupos (nome, descricao, criador_id, empresa_id, fixo, setor_id)
                VALUES (?, ?, ?, ?, 0, NULL)
            `, [nome, descricao, adminId, empresaId]);

            grupoId = result.insertId;
        }

        if (usuarioIds.length) {
            await connection.query(`
                INSERT IGNORE INTO grupo_membros (grupo_id, usuario_id)
                VALUES ?
            `, [usuarioIds.map((usuarioId) => [grupoId, usuarioId])]);
        }

        await connection.commit();

        const [gruposCriados] = await db.query(`
            SELECT
                g.id,
                g.nome,
                g.descricao,
                g.avatar,
                g.criador_id,
                g.fixo,
                g.setor_id,
                g.mensagem_fixada_titulo,
                g.mensagem_fixada_conteudo,
                g.mensagem_fixada_ativo,
                g.mensagem_fixada_atualizada_em,
                g.mensagem_fixada_atualizada_por,
                s.nome AS setor_nome,
                uc.nome AS criador_nome,
                g.criado_em,
                g.atualizado_em,
                (SELECT COUNT(*) FROM grupo_membros gm WHERE gm.grupo_id = g.id) AS total_membros,
                (
                    SELECT COUNT(*)
                    FROM mensagens m
                    WHERE m.grupo_id = g.id
                    AND m.deletada_em IS NULL
                ) AS total_mensagens
            FROM grupos g
            LEFT JOIN setores s ON g.setor_id = s.id
            LEFT JOIN usuarios uc ON g.criador_id = uc.id
            WHERE g.id = ? AND g.empresa_id = ? AND g.deletado_em IS NULL
            LIMIT 1
        `, [grupoId, empresaId]);

        res.status(201).json({
            ...gruposCriados[0],
            fixo: Boolean(gruposCriados[0]?.fixo),
            mensagem_fixada_ativo: Boolean(gruposCriados[0]?.mensagem_fixada_ativo),
        });
    } catch (err) {
        await connection.rollback();
        console.error("Erro ao criar grupo:", err);
        res.status(500).json({ error: "Erro ao criar grupo." });
    } finally {
        connection.release();
    }
});

route.delete("/admin/grupos/:id", authMiddleware, requireAdmin, async (req, res) => {
    const connection = await db.getConnection();

    try {
        const empresaId = req.admin.empresa_id;
        const grupoId = Number(req.params.id);

        if (!Number.isInteger(grupoId)) {
            return res.status(400).json({ error: "Grupo inválido." });
        }

        await garantirMetadadosGrupos(connection);

        const [grupos] = await connection.query(`
            SELECT id, nome
            FROM grupos
            WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
            LIMIT 1
        `, [grupoId, empresaId]);

        if (!grupos.length) {
            return res.status(404).json({ error: "Grupo não encontrado." });
        }

        await connection.beginTransaction();

        await connection.query(`
            UPDATE grupos
            SET deletado_em = NOW(),
                atualizado_em = NOW()
            WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
        `, [grupoId, empresaId]);

        await connection.query(`
            DELETE FROM grupo_membros
            WHERE grupo_id = ?
        `, [grupoId]);

        await connection.commit();

        res.json({
            success: true,
            id: grupoId,
        });
    } catch (err) {
        await connection.rollback();
        console.error("Erro ao excluir grupo:", err);
        res.status(500).json({ error: "Erro ao excluir grupo." });
    } finally {
        connection.release();
    }
});

route.get("/admin/grupos/:id/membros", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const grupoId = Number(req.params.id);

        if (!Number.isInteger(grupoId)) {
            return res.status(400).json({ error: "Grupo inválido" });
        }

        await garantirGruposFixos(empresaId, req.admin.id);

        const grupo = await buscarGrupoDaEmpresa(grupoId, empresaId);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        const [usuarios] = await db.query(`
            SELECT
                u.id,
                u.nome,
                u.email,
                u.avatar,
                u.perfil,
                u.status,
                u.setor_id,
                s.nome AS setor_nome,
                gm.id IS NOT NULL AS membro
            FROM usuarios u
            LEFT JOIN setores s ON u.setor_id = s.id
            LEFT JOIN grupo_membros gm
                ON gm.usuario_id = u.id
                AND gm.grupo_id = ?
            WHERE u.empresa_id = ? AND u.deletado_em IS NULL
            ORDER BY gm.id IS NULL ASC, s.nome ASC, u.nome ASC
        `, [grupoId, empresaId]);

        res.json({
            grupo,
            usuarios: usuarios.map((usuario) => ({
                ...usuario,
                membro: Boolean(usuario.membro),
            })),
        });
    } catch (err) {
        console.error("Erro ao buscar membros do grupo:", err);
        res.status(500).json({ error: "Erro ao buscar membros do grupo" });
    }
});

route.put("/admin/grupos/:id/fixado", authMiddleware, requireAdmin, async (req, res) => {
    try {
        const empresaId = req.admin.empresa_id;
        const grupoId = Number(req.params.id);
        const titulo = limitarTexto(req.body.titulo || "Mensagem fixada", 180);
        const conteudo = normalizarTextoLongo(req.body.conteudo, 3000);
        const ativo = Boolean(req.body.ativo);

        if (!Number.isInteger(grupoId)) {
            return res.status(400).json({ error: "Grupo inválido" });
        }

        if (ativo && !conteudo) {
            return res.status(400).json({ error: "Informe o conteúdo da mensagem fixada." });
        }

        await garantirMetadadosGrupos();

        const [result] = await db.query(`
            UPDATE grupos
            SET mensagem_fixada_titulo = ?,
                mensagem_fixada_conteudo = ?,
                mensagem_fixada_ativo = ?,
                mensagem_fixada_atualizada_em = NOW(),
                mensagem_fixada_atualizada_por = ?,
                atualizado_em = NOW()
            WHERE id = ?
              AND empresa_id = ?
              AND deletado_em IS NULL
        `, [
            titulo || "Mensagem fixada",
            conteudo || null,
            ativo ? 1 : 0,
            req.admin.id,
            grupoId,
            empresaId,
        ]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Grupo não encontrado." });
        }

        const grupo = await buscarGrupoDaEmpresa(grupoId, empresaId);
        const io = req.app.get("io");

        if (io) {
            io.to(`grupo_${grupoId}`).emit("group_pinned_message_updated", {
                grupo_id: grupoId,
                mensagem_fixada_titulo: grupo.mensagem_fixada_titulo,
                mensagem_fixada_conteudo: grupo.mensagem_fixada_conteudo,
                mensagem_fixada_ativo: Boolean(grupo.mensagem_fixada_ativo),
                mensagem_fixada_atualizada_em: grupo.mensagem_fixada_atualizada_em,
                mensagem_fixada_atualizada_por: grupo.mensagem_fixada_atualizada_por,
            });
        }

        res.json({
            ...grupo,
            fixo: Boolean(grupo.fixo),
            mensagem_fixada_ativo: Boolean(grupo.mensagem_fixada_ativo),
        });
    } catch (err) {
        console.error("Erro ao salvar mensagem fixada:", err);
        res.status(500).json({ error: "Erro ao salvar mensagem fixada." });
    }
});

route.post("/admin/grupos/:id/adicionar-acessos", authMiddleware, requireAdmin, async (req, res) => {
    const connection = await db.getConnection();

    try {
        const empresaId = req.admin.empresa_id;
        const grupoId = Number(req.params.id);
        const tipo = String(req.body.tipo || "").trim();

        if (!Number.isInteger(grupoId)) {
            return res.status(400).json({ error: "Grupo inválido" });
        }

        if (!["usuario", "setor", "cargo"].includes(tipo)) {
            return res.status(400).json({ error: "Tipo de inclusão inválido" });
        }

        await garantirGruposFixos(empresaId, req.admin.id);

        const grupo = await buscarGrupoDaEmpresa(grupoId, empresaId);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        let usuariosAlvo = [];

        if (tipo === "usuario") {
            const usuarioId = Number(req.body.usuario_id);

            if (!Number.isInteger(usuarioId)) {
                return res.status(400).json({ error: "Usuário inválido" });
            }

            const [usuarios] = await connection.query(`
                SELECT id, nome, setor_id
                FROM usuarios
                WHERE id = ?
                  AND empresa_id = ?
                  AND deletado_em IS NULL
                LIMIT 1
            `, [usuarioId, empresaId]);

            usuariosAlvo = usuarios;
        }

        if (tipo === "setor") {
            const setorId = Number(req.body.setor_id);

            if (!Number.isInteger(setorId)) {
                return res.status(400).json({ error: "Setor inválido" });
            }

            const [setor] = await connection.query(`
                SELECT id
                FROM setores
                WHERE id = ?
                  AND empresa_id = ?
                LIMIT 1
            `, [setorId, empresaId]);

            if (!setor.length) {
                return res.status(400).json({ error: "Setor inválido para essa empresa" });
            }

            const [usuarios] = await connection.query(`
                SELECT id, nome, setor_id
                FROM usuarios
                WHERE empresa_id = ?
                  AND setor_id = ?
                  AND deletado_em IS NULL
            `, [empresaId, setorId]);

            usuariosAlvo = usuarios;
        }

        if (tipo === "cargo") {
            const perfil = String(req.body.perfil || "").trim();

            if (!PERFIS_VALIDOS.includes(perfil)) {
                return res.status(400).json({ error: "Cargo inválido" });
            }

            const [usuarios] = await connection.query(`
                SELECT id, nome, setor_id
                FROM usuarios
                WHERE empresa_id = ?
                  AND perfil = ?
                  AND deletado_em IS NULL
            `, [empresaId, perfil]);

            usuariosAlvo = usuarios;
        }

        const usuarioIds = [...new Set(usuariosAlvo.map((usuario) => Number(usuario.id)))];

        if (!usuarioIds.length) {
            return res.status(400).json({ error: "Nenhum usuário encontrado para adicionar." });
        }

        await connection.beginTransaction();

        await connection.query(`
            INSERT IGNORE INTO grupo_membros (grupo_id, usuario_id)
            VALUES ?
        `, [usuarioIds.map((usuarioId) => [grupoId, usuarioId])]);

        await connection.query(`
            UPDATE grupos
            SET atualizado_em = NOW()
            WHERE id = ?
        `, [grupoId]);

        const [totalRows] = await connection.query(`
            SELECT COUNT(*) AS total_membros
            FROM grupo_membros
            WHERE grupo_id = ?
        `, [grupoId]);

        await connection.commit();

        await Promise.all(usuarioIds.map((usuarioId) => (
            notificarMudancaAcessoGrupos(req, {
                usuarioId,
                gruposAdicionados: [grupoId],
                gruposRemovidos: [],
            })
        )));

        res.json({
            success: true,
            message: "Usuários adicionados ao grupo.",
            total_membros: totalRows[0]?.total_membros || 0,
            usuarios_adicionados: usuarioIds,
        });
    } catch (err) {
        await connection.rollback();
        console.error("Erro ao adicionar acessos ao grupo:", err);
        res.status(500).json({ error: "Erro ao adicionar acessos ao grupo" });
    } finally {
        connection.release();
    }
});

route.put("/admin/grupos/:id/membros", authMiddleware, requireAdmin, async (req, res) => {
    const connection = await db.getConnection();

    try {
        const empresaId = req.admin.empresa_id;
        const grupoId = Number(req.params.id);
        const usuarioIds = Array.isArray(req.body.usuario_ids)
            ? [...new Set(req.body.usuario_ids.map(Number))]
            : [];

        if (!Number.isInteger(grupoId)) {
            return res.status(400).json({ error: "Grupo inválido" });
        }

        if (usuarioIds.some((id) => !Number.isInteger(id))) {
            return res.status(400).json({ error: "Lista de usuários inválida" });
        }

        await garantirGruposFixos(empresaId, req.admin.id);

        const grupo = await buscarGrupoDaEmpresa(grupoId, empresaId);

        if (!grupo) {
            return res.status(404).json({ error: "Grupo não encontrado" });
        }

        if (usuarioIds.length) {
            const [usuariosValidos] = await connection.query(`
                SELECT id
                FROM usuarios
                WHERE empresa_id = ?
                AND deletado_em IS NULL
                AND id IN (?)
            `, [empresaId, usuarioIds]);

            if (usuariosValidos.length !== usuarioIds.length) {
                return res.status(400).json({ error: "Há usuários inválidos para essa empresa" });
            }
        }

        await connection.beginTransaction();

        const [membrosAtuais] = await connection.query(`
            SELECT usuario_id
            FROM grupo_membros
            WHERE grupo_id = ?
        `, [grupoId]);

        const idsAtuais = membrosAtuais.map((membro) => Number(membro.usuario_id));
        const idsAtuaisSet = new Set(idsAtuais);
        const idsSolicitadosSet = new Set(usuarioIds.map(Number));
        const usuariosAdicionados = usuarioIds.filter((usuarioId) => !idsAtuaisSet.has(Number(usuarioId)));
        const usuariosRemovidos = idsAtuais.filter((usuarioId) => !idsSolicitadosSet.has(Number(usuarioId)));

        await connection.query(`
            DELETE FROM grupo_membros
            WHERE grupo_id = ?
        `, [grupoId]);

        if (usuarioIds.length) {
            await connection.query(`
                INSERT INTO grupo_membros (grupo_id, usuario_id)
                VALUES ?
            `, [usuarioIds.map((usuarioId) => [grupoId, usuarioId])]);
        }

        await connection.query(`
            UPDATE grupos
            SET atualizado_em = NOW()
            WHERE id = ?
        `, [grupoId]);

        await connection.commit();

        await Promise.all([
            ...usuariosAdicionados.map((usuarioId) => (
                notificarMudancaAcessoGrupos(req, {
                    usuarioId,
                    gruposAdicionados: [grupoId],
                    gruposRemovidos: [],
                })
            )),
            ...usuariosRemovidos.map((usuarioId) => (
                notificarMudancaAcessoGrupos(req, {
                    usuarioId,
                    gruposAdicionados: [],
                    gruposRemovidos: [grupoId],
                })
            )),
        ]);

        res.json({
            success: true,
            message: "Membros do grupo atualizados.",
            total_membros: usuarioIds.length,
            usuarios_adicionados: usuariosAdicionados,
            usuarios_removidos: usuariosRemovidos,
        });
    } catch (err) {
        await connection.rollback();
        console.error("Erro ao atualizar membros do grupo:", err);
        res.status(500).json({ error: "Erro ao atualizar membros do grupo" });
    } finally {
        connection.release();
    }
});

const AUDIT_INGEST_TOKEN = process.env.AUDIT_INGEST_TOKEN || getSecret();

const validarTokenIngestAuditoria = (req, res, next) => {
    const recebido = String(
        req.headers["x-audit-token"]
        || req.headers["x-operational-audit-token"]
        || req.headers.authorization?.replace(/^Bearer\s+/i, "")
        || ""
    );

    if (!AUDIT_INGEST_TOKEN || recebido !== AUDIT_INGEST_TOKEN) {
        return res.status(401).json({ error: "Token de auditoria inválido." });
    }

    return next();
};

const normalizarLimiteControle = (valor, fallback = 20, max = 100) => {
    const numero = Number(valor);
    if (!Number.isInteger(numero) || numero <= 0) return fallback;
    return Math.min(numero, max);
};

const termoBuscaControle = (valor) => String(valor || "").trim().slice(0, 120);

const buscarMensagensControle = async ({ empresaId, search = "", usuarioId = null, limit = 12 }) => {
    const termo = termoBuscaControle(search);
    if (!termo && !usuarioId) return [];

    const where = [
        `(
            (m.conversa_direta_id IS NOT NULL AND u1.empresa_id = ? AND u2.empresa_id = ?)
            OR (m.grupo_id IS NOT NULL AND g.empresa_id = ?)
        )`,
    ];
    const params = [empresaId, empresaId, empresaId];

    if (termo) {
        where.push("(m.mensagem LIKE ? OR CAST(m.id AS CHAR) = ?)");
        params.push(`%${termo}%`, termo);
    }

    if (usuarioId) {
        where.push("m.remetente_id = ?");
        params.push(usuarioId);
    }

    const [rows] = await db.query(`
        SELECT
            m.id,
            m.remetente_id,
            autor.nome AS remetente_nome,
            m.grupo_id,
            g.nome AS grupo_nome,
            m.conversa_direta_id,
            m.tipo_mensagem,
            CASE
                WHEN m.tipo_mensagem = 'imagem' THEN '[Imagem]'
                WHEN m.tipo_mensagem = 'audio' THEN '[Áudio]'
                WHEN m.tipo_mensagem = 'arquivo' THEN '[Arquivo]'
                WHEN m.tipo_mensagem = 'sticker' THEN 'Figurinha'
                ELSE LEFT(m.mensagem, 220)
            END AS previa,
            m.criada_em,
            m.editada_em,
            m.deletada_em
        FROM mensagens m
        JOIN usuarios autor ON autor.id = m.remetente_id
        LEFT JOIN grupos g ON g.id = m.grupo_id
        LEFT JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id
        LEFT JOIN usuarios u1 ON u1.id = cd.usuario1_id
        LEFT JOIN usuarios u2 ON u2.id = cd.usuario2_id
        WHERE ${where.join(" AND ")}
        ORDER BY m.criada_em DESC, m.id DESC
        LIMIT ?
    `, [...params, normalizarLimiteControle(limit, 12, 50)]);

    return rows;
};

const buscarUsuariosControle = async ({ empresaId, search = "", limit = 10 }) => {
    const termo = termoBuscaControle(search);
    if (!termo) return [];

    const [rows] = await db.query(`
        SELECT id, nome, email, perfil, status, ultimo_acesso
        FROM usuarios
        WHERE empresa_id = ?
          AND deletado_em IS NULL
          AND (nome LIKE ? OR email LIKE ? OR CAST(id AS CHAR) = ?)
        ORDER BY nome ASC
        LIMIT ?
    `, [empresaId, `%${termo}%`, `%${termo}%`, termo, normalizarLimiteControle(limit, 10, 50)]);

    return rows;
};

const responderTimelineControle = async (req, res, filtrosExtras = {}) => {
    try {
        const resultado = await listarAuditLogs({
            empresaId: req.admin.empresa_id,
            page: req.query.page,
            limit: req.query.limit || 50,
            periodo: req.query.periodo || "30d",
            ...filtrosExtras,
        });

        res.json(resultado);
    } catch (err) {
        console.error("Erro ao buscar timeline operacional:", err);
        res.status(500).json({ error: "Erro ao buscar histórico operacional." });
    }
};

const requireControleOperacionalEnabled = (_req, res, next) => {
    if (CONTROLE_OPERACIONAL_ENABLED) return next();
    return res.status(404).json({ error: "Central de Controle desativada temporariamente." });
};

route.get("/audit", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const resultado = await listarAuditLogs({
            empresaId: req.admin.empresa_id,
            ...req.query,
        });
        res.json(resultado);
    } catch (err) {
        console.error("Erro ao listar auditoria:", err);
        res.status(500).json({ error: "Erro ao listar auditoria." });
    }
});

route.get("/audit/:id", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const log = await obterAuditLogPorId(Number(req.params.id), req.admin.empresa_id);
        if (!log) return res.status(404).json({ error: "Evento não encontrado." });
        return res.json(log);
    } catch (err) {
        console.error("Erro ao buscar auditoria:", err);
        return res.status(500).json({ error: "Erro ao buscar auditoria." });
    }
});

route.get("/audit/entity/:tipo/:id", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => (
    responderTimelineControle(req, res, {
        entidade: req.params.tipo,
        entidadeId: req.params.id,
    })
));

route.post("/controle-operacional/ingest", validarTokenIngestAuditoria, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const payload = req.body || {};
        const id = await registrarAuditoria({
            empresaId: payload.empresa_id || payload.empresaId || null,
            usuarioId: payload.usuario_id || payload.usuarioId || null,
            usuarioNome: payload.usuario_nome || payload.usuarioNome || null,
            usuarioPerfil: payload.usuario_perfil || payload.usuarioPerfil || null,
            acao: payload.acao,
            entidade: payload.entidade,
            entidadeId: payload.entidade_id ?? payload.entidadeId,
            tipo: payload.tipo,
            nivel: payload.nivel,
            origem: payload.origem || "API",
            valorAnterior: payload.valor_anterior ?? payload.valorAnterior ?? null,
            valorNovo: payload.valor_novo ?? payload.valorNovo ?? null,
            metadata: payload.metadata || null,
            eventId: payload.event_id || payload.eventId || null,
            req,
        });

        res.status(201).json({ id });
    } catch (err) {
        console.error("Erro ao ingerir auditoria operacional:", err);
        res.status(400).json({ error: err.message || "Auditoria inválida." });
    }
});

route.get("/controle-operacional/resumo", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const resumo = await obterResumoOperacional(req.admin.empresa_id, req.query.periodo || "hoje");
        res.json(resumo);
    } catch (err) {
        console.error("Erro ao buscar resumo operacional:", err);
        res.status(500).json({ error: "Erro ao buscar resumo operacional." });
    }
});

route.get("/controle-operacional/feed", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const resultado = await listarAuditLogs({
            empresaId: req.admin.empresa_id,
            page: req.query.page,
            limit: req.query.limit || 25,
            periodo: req.query.periodo || "hoje",
            dataInicio: req.query.dataInicio || req.query.data_inicio,
            dataFim: req.query.dataFim || req.query.data_fim,
            usuario: req.query.usuario,
            tecnico: req.query.tecnico,
            entidade: req.query.entidade,
            acao: req.query.acao,
            nivel: req.query.nivel,
            tipo: req.query.tipo,
            search: req.query.search,
            criticalOnly: req.query.criticos === "1" || req.query.criticos === "true",
        });

        res.json(resultado);
    } catch (err) {
        console.error("Erro ao buscar feed operacional:", err);
        res.status(500).json({ error: "Erro ao buscar feed operacional." });
    }
});

route.get("/controle-operacional/search", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const search = termoBuscaControle(req.query.q || req.query.search);
        if (!search) {
            return res.json({
                query: "",
                audit_logs: [],
                mensagens: [],
                usuarios: [],
            });
        }

        const [auditLogs, mensagens, usuarios] = await Promise.all([
            listarAuditLogs({
                empresaId: req.admin.empresa_id,
                search,
                limit: req.query.limit || 20,
                page: 1,
            }),
            buscarMensagensControle({
                empresaId: req.admin.empresa_id,
                search,
                limit: 12,
            }),
            buscarUsuariosControle({
                empresaId: req.admin.empresa_id,
                search,
                limit: 10,
            }),
        ]);

        return res.json({
            query: search,
            audit_logs: auditLogs.data,
            mensagens,
            usuarios,
            pagination: auditLogs.pagination,
        });
    } catch (err) {
        console.error("Erro na pesquisa operacional:", err);
        return res.status(500).json({ error: "Erro ao pesquisar auditoria operacional." });
    }
});

route.get("/controle-operacional/chamado/:id", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const id = String(req.params.id || "").trim();
        const [timeline, mensagens] = await Promise.all([
            listarAuditLogs({
                empresaId: req.admin.empresa_id,
                entidade: "chamado",
                entidadeId: id,
                search: id,
                limit: req.query.limit || 100,
                page: req.query.page || 1,
            }),
            buscarMensagensControle({
                empresaId: req.admin.empresa_id,
                search: id,
                limit: 30,
            }),
        ]);

        res.json({
            entidade: "chamado",
            id,
            timeline: timeline.data,
            mensagens,
            pagination: timeline.pagination,
            historico_disponivel_desde: "2026-08-12",
        });
    } catch (err) {
        console.error("Erro ao buscar histórico do chamado:", err);
        res.status(500).json({ error: "Erro ao buscar histórico do chamado." });
    }
});

route.get("/controle-operacional/instalacao/:id", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => (
    responderTimelineControle(req, res, {
        entidade: "instalacao",
        entidadeId: req.params.id,
        search: req.params.id,
    })
));

route.get("/controle-operacional/usuario/:id", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => {
    try {
        const usuarioId = Number(req.params.id);
        if (!Number.isInteger(usuarioId) || usuarioId <= 0) {
            return res.status(400).json({ error: "Usuário inválido." });
        }

        const [[usuarioRows], timeline, mensagens] = await Promise.all([
            db.query(`
                SELECT id, nome, email, perfil, status, ultimo_acesso
                FROM usuarios
                WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL
                LIMIT 1
            `, [usuarioId, req.admin.empresa_id]),
            listarAuditLogs({
                empresaId: req.admin.empresa_id,
                usuario: usuarioId,
                periodo: req.query.periodo || "hoje",
                limit: req.query.limit || 100,
                page: req.query.page || 1,
            }),
            buscarMensagensControle({
                empresaId: req.admin.empresa_id,
                usuarioId,
                limit: 30,
            }),
        ]);

        if (!usuarioRows.length) {
            return res.status(404).json({ error: "Usuário não encontrado." });
        }

        return res.json({
            usuario: usuarioRows[0],
            timeline: timeline.data,
            mensagens,
            pagination: timeline.pagination,
        });
    } catch (err) {
        console.error("Erro ao buscar histórico do usuário:", err);
        return res.status(500).json({ error: "Erro ao buscar histórico do usuário." });
    }
});

route.get("/controle-operacional/tecnico/:id", authMiddleware, requireAdmin, requireControleOperacionalEnabled, async (req, res) => (
    responderTimelineControle(req, res, {
        tecnico: req.params.id,
        periodo: req.query.periodo || "30d",
    })
));

// Antes das rotas que aplicam autenticação a tudo (a verificação de certificado é pública).
route.use("/cursos", cursosRoutes);
route.use("/marketing", marketingRoutes);
route.use("/ia/assistente", assistenteRoutes);
route.use("/lembretes", lembretesRoutes);
route.use("/phone", phoneRoutes);
route.use("/admin/phone", authMiddleware, criarPhoneAdminRoutes({ requireAdmin }));
route.use("/remoto", remotoRoutes);
route.use("/admin/remoto", authMiddleware, criarRemotoAdminRoutes({ requireAdmin }));
route.use("/admin/ia", authMiddleware, criarIaAdminRoutes({ requireAdmin }));
route.use("/admin/navegador", authMiddleware, criarRotasNavegadorAdmin({ requireAdmin }));
route.use("/ia", iaResumoRoutes);
route.use("/chamados", chamadosRoutes);
route.use("/clientes/ligacao", clienteLigacaoRoutes);
route.use("/presenca", presencaRoutes);
route.use("/navegador", navegadorRoutes);
route.use(networkDiagnosticsRoutes);
route.use(oltRoutes);
route.use(bmpRoutes);
route.use(purchaseModuleRoutes);
route.use("/roulette", rouletteRoutes);

export default route;
