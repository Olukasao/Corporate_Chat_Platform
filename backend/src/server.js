import { config as dotenvConfig } from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
dotenvConfig({ path: path.resolve(__dirname, '../../.env') });
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import http from 'http';
import fs from 'fs';
import { Server } from 'socket.io';
import jwt from 'jsonwebtoken';
import db from './db/db.js';
import { iniciarAvaliacoesNovas, SALA_AVALIACOES } from './services/avaliacoesSiteService.js';
import { usuarioTemModulo } from './services/funcoesService.js';
import { servicoSituacao } from './services/situacaoService.js';
import { iniciarRegistroMassivos } from './services/massivosHistoricoService.js';
import { iniciarRelatorioSemanal } from './services/relatorioSemanalService.js';
import { iniciarIndiceTelefones } from './services/indiceTelefonesService.js';
import route from "./Routes/Routes.js";
import { getDiagnosticRunByRunId } from './repositories/networkDiagnosticsRepository.js';
import { userHasNetworkDiagnosticPermission } from './services/networkDiagnosticPermissionsService.js';
import { getJwtSecret } from './config/authSecrets.js';
import { lerCookieAgenda, validarSessaoAgenda } from './services/agendaSessionService.js';
import { iniciarAgendaTecnicosResumo } from './services/agendaTecnicosResumoService.js';
import { iniciarBriefing } from './services/briefingService.js';
import { iniciarLembretes } from './services/lembretesAlarme.js';
import { iniciarMonitorOlt } from './services/oltCloudService.js';
import { usuarioPodeVerRedeOlt } from './Routes/oltRoutes.js';
import { dashboardRelay } from './services/dashboardRelayService.js';
import { registrarWorkspace, removerWorkspace } from './services/workspacePresenceService.js';
import { dispositivoValido, marcarSaida, registrarVisto } from './services/workspaceDispositivosService.js';
import {
    iniciarContratacoesPendentes,
    obterResumoContratacoes,
    SALA_CONTRATACOES,
} from './services/contratacoesPendentesService.js';
import { AUDIT_LEVELS, AUDIT_TYPES, registrarAuditoria } from './services/auditService.js';
import { getAllowedSoundEffect, PUBLIC_SOUNDS_ROOT } from './services/soundEffectsService.js';
import {
    buscarUsuarioAlvoEfeitoSonoro,
    obterNomeGrupoAlvoEfeitosSonoros,
    obterPermissaoEfeitosSonoros,
} from './services/soundEffectPermissionsService.js';
import { resolverVolumePercent, VOLUME_PADRAO_PERCENT } from './services/soundEffectVolume.js';
import { registrarAppDownload } from './services/appDownload.js';
import { criarParsersDeCorpo } from './security/bodyLimits.js';
import { aplicarCabecalhosUpload } from './security/uploadSecurity.js';
import {
    criarAutorizadorSocket,
    criarMiddlewareAutenticacaoSocket,
    identidadeDoSocket,
    lerModoAutenticacaoSocket,
    normalizarIdSocket,
    verificarJwtHS256,
} from './security/socketSecurity.js';

const app = express();
// Limites de corpo: 1 MB por padrão (src/security/bodyLimits.js; rotas maiores listadas lá).
// Anexos trafegam por upload multipart (/api/chat/upload); o socket só leva texto/URL, então 10 MB sobra.
const SOCKET_MAX_BUFFER_SIZE = (Number(process.env.SOCKET_MAX_BUFFER_MB) || 10) * 1024 * 1024;
const SOCKET_AUTH_MODE = lerModoAutenticacaoSocket();
const NETWORK_DIAGNOSTIC_RUN_ID_REGEX = /^nd_[a-zA-Z0-9_-]{8,80}$/;
const SOUND_EFFECT_MAX_VOLUME = 0.7;
const SOUND_EFFECT_DEFAULT_VOLUME = 0.6;
const SOUND_EFFECT_TARGET_COOLDOWN_MS = 20_000;
const SOUND_EFFECT_ADMIN_WINDOW_MS = 60_000;
const SOUND_EFFECT_ADMIN_MAX_PER_WINDOW = 5;

const parseOrigins = (...values) => values
    .flatMap((value) => String(value || '').split(','))
    .map((origin) => origin.trim())
    .filter(Boolean)
    .map((origin) => {
        try {
            return new URL(origin).origin;
        } catch {
            return null;
        }
    })
    .filter(Boolean);

const allowedOrigins = new Set(parseOrigins(
    process.env.CORS_ALLOWED_ORIGINS,
    process.env.NODE_ENV !== 'production'
        ? 'http://localhost:5173,http://127.0.0.1:5173,http://192.168.1.133:5173'
        : ''
));
const socketAllowedOrigins = Array.from(new Set([
    ...allowedOrigins,
    ...parseOrigins(process.env.SOCKET_CORS_ORIGIN),
]));

app.disable('x-powered-by');
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback');
app.use(cors({
    credentials: true,
    origin(origin, callback) {
        callback(null, !origin || allowedOrigins.has(origin));
    },
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
}));
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", 'data:', 'blob:', 'https:'],
            mediaSrc: ["'self'", 'data:', 'blob:', 'https:'],
            connectSrc: ["'self'", 'https:', 'wss:', 'http:', 'ws:'],
            frameSrc: ["'self'", 'https:'],
            frameAncestors: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            "upgrade-insecure-requests": null,
        },
    },
    crossOriginResourcePolicy: false,
    hsts: false,
    referrerPolicy: { policy: 'no-referrer' },
}));
const parsersDeCorpo = criarParsersDeCorpo({
    // Só confere a assinatura (sem banco) antes de ler corpo grande.
    verificarAssinatura: (token) => {
        try {
            verificarJwtHS256(token, getJwtSecret());
            return true;
        } catch {
            return false;
        }
    },
});
app.use(parsersDeCorpo.json);
app.use(parsersDeCorpo.urlencoded);
app.get('/health', (req, res) => {
    res.json({ status: 'ok' });
});
registrarAppDownload(app);
app.use("/api", route);

const emailSignaturesPath = path.resolve(__dirname, '../../email-signatures');
const chatUploadsPath = path.resolve(__dirname, '../../uploads/chat');
const stickerUploadsPath = path.resolve(__dirname, '../../uploads/stickers');
const wallpaperUploadsPath = path.resolve(__dirname, '../../uploads/wallpapers');
const wikiUploadsPath = path.resolve(__dirname, '../../uploads/wiki');
const internalRequestsUploadsPath = path.resolve(__dirname, '../../uploads/solicitacoes');
const purchaseUploadsPath = path.resolve(__dirname, '../../uploads/compras');
const salesUploadsPath = path.resolve(__dirname, '../../uploads/vendas');
const ccnaCompetitionUploadsPath = path.resolve(__dirname, '../../uploads/ccna-competition');
const bannerHomeUploadsPath = path.resolve(__dirname, '../../uploads/banner-home');
const avisosUploadsPath = path.resolve(__dirname, '../../uploads/avisos');
const rouletteUploadsPath = path.resolve(__dirname, '../../uploads/roulette');
const imagensGaleriaUploadsPath = path.resolve(__dirname, '../../uploads/imagens');
const frontendDistPath = path.resolve(__dirname, '../../frontend/dist');
const frontendIndexPath = path.join(frontendDistPath, 'index.html');
const emailSignaturesCsp = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "connect-src 'self' http: https: ws: wss:",
    "media-src 'self' data: blob: https:",
    "frame-src 'self' https:",
    "frame-ancestors 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self' mailto:",
].join('; ');

fs.mkdirSync(chatUploadsPath, { recursive: true });
fs.mkdirSync(stickerUploadsPath, { recursive: true });
fs.mkdirSync(wikiUploadsPath, { recursive: true });
fs.mkdirSync(internalRequestsUploadsPath, { recursive: true });
fs.mkdirSync(purchaseUploadsPath, { recursive: true });
fs.mkdirSync(salesUploadsPath, { recursive: true });
fs.mkdirSync(ccnaCompetitionUploadsPath, { recursive: true });
fs.mkdirSync(bannerHomeUploadsPath, { recursive: true });
fs.mkdirSync(avisosUploadsPath, { recursive: true });
fs.mkdirSync(rouletteUploadsPath, { recursive: true });
fs.mkdirSync(imagensGaleriaUploadsPath, { recursive: true });

if (fs.existsSync(emailSignaturesPath)) {
    app.use('/email-signatures', express.static(emailSignaturesPath, {
        setHeaders: (res) => {
            res.setHeader('Content-Security-Policy', emailSignaturesCsp);
        },
    }));
}

if (fs.existsSync(PUBLIC_SOUNDS_ROOT)) {
    app.use('/sounds', express.static(PUBLIC_SOUNDS_ROOT, {
        immutable: true,
        maxAge: '30d',
        setHeaders: (res) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
            // Os sons são públicos; o app precisa dessa permissão para amplificar (acima de 100%) o áudio vindo do Chat.
            res.setHeader('Access-Control-Allow-Origin', '*');
        },
    }));
}

app.use('/uploads/chat', express.static(chatUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));

app.use('/uploads/stickers', express.static(stickerUploadsPath, {
    immutable: true,
    maxAge: '30d',
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
        res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
    },
}));

app.use('/uploads/wallpapers', express.static(wallpaperUploadsPath, {
    immutable: true,
    maxAge: '30d',
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
        res.setHeader('Cache-Control', 'public, max-age=2592000, immutable');
    },
}));

app.use('/uploads/wiki', express.static(wikiUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/solicitacoes', express.static(internalRequestsUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/compras', express.static(purchaseUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/vendas', express.static(salesUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/ccna-competition', express.static(ccnaCompetitionUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/banner-home', express.static(bannerHomeUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/avisos', express.static(avisosUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/roulette', express.static(rouletteUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.use('/uploads/imagens', express.static(imagensGaleriaUploadsPath, {
    setHeaders: (res, filePath) => {
        aplicarCabecalhosUpload(res, filePath);
    },
}));
app.get(/^\/uploads\/wiki\/.*/, (_req, res) => {
    res.status(404).json({ error: 'Mídia da aula não encontrada' });
});

if (fs.existsSync(frontendIndexPath)) {
    app.use(express.static(frontendDistPath));
    app.get(/^\/assets\/.*/, (req, res) => {
        res.status(404).send('Asset não encontrado');
    });
    app.get(/^\/(?!api\/|socket\.io\/).*/, (req, res, next) => {
        if (req.method !== 'GET') {
            return next();
        }

        res.sendFile(frontendIndexPath, (err) => {
            if (err) {
                next(err);
            }
        });
    });
} else {
    console.warn(`[APP] Frontend build não encontrado em ${frontendDistPath}. Rode "npm run build" no frontend.`);
}

app.use((err, _req, res, _next) => {
    if (err?.type === 'entity.too.large') {
        console.warn(`[APP] Corpo acima do limite recusado: ${_req.method} ${String(_req.originalUrl || '').split('?')[0]} (${err.length || '?'} bytes)`);
        return res.status(413).json({ success: false, message: 'Requisição muito grande.' });
    }

    if (err instanceof SyntaxError && err?.status === 400) {
        return res.status(400).json({ success: false, message: 'Requisição inválida.' });
    }

    console.error('[APP] Erro não tratado:', { name: err?.name || 'Error' });
    return res.status(500).json({ success: false, message: 'Erro interno.' });
});

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: socketAllowedOrigins.length ? socketAllowedOrigins : false,
        credentials: true,
    },
    transports: ['websocket', 'polling'],
    maxHttpBufferSize: SOCKET_MAX_BUFFER_SIZE
});

app.set('io', io);

const buscarUsuarioDoSocket = async (id) => {
    const usuarioId = normalizarIdSocket(id);
    if (!usuarioId) return null;
    const [rows] = await db.query(`
        SELECT u.id, u.nome, u.email, u.avatar, u.empresa_id, u.setor_id, s.nome AS setor_nome, u.perfil
        FROM usuarios u
        LEFT JOIN setores s ON s.id = u.setor_id
        WHERE u.id = ? AND u.deletado_em IS NULL
        LIMIT 1
    `, [usuarioId]);
    return rows[0] || null;
};

// Autenticação no handshake (C1). Modo em SOCKET_AUTH_MODE: enforce (padrão) | log | off.
io.use(criarMiddlewareAutenticacaoSocket({
    modo: SOCKET_AUTH_MODE,
    verificarToken: (token) => verificarJwtHS256(token, getJwtSecret()),
    buscarUsuario: buscarUsuarioDoSocket,
    sessaoAgenda: (socket) => validarSessaoAgenda(lerCookieAgenda(socket.handshake?.headers?.cookie)),
}));
console.log(`[SOCKET] Autenticação do handshake em modo "${SOCKET_AUTH_MODE}"`);

const autorizador = criarAutorizadorSocket(db);

// Situação da agenda de técnicos para o card da home (evento agenda-tecnicos:resumo).
iniciarAgendaTecnicosResumo(io);
// Ambiente de TESTES (AMBIENTE_TESTE=1): não gasta IA nem dispara alarmes; o resto é só leitura.
const AMBIENTE_TESTE = String(process.env.AMBIENTE_TESTE || '') === '1';
if (AMBIENTE_TESTE) {
    console.log('[TESTE] Ambiente de testes: briefing da IA e alarmes de lembretes desligados.');
} else {
    iniciarBriefing(io);
    iniciarLembretes(io);
    iniciarRelatorioSemanal(io);
    iniciarIndiceTelefones(); // exportação noturna de telefones do SGP (só números) para achar o DDD de números discados sem DDD
}
// Histórico de massivos (para o relatório semanal): guarda um retrato a cada 5 minutos enquanto houver massivo.
iniciarRegistroMassivos();
dashboardRelay.start();

// Incidentes de rede da OLT Cloud: quem tem acesso à rede entra na sala "olt_watchers" e recebe o aviso de novos incidentes.
// Só liga se as credenciais da OLT Cloud estiverem no .env (OLTCLOUD_*).
iniciarMonitorOlt({
    aoEventoMassa: (p) => io.to('olt_watchers').emit('olt_evento_massa', {
        semEnergia: p.semEnergia, loss: p.loss, aumento: p.aumento, olts: p.porOlt.slice(0, 3).map((o) => o.olt),
    }),
    aoSurgir: (i) => io.to('olt_watchers').emit('olt_incidente_novo', {
        id: i.id, tipo: i.tipo, olt: i.olt, pon: i.pon, slotPon: i.slotPon, cto: i.cto,
        dispositivosAtivos: i.dispositivosAtivos, totalDispositivos: i.totalDispositivos, inicio: i.inicio,
    }),
});

// Contratações pendentes do site (eventos contratacoes:resumo e contratacoes:novo).
iniciarContratacoesPendentes(io);
// Avaliações novas do atendimento (evento avaliacoes:nova) para quem tem a área Chamados.
iniciarAvaliacoesNovas(io);

// Mapa de usuários conectados e suas abas/dispositivos ativos
const usuariosConectados = new Map();
const soundEffectTargetCooldowns = new Map();
const soundEffectAdminHistory = new Map();
let leiturasMensagensTabelaGarantida = false;
let leiturasGruposTabelaGarantida = false;
let leiturasMensagensTabelaGarantidaPromise = null;
let leiturasGruposTabelaGarantidaPromise = null;

const normalizarId = (id) => String(id);

const obterPresencaUsuario = (usuarioId) => (
    usuariosConectados.get(normalizarId(usuarioId))
);

const usuarioEstaConectado = (usuarioId) => {
    const presenca = obterPresencaUsuario(usuarioId);
    return Boolean(presenca?.sockets?.size);
};

const normalizarSoundKey = (soundKey = '') => (
    String(soundKey || '').trim().toLowerCase()
);

const normalizarVolumeEfeitoSonoro = (volume) => {
    const numero = Number(volume);

    if (!Number.isFinite(numero)) {
        return SOUND_EFFECT_DEFAULT_VOLUME;
    }

    const normalizado = numero > 1 ? numero / 100 : numero;
    return Math.max(0, Math.min(SOUND_EFFECT_MAX_VOLUME, normalizado));
};

const obterSocketsDoUsuario = (usuarioId) => {
    const presenca = obterPresencaUsuario(usuarioId);

    if (!presenca?.sockets?.size) return [];

    return Array.from(presenca.sockets)
        .filter((socketId) => io.sockets.sockets.has(socketId));
};

const obterLimiteAdminEfeitoSonoro = (adminId, agora = Date.now()) => {
    const adminKey = normalizarId(adminId);
    const registrosRecentes = (soundEffectAdminHistory.get(adminKey) || [])
        .filter((timestamp) => agora - timestamp < SOUND_EFFECT_ADMIN_WINDOW_MS);

    soundEffectAdminHistory.set(adminKey, registrosRecentes);

    const restantes = SOUND_EFFECT_ADMIN_MAX_PER_WINDOW - registrosRecentes.length;

    return {
        permitido: restantes > 0,
        restantes: Math.max(restantes, 0),
        retryAfterMs: registrosRecentes.length
            ? Math.max(SOUND_EFFECT_ADMIN_WINDOW_MS - (agora - registrosRecentes[0]), 0)
            : 0,
    };
};

const registrarEnvioAdminEfeitoSonoro = (adminId, agora = Date.now()) => {
    const adminKey = normalizarId(adminId);
    const registrosRecentes = (soundEffectAdminHistory.get(adminKey) || [])
        .filter((timestamp) => agora - timestamp < SOUND_EFFECT_ADMIN_WINDOW_MS);

    registrosRecentes.push(agora);
    soundEffectAdminHistory.set(adminKey, registrosRecentes);
};

const obterCooldownAlvoEfeitoSonoro = (empresaId, usuarioId, agora = Date.now()) => {
    const cooldownKey = `${normalizarId(empresaId)}:${normalizarId(usuarioId)}`;
    const ultimoEnvio = soundEffectTargetCooldowns.get(cooldownKey) || 0;
    const restante = SOUND_EFFECT_TARGET_COOLDOWN_MS - (agora - ultimoEnvio);

    return {
        cooldownKey,
        permitido: restante <= 0,
        retryAfterMs: Math.max(restante, 0),
    };
};

const registrarCooldownAlvoEfeitoSonoro = (cooldownKey, agora = Date.now()) => {
    soundEffectTargetCooldowns.set(cooldownKey, agora);

    for (const [key, timestamp] of soundEffectTargetCooldowns.entries()) {
        if (agora - timestamp > SOUND_EFFECT_TARGET_COOLDOWN_MS * 3) {
            soundEffectTargetCooldowns.delete(key);
        }
    }
};

const formatarEsperaSegundos = (ms) => Math.max(1, Math.ceil(ms / 1000));

const emitirRespostaEfeitoSonoro = (socket, callback, payload) => {
    if (typeof callback === 'function') {
        try {
            callback(payload);
        } catch (err) {
            console.error('[SOUND_EFFECTS] Erro ao responder callback do socket:', err);
        }
    }

    socket.emit('admin:play-prank-sound:result', payload);
};

const registrarLogEfeitoSonoro = async ({
    admin = null,
    alvo = null,
    soundKey = null,
    sound = null,
    volume = null,
    sucesso = false,
    erro = '',
    socketsEnviados = 0,
} = {}) => {
    const horario = new Date().toISOString();
    const soundLabel = sound?.label || soundKey || 'som desconhecido';
    const adminNome = admin?.nome || `usuario ${admin?.id || 'desconhecido'}`;
    const alvoNome = alvo?.nome || `usuario ${alvo?.id || 'desconhecido'}`;

    if (sucesso) {
        console.log(`[SOUND_EFFECTS] ${adminNome} tocou "${soundLabel}" para ${alvoNome} às ${horario}.`);
    } else {
        console.warn(`[SOUND_EFFECTS] Falha: ${adminNome} tentou tocar "${soundLabel}" para ${alvoNome} às ${horario}. Motivo: ${erro || 'erro desconhecido'}.`);
    }

    if (!admin?.id) return;

    try {
        await registrarAuditoria({
            usuario: admin,
            acao: sucesso ? 'TOCAR_EFEITO_SONORO' : 'ERRO_EFEITO_SONORO',
            entidade: 'efeito_sonoro_remoto',
            entidadeId: alvo?.id || null,
            tipo: AUDIT_TYPES.CHAT,
            nivel: sucesso ? AUDIT_LEVELS.NORMAL : AUDIT_LEVELS.IMPORTANT,
            origem: 'CHAT_INTERNO_SOCKET',
            metadata: {
                sucesso,
                erro: erro || null,
                usuario_disparo: {
                    id: admin.id,
                    nome: admin.nome,
                    perfil: admin.perfil,
                },
                funcionario_alvo: alvo ? {
                    id: alvo.id,
                    nome: alvo.nome,
                    email: alvo.email,
                } : null,
                som: sound ? {
                    key: soundKey,
                    label: sound.label,
                    path: sound.path,
                } : { key: soundKey },
                volume,
                sockets_enviados: socketsEnviados,
                criado_em: horario,
            },
        });
    } catch (err) {
        console.error('[SOUND_EFFECTS] Erro ao registrar auditoria do efeito sonoro:', err);
    }
};

const previewMensagem = (tipoMensagem = 'texto', mensagem = '') => {
    if (tipoMensagem === 'imagem') return '[Imagem]';
    if (tipoMensagem === 'audio') return '[Áudio]';
    if (tipoMensagem === 'arquivo') return '[Arquivo]';
    if (tipoMensagem === 'sticker') return 'Figurinha';
    return String(mensagem || '').substring(0, 50);
};

const registrarUsuarioConectado = (socket, usuarioId, empresaId) => {
    const usuarioKey = normalizarId(usuarioId);
    const empresaKey = normalizarId(empresaId);

    let presenca = usuariosConectados.get(usuarioKey);

    if (!presenca) {
        presenca = {
            empresaId: empresaKey,
            sockets: new Set(),
        };
        usuariosConectados.set(usuarioKey, presenca);
    }

    presenca.empresaId = empresaKey;
    presenca.sockets.add(socket.id);
    socket.data.usuarioId = usuarioKey;
    socket.data.empresaId = empresaKey;

    return presenca;
};

const removerUsuarioConectado = (socket) => {
    const usuarioId = socket.data.usuarioId;

    if (!usuarioId) {
        return null;
    }

    const presenca = usuariosConectados.get(usuarioId);

    if (!presenca) {
        return null;
    }

    presenca.sockets.delete(socket.id);

    if (presenca.sockets.size > 0) {
        return {
            usuarioId,
            empresaId: presenca.empresaId,
            ficouOffline: false,
        };
    }

    usuariosConectados.delete(usuarioId);

    return {
        usuarioId,
        empresaId: presenca.empresaId || socket.data.empresaId,
        ficouOffline: true,
    };
};

const autenticarSocketUsuario = async (socket) => {
    const token = socket.auth?.token || socket.handshake?.auth?.token;

    if (!token) {
        throw new Error('Token ausente');
    }

    const decoded = verificarJwtHS256(token, getJwtSecret());
    const [rows] = await db.query(`
        SELECT u.id, u.nome, u.email, u.empresa_id, u.setor_id, s.nome AS setor_nome, u.perfil
        FROM usuarios u
        LEFT JOIN setores s ON s.id = u.setor_id
        WHERE u.id = ? AND u.deletado_em IS NULL
        LIMIT 1
    `, [decoded.id]);

    if (!rows.length) {
        throw new Error('Usuário inválido');
    }

    return { ...decoded, ...rows[0] };
};

const usuarioPodeAcessarRunDiagnostico = async (usuario, runId) => {
    const run = await getDiagnosticRunByRunId(runId, usuario.empresa_id);

    if (!run) return false;
    if (Number(run.requested_by_user_id) === Number(usuario.id)) return true;

    return userHasNetworkDiagnosticPermission(usuario, 'network_diagnostics.history');
};

const resetarUsuariosOnlineAoIniciar = async () => {
    try {
        await db.query(`
            UPDATE usuarios
            SET status = 'offline', ultimo_acesso = NOW()
            WHERE status = 'online' AND deletado_em IS NULL
        `);
    } catch (err) {
        console.error('Erro ao resetar presenças ao iniciar:', err);
    }
};

const emitirStatusMensagensDiretas = (mensagens, status, extras = {}) => {
    const porRemetente = new Map();

    mensagens.forEach((mensagem) => {
        if (!porRemetente.has(mensagem.remetente_id)) {
            porRemetente.set(mensagem.remetente_id, []);
        }

        porRemetente.get(mensagem.remetente_id).push(mensagem);
    });

    porRemetente.forEach((items, remetenteId) => {
        io.to(`user_${remetenteId}`).emit('direct_message_status', {
            status,
            ids: items.map((mensagem) => mensagem.id),
            conversa_id: items[0]?.conversa_direta_id || null,
            ...extras,
        });
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
            if (err?.code !== 'ER_LOCK_DEADLOCK') {
                throw err;
            }

            console.warn('Deadlock ignorado ao compatibilizar leituras_mensagens; tentativa futura manterá a tabela atualizada.');
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

const obterUsuariosNaSala = (sala) => {
    const socketIds = io.sockets.adapter.rooms.get(sala);
    const usuarios = new Set();

    if (!socketIds) return [];

    socketIds.forEach((socketId) => {
        const socketConectado = io.sockets.sockets.get(socketId);
        const usuarioId = Number(socketConectado?.data?.usuarioId);

        if (usuarioId) {
            usuarios.add(usuarioId);
        }
    });

    return Array.from(usuarios);
};

const registrarStatusMensagemGrupo = async ({ mensagemId, usuarioIds, lida = false }) => {
    const mensagemIdNumerico = Number(mensagemId);
    const usuariosUnicos = Array.from(new Set(
        (usuarioIds || []).map((usuarioId) => Number(usuarioId)).filter(Boolean)
    ));

    if (!mensagemIdNumerico || !usuariosUnicos.length) return;

    await garantirTabelaLeiturasMensagens();

    const agora = new Date();
    const valores = usuariosUnicos.map((usuarioId) => [
        mensagemIdNumerico,
        usuarioId,
        agora,
        lida ? agora : null,
    ]);

    await db.query(`
        INSERT INTO leituras_mensagens (mensagem_id, usuario_id, entregue_em, lida_em)
        VALUES ?
        ON DUPLICATE KEY UPDATE
            entregue_em = COALESCE(leituras_mensagens.entregue_em, VALUES(entregue_em)),
            lida_em = COALESCE(leituras_mensagens.lida_em, VALUES(lida_em))
    `, [valores]);
};

const marcarMensagensGrupoDoUsuario = async ({ usuarioId, grupoId = null, lida = false }) => {
    const usuarioIdNumerico = Number(usuarioId);
    const grupoIdNumerico = Number(grupoId);

    if (!usuarioIdNumerico) return;

    await garantirTabelaLeiturasMensagens();

    const filtroGrupo = grupoIdNumerico ? 'AND m.grupo_id = ?' : '';
    const lidaSql = lida ? 'NOW()' : 'NULL';
    const statusJaRegistradoSql = lida ? 'lm.lida_em IS NOT NULL' : 'lm.entregue_em IS NOT NULL';
    const params = [
        usuarioIdNumerico,
        usuarioIdNumerico,
        usuarioIdNumerico,
        usuarioIdNumerico,
    ];

    if (grupoIdNumerico) {
        params.push(grupoIdNumerico);
    }

    await db.query(`
        INSERT INTO leituras_mensagens (mensagem_id, usuario_id, entregue_em, lida_em)
        SELECT m.id, ?, NOW(), ${lidaSql}
        FROM mensagens m
        JOIN grupo_membros gm
          ON gm.grupo_id = m.grupo_id
         AND gm.usuario_id = ?
        WHERE m.grupo_id IS NOT NULL
          AND m.remetente_id != ?
          AND m.deletada_em IS NULL
          AND NOT EXISTS (
              SELECT 1
              FROM leituras_mensagens lm
              WHERE lm.mensagem_id = m.id
                AND lm.usuario_id = ?
                AND ${statusJaRegistradoSql}
          )
          ${filtroGrupo}
        ON DUPLICATE KEY UPDATE
            entregue_em = COALESCE(leituras_mensagens.entregue_em, VALUES(entregue_em)),
            lida_em = COALESCE(leituras_mensagens.lida_em, VALUES(lida_em))
    `, params);

    if (lida && grupoIdNumerico) {
        await marcarLeituraGrupoPorCursor(grupoIdNumerico, usuarioIdNumerico);
    }
};

const marcarMensagensEntreguesDoUsuario = async (usuarioId) => {
    const [mensagens] = await db.query(`
        SELECT m.id, m.remetente_id, m.conversa_direta_id
        FROM mensagens m
        JOIN conversas_diretas cd ON m.conversa_direta_id = cd.id
        WHERE (cd.usuario1_id = ? OR cd.usuario2_id = ?)
          AND m.remetente_id != ?
          AND m.entregue_em IS NULL
          AND m.deletada_em IS NULL
    `, [usuarioId, usuarioId, usuarioId]);

    if (!mensagens.length) return;

    const ids = mensagens.map((mensagem) => mensagem.id);

    await db.query(`
        UPDATE mensagens
        SET entregue_em = COALESCE(entregue_em, NOW())
        WHERE id IN (?)
    `, [ids]);

    emitirStatusMensagensDiretas(mensagens, 'entregue', {
        entregue_em: new Date(),
    });
};

const entrarSalasDoUsuario = async (socket, { usuarioId, empresaId, motivo = 'sync' }) => {
    const usuarioKey = normalizarId(usuarioId);
    const empresaKey = normalizarId(empresaId);

    if (!usuarioKey || !empresaKey) {
        throw new Error('Dados do usuário ausentes para entrar nas salas');
    }

    socket.join(`user_${usuarioKey}`);
    socket.join(`empresa_${empresaKey}`);
    socket.join(SALA_CONTRATACOES);
    try {
        const [pessoa] = await db.query('SELECT id, perfil, setor_id, empresa_id FROM usuarios WHERE id = ? AND deletado_em IS NULL', [usuarioKey]);
        if (pessoa[0] && await usuarioTemModulo(pessoa[0], 'chamados')) socket.join(SALA_AVALIACOES);
    } catch (e) { console.error('Avaliações: não foi possível entrar na sala:', e?.message); }
    socket.emit('contratacoes:resumo', obterResumoContratacoes());

    const [conversas] = await db.query(
        'SELECT id FROM conversas_diretas WHERE usuario1_id = ? OR usuario2_id = ?',
        [usuarioKey, usuarioKey]
    );

    conversas.forEach((conversa) => {
        socket.join(`conversa_${conversa.id}`);
    });

    const [grupos] = await db.query(`
        SELECT gm.grupo_id
        FROM grupo_membros gm
        JOIN grupos g ON gm.grupo_id = g.id
        WHERE gm.usuario_id = ?
          AND g.empresa_id = ?
          AND g.deletado_em IS NULL
    `, [usuarioKey, empresaKey]);

    grupos.forEach((grupo) => {
        socket.join(`grupo_${grupo.grupo_id}`);
    });

    console.log(
        `[SOCKET] Usuário ${usuarioKey} entrou em ${conversas.length} conversas e ${grupos.length} grupos (${motivo})`
    );

    return {
        conversas: conversas.length,
        grupos: grupos.length,
    };
};

// Identidade efetiva do socket. Autenticado: vem do JWT (payload do cliente é ignorado).
// Sem identidade só é possível em SOCKET_AUTH_MODE=log/off (clientes antigos): aí cai no comportamento legado.
const identidadeEfetiva = (socket, data = {}) => {
    const ident = identidadeDoSocket(socket);
    if (ident) return ident;
    if (SOCKET_AUTH_MODE === 'enforce') return null;

    const usuarioId = normalizarIdSocket(socket.data.usuarioId ?? data?.remetente_id ?? data?.usuario_id);
    if (!usuarioId) return null;
    return {
        usuarioId,
        empresaId: normalizarIdSocket(socket.data.empresaId ?? data?.empresa_id),
        user: { id: usuarioId, nome: data?.remetente_nome ?? data?.usuario_nome ?? null, avatar: data?.remetente_avatar ?? null, perfil: null, setor_id: null },
        legado: true,
    };
};

const recusarSocket = (socket, mensagem = 'Operação não permitida') => {
    socket.emit('socket_error', { error: mensagem });
};

io.on('connection', (socket) => {
    console.log(`[SOCKET] Novo cliente conectado: ${socket.id}`);

    // ========================================
    // EVENTOS DE CONEXÃO/DESCONEXÃO
    // ========================================

    // Usuário conecta ao chat
    socket.on('user_connect', async (data) => {
        try {
            const { usuario_id, empresa_id } = data || {};
            const ident = socket.data.user
                ? identidadeDoSocket(socket)
                : (SOCKET_AUTH_MODE === 'enforce' ? null : {
                    usuarioId: normalizarIdSocket(usuario_id),
                    empresaId: normalizarIdSocket(empresa_id),
                });

            if (!ident?.usuarioId || !ident?.empresaId) {
                socket.emit('socket_error', { error: 'Dados do usuário ausentes' });
                return;
            }

            // Identidade vem do token; usuario_id/empresa_id do payload são ignorados (só registramos a divergência).
            if (socket.data.user && usuario_id && normalizarIdSocket(usuario_id) !== ident.usuarioId) {
                console.warn(`[SOCKET-AUTH] user_connect com usuario_id divergente do token: token=${ident.usuarioId} payload=${usuario_id} socket=${socket.id}`);
            }

            const usuarioId = normalizarId(ident.usuarioId);
            const empresaId = normalizarId(ident.empresaId);
            const jaEstavaOnline = usuarioEstaConectado(usuarioId);

            // Salvar conexão do usuário
            registrarUsuarioConectado(socket, usuarioId, empresaId);

            await entrarSalasDoUsuario(socket, {
                usuarioId,
                empresaId,
                motivo: 'connect',
            });

            await marcarMensagensEntreguesDoUsuario(usuarioId);
            marcarMensagensGrupoDoUsuario({ usuarioId }).catch((err) => {
                console.error(`[SOCKET] Erro ao marcar entregas de grupo do usuário ${usuarioId}:`, err);
            });

            // Atualizar status no banco
            await db.query(
                'UPDATE usuarios SET status = ? WHERE id = ? AND deletado_em IS NULL',
                ['online', usuarioId]
            );

            // Notificar que usuário está online
            if (!jaEstavaOnline) {
                io.to(`empresa_${empresaId}`).emit('user_status_changed', {
                    usuario_id: Number(usuarioId),
                    status: 'online',
                    ultimo_acesso: null,
                });
            }

            console.log(`[SOCKET] Usuário ${usuarioId} conectado`);
        } catch (err) {
            console.error('Erro ao conectar usuário no socket:', err);
            socket.emit('socket_error', { error: 'Erro ao conectar ao chat' });
        }
    });

    // Aplicativo Acessa Workspace aberto: entra na lista "quem está usando o app" do painel admin.
    // A identidade vem do token do socket; do cliente só aceitamos o número da versão.
    socket.on('workspace_presence', async (data) => {
        try {
            const usuario = await autenticarSocketUsuario(socket);
            const dispositivo = dispositivoValido(data?.dispositivo);
            registrarWorkspace(socket.id, {
                usuarioId: usuario.id,
                empresaId: usuario.empresa_id,
                versao: data?.versao,
                dispositivo,
            });
            // Guarda o computador (quem, de onde, qual versão) para o painel de versões; uma falha aqui não derruba a presença.
            registrarVisto({
                empresaId: usuario.empresa_id,
                usuarioId: usuario.id,
                dispositivo,
                computador: data?.computador,
                ip: socket.handshake?.headers?.['x-forwarded-for']?.split(',')[0] || socket.handshake?.address,
                versao: data?.versao,
            }).catch((e) => console.error('[SOCKET] Não registrou o computador:', e.message));
            socket.data.workspaceEmpresaId = usuario.empresa_id;
            io.to(`empresa_${usuario.empresa_id}`).emit('workspace_presence_changed');
        } catch (err) {
            console.error('[SOCKET] Presença do Workspace recusada:', err.message);
        }
    });

    // Widget de chat da Agenda Técnicos: chega pelo túnel do servidor da agenda, com o cookie de
    // sessão assinado por este chat. O usuário vem da sessão validada, nunca de dados do cliente.
    socket.on('agenda_widget_connect', async () => {
        try {
            const sessao = validarSessaoAgenda(lerCookieAgenda(socket.handshake?.headers?.cookie));
            if (!sessao) {
                socket.emit('agenda_widget_error', { error: 'Sessão do chat expirada. Entre no Chat Interno novamente.' });
                return;
            }

            const [rows] = await db.query(`
                SELECT id, nome, avatar, empresa_id
                FROM usuarios
                WHERE id = ? AND deletado_em IS NULL
                LIMIT 1
            `, [sessao.id]);
            if (!rows.length) {
                socket.emit('agenda_widget_error', { error: 'Usuário do chat não encontrado.' });
                return;
            }

            const usuario = rows[0];
            const jaEstavaOnline = usuarioEstaConectado(usuario.id);
            registrarUsuarioConectado(socket, usuario.id, usuario.empresa_id);
            await entrarSalasDoUsuario(socket, {
                usuarioId: usuario.id,
                empresaId: usuario.empresa_id,
                motivo: 'agenda-widget',
            });
            await marcarMensagensEntreguesDoUsuario(usuario.id);

            await db.query(
                'UPDATE usuarios SET status = ? WHERE id = ? AND deletado_em IS NULL',
                ['online', usuario.id]
            );
            if (!jaEstavaOnline) {
                io.to(`empresa_${usuario.empresa_id}`).emit('user_status_changed', {
                    usuario_id: Number(usuario.id),
                    status: 'online',
                    ultimo_acesso: null,
                });
            }

            socket.emit('agenda_widget_ready', {
                usuario: { id: usuario.id, nome: usuario.nome, avatar: usuario.avatar, empresa_id: usuario.empresa_id },
            });
            console.log(`[SOCKET] Usuário ${usuario.id} conectado pelo widget da agenda`);
        } catch (err) {
            console.error('Erro ao conectar widget da agenda:', err);
            socket.emit('agenda_widget_error', { error: 'Erro ao conectar ao chat' });
        }
    });

    socket.on('join_user_groups', async (data = {}) => {
        try {
            const ident = identidadeDoSocket(socket) || (SOCKET_AUTH_MODE === 'enforce' ? null : {
                usuarioId: normalizarIdSocket(socket.data.usuarioId || data.usuario_id),
                empresaId: normalizarIdSocket(socket.data.empresaId || data.empresa_id),
            });
            const usuarioId = ident?.usuarioId;
            const empresaId = ident?.empresaId;

            if (!usuarioId || !empresaId) {
                socket.emit('socket_error', { error: 'Dados do usuário ausentes para sincronizar grupos' });
                return;
            }

            if (data.usuario_id && normalizarId(data.usuario_id) !== normalizarId(usuarioId)) {
                console.warn(
                    `[SOCKET] Tentativa de sincronizar grupos de outro usuário: socket=${usuarioId}, payload=${data.usuario_id}`
                );
                socket.emit('socket_error', { error: 'Usuário inválido para sincronizar grupos' });
                return;
            }

            const resultado = await entrarSalasDoUsuario(socket, {
                usuarioId,
                empresaId,
                motivo: 'resync',
            });

            socket.emit('user_groups_joined', resultado);
        } catch (err) {
            console.error('Erro ao sincronizar salas do usuário:', err);
            socket.emit('socket_error', { error: 'Erro ao sincronizar grupos do chat' });
        }
    });

    socket.on('network-diagnostic:join', async (data = {}) => {
        try {
            const runId = String(data.runId || data.run_id || '').trim();

            if (!NETWORK_DIAGNOSTIC_RUN_ID_REGEX.test(runId)) {
                socket.emit('network-diagnostic:error', { error: 'Execução inválida.' });
                return;
            }

            const usuario = await autenticarSocketUsuario(socket);
            const autorizado = await usuarioPodeAcessarRunDiagnostico(usuario, runId);

            if (!autorizado) {
                socket.emit('network-diagnostic:error', {
                    runId,
                    error: 'Você não possui permissão para visualizar este diagnóstico.',
                });
                return;
            }

            socket.join(`network-diagnostic:${runId}`);
            socket.emit('network-diagnostic:joined', { runId });
        } catch (err) {
            console.error('Erro ao entrar na sala de diagnóstico:', err);
            socket.emit('network-diagnostic:error', { error: 'Não foi possível acompanhar o diagnóstico.' });
        }
    });

    socket.on('network-diagnostic:leave', (data = {}) => {
        const runId = String(data.runId || data.run_id || '').trim();

        if (!NETWORK_DIAGNOSTIC_RUN_ID_REGEX.test(runId)) return;

        socket.leave(`network-diagnostic:${runId}`);
    });

    socket.on('admin:play-prank-sound', async (data = {}, callback) => {
        let admin = null;
        let alvo = null;
        let sound = null;
        let soundKey = null;
        let volume = SOUND_EFFECT_DEFAULT_VOLUME;
        let volumePercent = VOLUME_PADRAO_PERCENT;

        const responder = (payload) => emitirRespostaEfeitoSonoro(socket, callback, payload);

        try {
            admin = await autenticarSocketUsuario(socket);

            const permissaoSom = await obterPermissaoEfeitosSonoros(admin);

            if (!(permissaoSom.can_use || permissaoSom.can_manage)) {
                await registrarLogEfeitoSonoro({
                    admin,
                    soundKey: normalizarSoundKey(data.sound_key || data.sound),
                    sucesso: false,
                    erro: 'Acesso negado',
                });

                responder({
                    ok: false,
                    error: 'Acesso negado. Seu usuário não tem permissão para disparar efeitos sonoros.',
                });
                return;
            }

            soundKey = normalizarSoundKey(data.sound_key || data.sound);
            sound = getAllowedSoundEffect(soundKey);
            // O volume pedido nunca passa do limite de quem dispara (70% por padrão; o dono pode mais, até 200%).
            volumePercent = resolverVolumePercent(data, permissaoSom.max_volume_percent);
            volume = volumePercent / 100;

            if (!sound) {
                await registrarLogEfeitoSonoro({
                    admin,
                    soundKey,
                    volume,
                    sucesso: false,
                    erro: 'Som não permitido',
                });

                responder({
                    ok: false,
                    error: 'Som não permitido.',
                });
                return;
            }

            const targetUserId = Number(data.target_user_id || data.usuario_id || data.user_id);

            if (!Number.isInteger(targetUserId) || targetUserId <= 0) {
                await registrarLogEfeitoSonoro({
                    admin,
                    soundKey,
                    sound,
                    volume,
                    sucesso: false,
                    erro: 'Funcionário alvo inválido',
                });

                responder({
                    ok: false,
                    error: 'Funcionário inválido.',
                });
                return;
            }

            alvo = await buscarUsuarioAlvoEfeitoSonoro(admin, targetUserId);

            if (!alvo) {
                const grupoAlvo = obterNomeGrupoAlvoEfeitosSonoros();

                await registrarLogEfeitoSonoro({
                    admin,
                    soundKey,
                    sound,
                    volume,
                    sucesso: false,
                    erro: `Funcionário alvo não encontrado no grupo ${grupoAlvo}`,
                });

                responder({
                    ok: false,
                    error: `Só é possível enviar áudio para usuários do grupo ${grupoAlvo}.`,
                });
                return;
            }

            const socketIdsAlvo = obterSocketsDoUsuario(targetUserId);

            if (!socketIdsAlvo.length) {
                await registrarLogEfeitoSonoro({
                    admin,
                    alvo,
                    soundKey,
                    sound,
                    volume,
                    sucesso: false,
                    erro: 'Funcionário offline',
                });

                responder({
                    ok: false,
                    error: 'Funcionário não está conectado ao Chat Interno.',
                    target_user: {
                        id: alvo.id,
                        nome: alvo.nome,
                        status: 'offline',
                    },
                });
                return;
            }

            const agora = Date.now();
            // Quem tem "sem limite de tempo" (o dono, por padrão) dispara sem as esperas abaixo.
            const semLimiteTempo = Boolean(permissaoSom.no_time_limit);
            const limiteAdmin = semLimiteTempo ? { permitido: true } : obterLimiteAdminEfeitoSonoro(admin.id, agora);

            if (!limiteAdmin.permitido) {
                const segundos = formatarEsperaSegundos(limiteAdmin.retryAfterMs);

                await registrarLogEfeitoSonoro({
                    admin,
                    alvo,
                    soundKey,
                    sound,
                    volume,
                    sucesso: false,
                    erro: `Limite por usuário atingido (${segundos}s)`,
                });

                responder({
                    ok: false,
                    error: `Limite atingido. Aguarde ${segundos}s para enviar outro efeito.`,
                    retry_after_seconds: segundos,
                });
                return;
            }

            const cooldownAlvo = semLimiteTempo ? { permitido: true } : obterCooldownAlvoEfeitoSonoro(admin.empresa_id, targetUserId, agora);

            if (!cooldownAlvo.permitido) {
                const segundos = formatarEsperaSegundos(cooldownAlvo.retryAfterMs);

                await registrarLogEfeitoSonoro({
                    admin,
                    alvo,
                    soundKey,
                    sound,
                    volume,
                    sucesso: false,
                    erro: `Cooldown do funcionário alvo ativo (${segundos}s)`,
                });

                responder({
                    ok: false,
                    error: `Aguarde ${segundos}s antes de tocar outro som para este funcionário.`,
                    retry_after_seconds: segundos,
                });
                return;
            }

            if (!semLimiteTempo) {
                registrarEnvioAdminEfeitoSonoro(admin.id, agora);
                registrarCooldownAlvoEfeitoSonoro(cooldownAlvo.cooldownKey, agora);
            }

            const payload = {
                sound: sound.path,
                sound_key: soundKey,
                label: sound.label,
                // `volume` (fração até 1) continua valendo para os apps antigos; `volume_percent` pode passar de 100.
                volume: Math.min(1, volume),
                volume_percent: volumePercent,
                requested_by: admin.nome,
                created_at: new Date().toISOString(),
            };

            socketIdsAlvo.forEach((socketId) => {
                io.to(socketId).emit('play-prank-sound', payload);
            });

            await registrarLogEfeitoSonoro({
                admin,
                alvo,
                soundKey,
                sound,
                volume,
                sucesso: true,
                socketsEnviados: socketIdsAlvo.length,
            });

            responder({
                ok: true,
                message: `Som "${sound.label}" enviado para ${alvo.nome}.`,
                target_user: {
                    id: alvo.id,
                    nome: alvo.nome,
                    status: 'online',
                },
                sound: {
                    key: soundKey,
                    label: sound.label,
                },
                sent_sockets: socketIdsAlvo.length,
            });
        } catch (err) {
            console.error('[SOUND_EFFECTS] Erro ao processar efeito sonoro remoto:', err);

            await registrarLogEfeitoSonoro({
                admin,
                alvo,
                soundKey,
                sound,
                volume,
                sucesso: false,
                erro: err?.message || 'Erro interno',
            });

            responder({
                ok: false,
                error: 'Erro ao disparar efeito sonoro.',
            });
        }
    });

    // Usuário desconecta
    socket.on('disconnect', async () => {
        const presenca = removerUsuarioConectado(socket);
        const saiu = removerWorkspace(socket.id);
        if (saiu) {
            io.to(`empresa_${socket.data.workspaceEmpresaId}`).emit('workspace_presence_changed');
            if (saiu.dispositivo) {
                marcarSaida({ empresaId: saiu.empresaId, usuarioId: saiu.usuarioId, dispositivo: saiu.dispositivo })
                    .catch((e) => console.error('[SOCKET] Não carimbou a saída do computador:', e.message));
            }
        }

        if (presenca?.ficouOffline) {
            servicoSituacao.marcarLigacao(presenca.empresaId, presenca.usuarioId, false).then((ef) => io.to(`empresa_${presenca.empresaId}`).emit('situacao_changed', { usuario_id: Number(presenca.usuarioId), situacao: ef.situacao, ate: ef.ate })).catch(() => {});
            try {
                const ultimoAcesso = new Date();

                // Atualizar status no banco
                await db.query(
                    'UPDATE usuarios SET status = ?, ultimo_acesso = NOW() WHERE id = ? AND deletado_em IS NULL',
                    ['offline', presenca.usuarioId]
                );

                // Notificar desconexão
                io.to(`empresa_${presenca.empresaId}`).emit('user_status_changed', {
                    usuario_id: Number(presenca.usuarioId),
                    status: 'offline',
                    ultimo_acesso: ultimoAcesso.toISOString(),
                });

                console.log(`[SOCKET] Usuário ${presenca.usuarioId} desconectado`);
            } catch (err) {
                console.error('Erro ao desconectar usuário no socket:', err);
            }
        }
    });

    // ========================================
    // EVENTOS DE MENSAGENS DIRETAS
    // ========================================

    // Usuário entra em conversa direta
    socket.on('join_direct_chat', async (data) => {
        try {
            const ident = identidadeEfetiva(socket, data);
            const conversa = ident && await autorizador.participanteDaConversa(ident.usuarioId, data?.conversa_id);
            if (!conversa) {
                console.warn(`[SOCKET-AUTH] join_direct_chat negado: usuario=${ident?.usuarioId || '-'} conversa=${data?.conversa_id}`);
                return recusarSocket(socket, 'Você não tem acesso a esta conversa');
            }
            socket.join(`conversa_${conversa.id}`);
        } catch (err) {
            console.error('Erro ao entrar na conversa direta:', err);
        }
    });

    // Quem pode ver a rede entra na sala que recebe os avisos de incidente novo (a permissão é checada aqui, no servidor).
    socket.on('olt_watch', async () => {
        try {
            const usuario = await autenticarSocketUsuario(socket);
            if (await usuarioPodeVerRedeOlt(usuario)) socket.join('olt_watchers');
        } catch { /* sem permissão ou sessão inválida: não entra */ }
    });

    socket.on('leave_direct_chat', (data) => {
        const { conversa_id } = data || {};
        if (!conversa_id) return;
        socket.leave(`conversa_${conversa_id}`);
        console.log(`[SOCKET] Usuário saiu da conversa ${conversa_id}`);
    });

    // Enviar mensagem direta
    socket.on('send_direct_message', async (data) => {
        try {
            const ident = identidadeEfetiva(socket, data);
            const conversa = ident && await autorizador.participanteDaConversa(ident.usuarioId, data?.conversa_id);
            if (!conversa) {
                console.warn(`[SOCKET-AUTH] send_direct_message negado: usuario=${ident?.usuarioId || '-'} conversa=${data?.conversa_id}`);
                return recusarSocket(socket, 'Você não tem acesso a esta conversa');
            }
            if (data.id && !(await autorizador.mensagemPertenceAoRemetente({
                mensagemId: data.id,
                remetenteId: ident.usuarioId,
                conversaId: conversa.id,
            }))) {
                console.warn(`[SOCKET-AUTH] send_direct_message com mensagem que não é do remetente: usuario=${ident.usuarioId} msg=${data.id}`);
                return recusarSocket(socket, 'Mensagem inválida');
            }

            // Remetente, destinatário e conversa são sempre derivados do socket/banco, nunca do payload.
            const remetente_id = ident.usuarioId;
            const usuario_id = conversa.outroId;
            const conversa_id = conversa.id;
            const remetente_nome = ident.user.nome ?? data.remetente_nome;
            const remetente_avatar = ident.legado ? data.remetente_avatar : (ident.user.avatar ?? data.remetente_avatar);
            const {
                mensagem,
                tipo_mensagem = 'texto',
                anexo_nome = null,
                anexo_mime = null,
                sticker_id = null,
                mencoes = [],
                resposta_mensagem_id = null,
                resposta_remetente_id = null,
                resposta_remetente_nome = null,
                resposta_tipo_mensagem = null,
                resposta_mensagem = null,
                resposta_anexo_nome = null,
                resposta_sticker_id = null,
                resposta_previa = null,
                id = null,
                criada_em = null,
            } = data;

            const mensagemId = id || Date.now();
            const criadaEm = criada_em || new Date();
            const entregueEm = usuarioEstaConectado(usuario_id) ? new Date() : null;

            if (entregueEm && id) {
                await db.query(`
                    UPDATE mensagens
                    SET entregue_em = COALESCE(entregue_em, NOW())
                    WHERE id = ?
                `, [id]);
            }

            // Emitir para ambos os usuários
            io.to(`conversa_${conversa_id}`).emit('receive_direct_message', {
                id: mensagemId,
                remetente_id,
                usuario_id,
                conversa_id,
                remetente_nome,
                remetente_avatar,
                mensagem,
                tipo_mensagem,
                anexo_nome,
                anexo_mime,
                sticker_id,
                resposta_mensagem_id,
                resposta_remetente_id,
                resposta_remetente_nome,
                resposta_tipo_mensagem,
                resposta_mensagem,
                resposta_anexo_nome,
                resposta_sticker_id,
                resposta_previa,
                lida: false,
                entregue_em: entregueEm,
                lida_em: null,
                reacoes: [],
                criada_em: criadaEm
            });

            // Notificar também na sala do usuário se ele não estiver na conversa
            io.to(`user_${usuario_id}`).emit('new_direct_message_notification', {
                id: mensagemId,
                remetente_id,
                usuario_id,
                conversa_id,
                remetente_nome,
                remetente_avatar,
                tipo_mensagem,
                anexo_nome,
                anexo_mime,
                sticker_id,
                resposta_mensagem_id,
                resposta_remetente_id,
                resposta_remetente_nome,
                resposta_tipo_mensagem,
                resposta_mensagem,
                resposta_anexo_nome,
                resposta_sticker_id,
                resposta_previa,
                criada_em: criadaEm,
                preview: previewMensagem(tipo_mensagem, mensagem)
            });

            if (entregueEm) {
                io.to(`user_${remetente_id}`).emit('direct_message_status', {
                    status: 'entregue',
                    id: mensagemId,
                    ids: [mensagemId],
                    conversa_id,
                    entregue_em: entregueEm,
                });
            }

            console.log(`[SOCKET] Mensagem direta de ${remetente_id} para ${usuario_id}`);
        } catch (err) {
            console.error('Erro ao enviar mensagem direta:', err);
        }
    });

    // Marcar conversa como lida
    socket.on('mark_conversa_read', async (data) => {
        try {
            const ident = identidadeEfetiva(socket, data);
            const conversa = ident && await autorizador.participanteDaConversa(ident.usuarioId, data?.conversa_id);
            if (!conversa) {
                console.warn(`[SOCKET-AUTH] mark_conversa_read negado: usuario=${ident?.usuarioId || '-'} conversa=${data?.conversa_id}`);
                return;
            }
            const conversa_id = conversa.id;
            const usuario_id = ident.usuarioId;
            const [mensagensParaMarcar] = await db.query(`
                SELECT id, remetente_id, conversa_direta_id
                FROM mensagens
                WHERE conversa_direta_id = ?
                  AND remetente_id != ?
                  AND lida = FALSE
                  AND deletada_em IS NULL
            `, [conversa_id, usuario_id]);

            await db.query(`
                UPDATE mensagens 
                SET
                    lida = TRUE,
                    lida_em = COALESCE(lida_em, NOW()),
                    entregue_em = COALESCE(entregue_em, NOW())
                WHERE conversa_direta_id = ? AND remetente_id != ? AND lida = FALSE
            `, [conversa_id, usuario_id]);

            if (mensagensParaMarcar.length) {
                emitirStatusMensagensDiretas(mensagensParaMarcar, 'lida', {
                    entregue_em: new Date(),
                    lida_em: new Date(),
                });
            }
        } catch (err) {
            console.error('Erro ao marcar como lido:', err);
        }
    });

    socket.on('mark_group_read', async (data) => {
        const { grupo_id } = data || {};
        const ident = identidadeEfetiva(socket, data);
        const usuario_id = ident?.usuarioId;

        try {
            if (!usuario_id || !(await autorizador.membroDoGrupo(usuario_id, grupo_id))) return;
            await marcarMensagensGrupoDoUsuario({
                usuarioId: usuario_id,
                grupoId: grupo_id,
                lida: true,
            });
        } catch (err) {
            console.error('Erro ao marcar grupo como lido:', err);
        }
    });

    socket.on('message_deleted', async (data) => {
        try {
            const {
                id,
                conversa_id = null,
                grupo_id = null,
                escopo = 'todos',
            } = data || {};

            if (!id || escopo !== 'todos') return;

            const ident = identidadeEfetiva(socket, data);
            if (!ident) return;
            const usuario = { ...ident.user, id: ident.usuarioId };

            if (conversa_id) {
                const conversa = await autorizador.participanteDaConversa(ident.usuarioId, conversa_id);
                if (conversa && await autorizador.podeAnunciarExclusao({ usuario, mensagemId: id, conversaId: conversa.id })) {
                    io.to(`conversa_${conversa.id}`).emit('message_deleted', {
                        id,
                        conversa_id: conversa.id,
                        escopo,
                    });
                } else {
                    console.warn(`[SOCKET-AUTH] message_deleted negado: usuario=${ident.usuarioId} conversa=${conversa_id} msg=${id}`);
                }
            }

            if (grupo_id) {
                if (await autorizador.membroDoGrupo(ident.usuarioId, grupo_id)
                    && await autorizador.podeAnunciarExclusao({ usuario, mensagemId: id, grupoId: grupo_id })) {
                    io.to(`grupo_${grupo_id}`).emit('message_deleted', {
                        id,
                        grupo_id,
                        escopo,
                    });
                } else {
                    console.warn(`[SOCKET-AUTH] message_deleted negado: usuario=${ident.usuarioId} grupo=${grupo_id} msg=${id}`);
                }
            }
        } catch (err) {
            console.error('Erro ao propagar exclusão de mensagem:', err);
        }
    });

    // ========================================
    // EVENTOS DE GRUPOS
    // ========================================

    // Usuário entra em grupo
    socket.on('join_group', async (data) => {
        const { grupo_id } = data || {};
        const usuarioId = identidadeEfetiva(socket, data)?.usuarioId;

        if (!grupo_id || !usuarioId) {
            socket.emit('socket_error', { error: 'Não foi possível entrar no grupo' });
            return;
        }

        try {
            const [membro] = await db.query(`
                SELECT gm.grupo_id
                FROM grupo_membros gm
                JOIN grupos g ON g.id = gm.grupo_id
                WHERE gm.grupo_id = ?
                  AND gm.usuario_id = ?
                  AND g.deletado_em IS NULL
                LIMIT 1
            `, [grupo_id, usuarioId]);

            if (!membro.length) {
                console.warn(`[SOCKET] Permissão negada ao entrar no grupo ${grupo_id} para usuário ${usuarioId}`);
                socket.emit('socket_error', { error: 'Você não tem acesso a este grupo' });
                return;
            }

            socket.join(`grupo_${grupo_id}`);

            await marcarMensagensGrupoDoUsuario({
                usuarioId,
                grupoId: grupo_id,
                lida: false,
            });

            console.log(`[SOCKET] Usuário ${usuarioId} entrou no grupo ${grupo_id}`);
        } catch (err) {
            console.error(`[SOCKET] Erro ao entrar no grupo ${grupo_id}:`, err);
            socket.emit('socket_error', { error: 'Erro ao entrar no grupo' });
        }
    });

    socket.on('leave_group', (data) => {
        const { grupo_id } = data || {};
        if (!grupo_id) return;
        socket.leave(`grupo_${grupo_id}`);
        console.log(`[SOCKET] Usuário saiu do grupo ${grupo_id}`);
    });

    // Enviar mensagem de grupo
    socket.on('send_group_message', async (data) => {
        try {
            const ident = identidadeEfetiva(socket, data);
            if (!ident || !(await autorizador.membroDoGrupo(ident.usuarioId, data?.grupo_id))) {
                console.warn(`[SOCKET-AUTH] send_group_message negado: usuario=${ident?.usuarioId || '-'} grupo=${data?.grupo_id}`);
                return recusarSocket(socket, 'Você não tem acesso a este grupo');
            }
            if (data.id && !(await autorizador.mensagemPertenceAoRemetente({
                mensagemId: data.id,
                remetenteId: ident.usuarioId,
                grupoId: data.grupo_id,
            }))) {
                console.warn(`[SOCKET-AUTH] send_group_message com mensagem que não é do remetente: usuario=${ident.usuarioId} msg=${data.id}`);
                return recusarSocket(socket, 'Mensagem inválida');
            }

            // Remetente sempre derivado do socket.
            const remetente_id = ident.usuarioId;
            const remetente_nome = ident.user.nome ?? data.remetente_nome;
            const remetente_avatar = ident.legado ? data.remetente_avatar : (ident.user.avatar ?? data.remetente_avatar);
            const {
                grupo_id,
                grupo_nome = null,
                mensagem,
                tipo_mensagem = 'texto',
                anexo_nome = null,
                anexo_mime = null,
                sticker_id = null,
                mencoes = [],
                resposta_mensagem_id = null,
                resposta_remetente_id = null,
                resposta_remetente_nome = null,
                resposta_tipo_mensagem = null,
                resposta_mensagem = null,
                resposta_anexo_nome = null,
                resposta_sticker_id = null,
                resposta_previa = null,
                id = null,
                criada_em = null,
            } = data;

            const mensagemId = id || Date.now();
            const criadaEm = criada_em || new Date();
            const mensagemIdPersistida = Number(id);
            let grupoNome = grupo_nome || null;
            let totalEntregas = 1;
            let totalLeituras = 1;

            if (!grupoNome && grupo_id) {
                const [grupos] = await db.query(
                    'SELECT nome FROM grupos WHERE id = ? AND deletado_em IS NULL LIMIT 1',
                    [grupo_id]
                );

                grupoNome = grupos[0]?.nome || null;
            }

            if (mensagemIdPersistida) {
                try {
                    await registrarStatusMensagemGrupo({
                        mensagemId: mensagemIdPersistida,
                        usuarioIds: [remetente_id],
                        lida: true,
                    });

                    const usuariosNaSala = obterUsuariosNaSala(`grupo_${grupo_id}`);
                    await registrarStatusMensagemGrupo({
                        mensagemId: mensagemIdPersistida,
                        usuarioIds: usuariosNaSala,
                        lida: false,
                    });

                    totalEntregas = Math.max(usuariosNaSala.length, 1);
                } catch (err) {
                    console.error('Erro ao registrar entrega da mensagem de grupo:', err);
                }
            }

            io.to(`grupo_${grupo_id}`).emit('receive_group_message', {
                id: mensagemId,
                remetente_id,
                grupo_id,
                grupo_nome: grupoNome,
                remetente_nome,
                remetente_avatar,
                mensagem,
                tipo_mensagem,
                anexo_nome,
                anexo_mime,
                sticker_id,
                resposta_mensagem_id,
                resposta_remetente_id,
                resposta_remetente_nome,
                resposta_tipo_mensagem,
                resposta_mensagem,
                resposta_anexo_nome,
                resposta_sticker_id,
                resposta_previa,
                mencoes,
                lida: false,
                total_entregas: totalEntregas,
                total_leituras: totalLeituras,
                reacoes: [],
                criada_em: criadaEm
            });

            console.log(`[SOCKET] Mensagem no grupo ${grupo_id} de ${remetente_id}`);
        } catch (err) {
            console.error('Erro ao enviar mensagem de grupo:', err);
        }
    });

    // ========================================
    // EVENTOS DE STATUS
    // ========================================

    // Usuário está digitando (direto)
    // Os eventos de digitação só valem para salas em que este socket já entrou (entrada validada no servidor);
    // quem digita é sempre o usuário do socket.
    socket.on('typing_direct', (data) => {
        const { conversa_id } = data || {};
        const ident = identidadeEfetiva(socket, data);
        if (!ident || !socket.rooms.has(`conversa_${conversa_id}`)) return;
        socket.to(`conversa_${conversa_id}`).emit('user_typing_direct', {
            usuario_id: ident.usuarioId,
            usuario_nome: ident.user.nome ?? data.usuario_nome
        });
    });

    // Parou de digitar (direto)
    socket.on('stop_typing_direct', (data) => {
        const { conversa_id } = data || {};
        const ident = identidadeEfetiva(socket, data);
        if (!ident || !socket.rooms.has(`conversa_${conversa_id}`)) return;
        socket.to(`conversa_${conversa_id}`).emit('user_stop_typing_direct', {
            usuario_id: ident.usuarioId
        });
    });

    // Usuário está digitando (grupo)
    socket.on('typing_group', (data) => {
        const { grupo_id } = data || {};
        const ident = identidadeEfetiva(socket, data);
        if (!ident || !socket.rooms.has(`grupo_${grupo_id}`)) return;
        socket.to(`grupo_${grupo_id}`).emit('user_typing_group', {
            grupo_id,
            usuario_id: ident.usuarioId,
            usuario_nome: ident.user.nome ?? data.usuario_nome
        });
    });

    // Parou de digitar (grupo)
    socket.on('stop_typing_group', (data) => {
        const { grupo_id } = data || {};
        const ident = identidadeEfetiva(socket, data);
        if (!ident || !socket.rooms.has(`grupo_${grupo_id}`)) return;
        socket.to(`grupo_${grupo_id}`).emit('user_stop_typing_group', {
            grupo_id,
            usuario_id: ident.usuarioId
        });
    });

    // ========================================
    // EVENTOS HERDADOS (compatibilidade)
    // ========================================

    // O argumento enviado pelo cliente é ignorado: só se entra na empresa/setor do próprio usuário autenticado.
    socket.on('join_empresa', () => {
        const ident = identidadeDoSocket(socket);
        if (!ident?.empresaId) return;
        socket.join(`empresa_${ident.empresaId}`);
    });

    socket.on('join_setor', () => {
        const ident = identidadeDoSocket(socket);
        const setorId = normalizarIdSocket(ident?.user?.setor_id);
        if (!ident?.empresaId || !setorId) return;
        socket.join(`setor_${setorId}`);
    });

    socket.on('setor_message', async (data) => {
        try {
            const ident = identidadeDoSocket(socket);
            const setorId = normalizarIdSocket(ident?.user?.setor_id);
            if (!ident || !setorId) return;
            io.to(`setor_${setorId}`).emit('receive_setor', {
                ...data,
                setor_id: setorId,
                usuario_id: ident.usuarioId,
                nome: ident.user.nome
            });
        } catch (err) {
            console.error('Erro ao enviar mensagem de setor:', err);
        }
    });

    socket.on('empresa_message', async (data) => {
        try {
            const ident = identidadeDoSocket(socket);
            if (!ident?.empresaId) return;
            io.to(`empresa_${ident.empresaId}`).emit('receive_empresa', {
                ...data,
                empresa_id: ident.empresaId,
                usuario_id: ident.usuarioId,
            });
        } catch (err) {
            console.error('Erro ao enviar mensagem de empresa:', err);
        }
    });
});

const PORT = process.env.PORT || 8600;
const HOST = process.env.HOST || '0.0.0.0';

const iniciarServidor = async () => {
    await resetarUsuariosOnlineAoIniciar();

    server.listen(PORT, HOST, () => {
        console.log(`🚀 Servidor Chat Interno rodando em http://${HOST}:${PORT}`);
    });
};

iniciarServidor();
