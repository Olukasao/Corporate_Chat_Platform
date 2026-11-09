// Workscape Phone: contas SIP por funcionário, histórico e auditoria.
// A senha SIP é guardada cifrada (AES-256-GCM) com a chave PHONE_SECRET_KEY (32 bytes em base64) e nunca
// aparece em log, em listagens ou no histórico. Só o dono da conta lê a própria senha, e só pela rota de credenciais.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import db from "../db/db.js";

const TRANSPORTES = new Set(["udp", "tcp"]);
const RE_HOST = /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const RE_RAMAL = /^[0-9]{1,20}$/;
const RE_USUARIO_SIP = /^[A-Za-z0-9._+-]{1,64}$/;
const RESULTADOS = new Set(["atendida", "nao_atendida", "rejeitada", "falhou"]);

export function chaveDeCifra(env = process.env) {
  const bruta = String(env.PHONE_SECRET_KEY || "").trim();
  if (!bruta) return null;
  const chave = Buffer.from(bruta, "base64");
  return chave.length === 32 ? chave : null;
}

export function telefoniaConfigurada(env = process.env) {
  return chaveDeCifra(env) !== null;
}

/** Formato: v1:<iv>:<tag>:<texto cifrado>, tudo em base64. */
export function cifrarSenha(senha, env = process.env) {
  const chave = chaveDeCifra(env);
  if (!chave) throw Object.assign(new Error("Telefonia não configurada no servidor (PHONE_SECRET_KEY)."), { status: 503 });
  const iv = randomBytes(12);
  const cifra = createCipheriv("aes-256-gcm", chave, iv);
  const dados = Buffer.concat([cifra.update(String(senha), "utf8"), cifra.final()]);
  return `v1:${iv.toString("base64")}:${cifra.getAuthTag().toString("base64")}:${dados.toString("base64")}`;
}

export function decifrarSenha(valor, env = process.env) {
  const chave = chaveDeCifra(env);
  if (!chave) throw Object.assign(new Error("Telefonia não configurada no servidor (PHONE_SECRET_KEY)."), { status: 503 });
  const [versao, iv, tag, dados] = String(valor || "").split(":");
  if (versao !== "v1" || !iv || !tag || !dados) throw new Error("Senha SIP em formato inválido.");
  const decifra = createDecipheriv("aes-256-gcm", chave, Buffer.from(iv, "base64"));
  decifra.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([decifra.update(Buffer.from(dados, "base64")), decifra.final()]).toString("utf8");
}

/** Valida e normaliza os dados de uma conta SIP. `senhaObrigatoria` é falso ao editar sem trocar a senha. */
export function validarConta(entrada, { senhaObrigatoria = true } = {}) {
  const erro = (m) => Object.assign(new Error(m), { status: 400 });
  const e = entrada && typeof entrada === "object" ? entrada : {};
  const ramal = String(e.ramal ?? "").trim();
  const sipUser = String(e.sipUser ?? ramal).trim();
  const sipDomain = String(e.sipDomain ?? "").trim().toLowerCase();
  const sipServer = String(e.sipServer ?? sipDomain).trim().toLowerCase();
  const porta = e.sipPort === undefined || e.sipPort === "" ? 5060 : Number(e.sipPort);
  const transporte = String(e.transport ?? "udp").toLowerCase();
  const nome = String(e.displayName ?? "").replace(/[\r\n"]/g, "").trim().slice(0, 100);
  if (!RE_RAMAL.test(ramal)) throw erro("O ramal deve ter só números (até 20).");
  if (!RE_USUARIO_SIP.test(sipUser)) throw erro("Usuário SIP inválido.");
  if (!RE_HOST.test(sipDomain)) throw erro("Domínio SIP inválido.");
  if (!RE_HOST.test(sipServer)) throw erro("Servidor SIP inválido.");
  if (!Number.isInteger(porta) || porta < 1 || porta > 65535) throw erro("Porta SIP inválida.");
  if (!TRANSPORTES.has(transporte)) throw erro("Transporte deve ser udp ou tcp.");
  const senha = e.senha === undefined || e.senha === null ? "" : String(e.senha);
  if (senhaObrigatoria && !senha) throw erro("Informe a senha SIP.");
  if (senha && (senha.length > 128 || /[\r\n\0]/.test(senha))) throw erro("Senha SIP inválida.");
  return { ramal, sipUser, sipDomain, sipServer, sipPort: porta, transport: transporte, displayName: nome, senha };
}

export function validarChamada(entrada) {
  const erro = (m) => Object.assign(new Error(m), { status: 400 });
  const e = entrada && typeof entrada === "object" ? entrada : {};
  const direcao = e.direcao === "in" ? "in" : e.direcao === "out" ? "out" : null;
  if (!direcao) throw erro("Direção inválida.");
  const numero = String(e.numero ?? "").trim();
  if (!/^[0-9+*#A-Za-z._-]{1,64}$/.test(numero)) throw erro("Número inválido.");
  const resultado = String(e.resultado ?? "");
  if (!RESULTADOS.has(resultado)) throw erro("Resultado inválido.");
  const duracao = Math.max(0, Math.min(86400, Math.trunc(Number(e.duracaoSeg) || 0)));
  const inicio = new Date(Number(e.inicioMs) || Date.now());
  if (Number.isNaN(inicio.getTime()) || Math.abs(inicio.getTime() - Date.now()) > 2 * 86400_000) throw erro("Horário inválido.");
  return { direcao, numero, resultado, duracaoSeg: duracao, inicio };
}

let schemaPronto = null;
export function garantirSchemaPhone() {
  schemaPronto ??= (async () => {
    const motor = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    await db.query(`CREATE TABLE IF NOT EXISTS phone_accounts (
      id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      empresa_id INT NOT NULL,
      usuario_id INT NOT NULL,
      ramal VARCHAR(20) NOT NULL,
      sip_user VARCHAR(64) NOT NULL,
      sip_domain VARCHAR(253) NOT NULL,
      sip_server VARCHAR(253) NOT NULL,
      sip_port INT NOT NULL DEFAULT 5060,
      transport VARCHAR(3) NOT NULL DEFAULT 'udp',
      display_name VARCHAR(100) NOT NULL DEFAULT '',
      senha_cifrada VARCHAR(600) NOT NULL,
      ativo TINYINT(1) NOT NULL DEFAULT 1,
      criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      UNIQUE KEY uq_phone_usuario (empresa_id, usuario_id),
      UNIQUE KEY uq_phone_ramal (empresa_id, ramal)
    ) ${motor}`);
    await db.query(`CREATE TABLE IF NOT EXISTS phone_calls (
      id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      empresa_id INT NOT NULL,
      usuario_id INT NOT NULL,
      direcao VARCHAR(3) NOT NULL,
      numero VARCHAR(64) NOT NULL,
      resultado VARCHAR(20) NOT NULL,
      duracao_seg INT NOT NULL DEFAULT 0,
      inicio DATETIME NOT NULL,
      criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_phone_calls_usuario (empresa_id, usuario_id, inicio)
    ) ${motor}`);
    await db.query(`CREATE TABLE IF NOT EXISTS phone_audit (
      id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      empresa_id INT NOT NULL,
      ator_id INT NOT NULL,
      acao VARCHAR(40) NOT NULL,
      alvo_usuario_id INT DEFAULT NULL,
      detalhe VARCHAR(255) NOT NULL DEFAULT '',
      criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      KEY idx_phone_audit (empresa_id, criado_em)
    ) ${motor}`);
  })().catch((e) => { schemaPronto = null; throw e; });
  return schemaPronto;
}

export async function auditar({ empresaId, atorId, acao, alvoUsuarioId = null, detalhe = "" }) {
  await db.query("INSERT INTO phone_audit (empresa_id, ator_id, acao, alvo_usuario_id, detalhe) VALUES (?, ?, ?, ?, ?)",
    [empresaId, atorId, acao, alvoUsuarioId, String(detalhe).slice(0, 255)]);
}

/** Conta sem a senha: é o que a interface e o administrador veem. */
export const publica = (l) => ({
  usuarioId: l.usuario_id, ramal: l.ramal, sipUser: l.sip_user, sipDomain: l.sip_domain, sipServer: l.sip_server,
  sipPort: l.sip_port, transport: l.transport, displayName: l.display_name, ativo: !!l.ativo,
});

/**
 * Número que se disca para falar com este ramal. A conta SIP usa o ramal completo (ex.: 7781010), mas a central só
 * reconhece o número curto (1010): discar o completo cai em "telefone não existe". Tira o prefixo da central (padrão 778,
 * ajustável em PHONE_PREFIXO_RAMAL; vazio desliga) quando sobram ao menos 3 dígitos.
 */
export function extensaoDeDiscagem(ramal, prefixo = process.env.PHONE_PREFIXO_RAMAL ?? "778") {
    const r = String(ramal ?? "").trim();
    const p = String(prefixo ?? "").trim();
    return p && /^\d+$/.test(r) && r.startsWith(p) && r.length - p.length >= 3 ? r.slice(p.length) : r;
}
