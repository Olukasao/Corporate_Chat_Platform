// Gravação e transcrição das chamadas do Workscape Phone.
//
// Fluxo: o app grava a conversa em dois arquivos (atendente e cliente), envia ao terminar e o servidor transcreve com
// faster-whisper (local, sem custo e sem o áudio sair da rede). Cada lado é transcrito à parte, então já se sabe quem falou.
// O áudio é APAGADO assim que a transcrição termina (ou falha); só o texto fica, pelo prazo configurado.
import { spawn } from "node:child_process";
import { mkdirSync, unlinkSync, writeFileSync, existsSync } from "node:fs";
import path from "node:path";
import db from "../db/db.js";
import { conversar, mascararSensivel } from "./assistenteIa.js";
import { garantirSchemaPhone } from "./phoneService.js";

const PASTA = process.env.PHONE_GRAVACAO_DIR || "/home/noc/transcricao/fila";
const PYTHON = process.env.WHISPER_PYTHON || "/home/noc/transcricao/venv/bin/python";
const SCRIPT = process.env.WHISPER_SCRIPT || "/home/noc/transcricao/transcrever.py";
const MODELO = process.env.WHISPER_MODELO || "small";
export const MAX_ARQUIVO = 40 * 1024 * 1024; // por lado: WAV de 8 kHz, mono, 16 bits = 16 KB/s, ou seja, uns 40 minutos de conversa
export const DIAS_PADRAO = 90;
export const MOTIVOS = [
  "Suporte técnico: sem conexão", "Suporte técnico: lentidão ou instabilidade", "Suporte técnico: Wi-Fi ou equipamento",
  "Financeiro: fatura ou boleto", "Financeiro: pagamento, desbloqueio ou negociação", "Comercial: nova contratação",
  "Comercial: mudança de plano", "Mudança de endereço", "Agendamento ou visita técnica", "Cancelamento", "Informação geral", "Outro",
];

let schemaPronto = null;
export function garantirSchemaTranscricao() {
  schemaPronto ??= (async () => {
    await garantirSchemaPhone();
    const motor = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    await db.query(`CREATE TABLE IF NOT EXISTS phone_config (
      empresa_id INT NOT NULL, chave VARCHAR(40) NOT NULL, valor VARCHAR(100) NOT NULL,
      PRIMARY KEY (empresa_id, chave)) ${motor}`);
    await db.query(`CREATE TABLE IF NOT EXISTS phone_gravacoes (
      id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
      empresa_id INT NOT NULL, usuario_id INT NOT NULL, call_id BIGINT DEFAULT NULL,
      direcao VARCHAR(3) NOT NULL, numero VARCHAR(64) NOT NULL, inicio_ms BIGINT NOT NULL, duracao_seg INT NOT NULL DEFAULT 0,
      status VARCHAR(16) NOT NULL DEFAULT 'fila',
      arquivo_local VARCHAR(255) DEFAULT NULL, arquivo_remoto VARCHAR(255) DEFAULT NULL,
      segmentos MEDIUMTEXT DEFAULT NULL, resumo TEXT DEFAULT NULL, motivo VARCHAR(80) DEFAULT NULL, erro VARCHAR(255) DEFAULT NULL,
      criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, concluido_em DATETIME DEFAULT NULL,
      UNIQUE KEY uq_phone_grav (empresa_id, usuario_id, inicio_ms, numero),
      KEY idx_phone_grav_status (status, id), KEY idx_phone_grav_call (call_id), KEY idx_phone_grav_usuario (empresa_id, usuario_id, inicio_ms)
    ) ${motor}`);
  })().catch((e) => { schemaPronto = null; throw e; });
  return schemaPronto;
}

// ---- configuração (o administrador liga e desliga) -------------------------------------------------
export async function lerConfig(empresaId) {
  await garantirSchemaTranscricao();
  const [linhas] = await db.query("SELECT chave, valor FROM phone_config WHERE empresa_id = ?", [empresaId]);
  const v = Object.fromEntries(linhas.map((l) => [l.chave, l.valor]));
  const dias = Math.max(1, Math.min(3650, Number(v.gravacao_dias) || DIAS_PADRAO));
  return { ativa: v.gravacao_ativa === "1", dias };
}
export async function salvarConfig(empresaId, { ativa, dias }) {
  await garantirSchemaTranscricao();
  const grava = (chave, valor) => db.query("INSERT INTO phone_config (empresa_id, chave, valor) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE valor = VALUES(valor)", [empresaId, chave, String(valor)]);
  if (typeof ativa === "boolean") await grava("gravacao_ativa", ativa ? "1" : "0");
  if (dias !== undefined) await grava("gravacao_dias", Math.max(1, Math.min(3650, Math.trunc(Number(dias)) || DIAS_PADRAO)));
  return lerConfig(empresaId);
}

// ---- recepção ---------------------------------------------------------------------------------------
const ehWav = (buf) => Buffer.isBuffer(buf) && buf.length > 44 && buf.toString("latin1", 0, 4) === "RIFF" && buf.toString("latin1", 8, 12) === "WAVE";

export function validarGravacao(corpo, arquivos) {
  const erro = (m) => Object.assign(new Error(m), { status: 400 });
  const direcao = corpo?.direcao === "in" ? "in" : corpo?.direcao === "out" ? "out" : null;
  if (!direcao) throw erro("Direção inválida.");
  const numero = String(corpo?.numero ?? "").trim();
  if (!/^[0-9+*#A-Za-z._-]{1,64}$/.test(numero)) throw erro("Número inválido.");
  const inicioMs = Math.trunc(Number(corpo?.inicioMs));
  if (!Number.isFinite(inicioMs) || Math.abs(inicioMs - Date.now()) > 8 * 86400_000) throw erro("Horário inválido.");
  const duracaoSeg = Math.max(0, Math.min(86400, Math.trunc(Number(corpo?.duracaoSeg) || 0)));
  const local = arquivos?.local?.[0]?.buffer, remoto = arquivos?.remoto?.[0]?.buffer;
  if (!ehWav(local) || !ehWav(remoto)) throw erro("Áudio inválido.");
  return { direcao, numero, inicioMs, duracaoSeg, local, remoto };
}

/** Liga a gravação à linha do histórico de chamadas (que o app grava em separado). Tolera 1 s de diferença. */
export async function ligarAoHistorico({ empresaId, usuarioId, numero, inicioMs }) {
  const base = Math.floor(inicioMs / 1000) * 1000;
  const [achou] = await db.query(
    "SELECT id FROM phone_calls WHERE empresa_id = ? AND usuario_id = ? AND numero = ? AND inicio BETWEEN ? AND ? ORDER BY id DESC LIMIT 1",
    [empresaId, usuarioId, numero, new Date(base - 1000), new Date(base + 1999)]);
  if (!achou[0]) return;
  await db.query("UPDATE phone_gravacoes SET call_id = ? WHERE empresa_id = ? AND usuario_id = ? AND inicio_ms = ? AND numero = ? AND call_id IS NULL",
    [achou[0].id, empresaId, usuarioId, inicioMs, numero]);
}

export async function receberGravacao({ empresaId, usuarioId, dados, io }) {
  await garantirSchemaTranscricao();
  mkdirSync(PASTA, { recursive: true, mode: 0o700 });
  const base = `${Date.now()}-${usuarioId}-${Math.random().toString(36).slice(2, 8)}`;
  const local = path.join(PASTA, `${base}-local.wav`), remoto = path.join(PASTA, `${base}-remoto.wav`);
  let id;
  try {
    const [r] = await db.query(
      "INSERT INTO phone_gravacoes (empresa_id, usuario_id, direcao, numero, inicio_ms, duracao_seg, status, arquivo_local, arquivo_remoto) VALUES (?, ?, ?, ?, ?, ?, 'fila', ?, ?)",
      [empresaId, usuarioId, dados.direcao, dados.numero, dados.inicioMs, dados.duracaoSeg, local, remoto]);
    id = r.insertId;
  } catch (e) {
    if (e?.code === "ER_DUP_ENTRY") throw Object.assign(new Error("Gravação já recebida."), { status: 409 });
    throw e;
  }
  writeFileSync(local, dados.local, { mode: 0o600 });
  writeFileSync(remoto, dados.remoto, { mode: 0o600 });
  await ligarAoHistorico({ empresaId, usuarioId, numero: dados.numero, inicioMs: dados.inicioMs }).catch(() => {});
  iniciarFila(io);
  return id;
}

// ---- transcrição --------------------------------------------------------------------------------------
function rodarWhisper(arquivo, tempoMs) {
  return new Promise((resolve, reject) => {
    const proc = spawn(PYTHON, [SCRIPT, arquivo, MODELO], { stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, PYTHONIOENCODING: "utf-8" } });
    const saida = []; let erro = "";
    const timer = setTimeout(() => { proc.kill("SIGKILL"); reject(new Error("A transcrição demorou demais.")); }, tempoMs);
    proc.stdout.on("data", (d) => saida.push(d));
    proc.stderr.on("data", (d) => { erro = (erro + d).slice(-600); });
    proc.on("error", (e) => { clearTimeout(timer); reject(e); });
    proc.on("close", (codigo) => {
      clearTimeout(timer);
      if (codigo !== 0) return reject(new Error(`faster-whisper falhou (${codigo}): ${erro.trim().split("\n").pop() ?? ""}`));
      try { resolve(JSON.parse(Buffer.concat(saida).toString("utf8")).segmentos ?? []); } catch { reject(new Error("Resposta do faster-whisper ilegível.")); }
    });
  });
}

// O Whisper costuma "inventar" estas frases em trechos de ruído ou silêncio.
const ALUCINACOES = /^(legendas? (pela|por|feitas?)|obrigad[oa] por assistir|inscreva-se|tchau,? tchau|\.+|…|\[.*\])/i;

/** Junta as falas dos dois lados na ordem em que aconteceram. Ruído isolado e frases inventadas saem. */
export function juntarFalas(local, remoto) {
  const limpo = (segs, quem) => segs
    .map((s) => ({ quem, ini: Number(s.ini) || 0, fim: Number(s.fim) || 0, texto: String(s.texto ?? "").trim() }))
    .filter((s) => s.texto.length > 1 && !ALUCINACOES.test(s.texto));
  return [...limpo(local, "atendente"), ...limpo(remoto, "cliente")].sort((a, b) => a.ini - b.ini || a.fim - b.fim);
}

export const textoDaConversa = (falas) => falas.map((f) => `${f.quem === "atendente" ? "Atendente" : "Cliente"}: ${f.texto}`).join("\n");

const SISTEMA_RESUMO = [
  "Você resume ligações de atendimento de um provedor de internet (Acessanet), em português do Brasil.",
  "Responda SOMENTE com um JSON válido, sem texto antes ou depois, no formato:",
  '{"resumo": "2 a 4 frases: o que o cliente queria, o que foi feito e o que ficou pendente", "motivo": "<um dos motivos da lista>"}',
  `Lista de motivos (copie um exatamente): ${MOTIVOS.join(" | ")}.`,
  "Não invente fatos que não estão na conversa. Se a conversa for curta ou confusa, diga isso no resumo e use o motivo \"Outro\".",
].join(" ");

export function lerResumo(resposta) {
  const bruto = String(resposta ?? "");
  const m = /\{[\s\S]*\}/.exec(bruto);
  if (!m) return { resumo: bruto.trim().slice(0, 800), motivo: null };
  try {
    const j = JSON.parse(m[0]);
    const motivo = MOTIVOS.find((x) => x.toLowerCase() === String(j.motivo ?? "").trim().toLowerCase()) ?? null;
    return { resumo: String(j.resumo ?? "").trim().slice(0, 1200) || null, motivo };
  } catch { return { resumo: bruto.trim().slice(0, 800), motivo: null }; }
}

async function resumir(falas, { conversarImpl = conversar } = {}) {
  // O texto vai a um modelo de IA na internet: CPF, telefone e e-mail falados são ocultados antes.
  const texto = mascararSensivel(textoDaConversa(falas)).slice(0, 12000);
  const r = await conversarImpl([{ role: "user", content: texto }], { sistema: SISTEMA_RESUMO, maxTokens: 400, tempoLimiteMs: 25000 });
  return lerResumo(r.resposta);
}

const apagar = (...arqs) => { for (const a of arqs) { try { if (a && existsSync(a)) unlinkSync(a); } catch { /* já apagado */ } } };

export async function processarGravacao(linha, { io, rodar = rodarWhisper, resumirImpl = resumir } = {}) {
  const tempo = Math.max(180_000, (linha.duracao_seg || 60) * 4000);
  try {
    // Um lado de cada vez: a máquina é pequena e dois Whisper juntos disputam CPU e memória.
    const segLocal = await rodar(linha.arquivo_local, tempo);
    const segRemoto = await rodar(linha.arquivo_remoto, tempo);
    const falas = juntarFalas(segLocal, segRemoto);
    if (!falas.length) {
      await db.query("UPDATE phone_gravacoes SET status = 'sem_fala', arquivo_local = NULL, arquivo_remoto = NULL, concluido_em = NOW() WHERE id = ?", [linha.id]);
    } else {
      let resumo = null, motivo = null;
      try { ({ resumo, motivo } = await resumirImpl(falas)); } catch { /* sem IA: fica só a transcrição */ }
      await db.query("UPDATE phone_gravacoes SET status = 'pronta', segmentos = ?, resumo = ?, motivo = ?, arquivo_local = NULL, arquivo_remoto = NULL, concluido_em = NOW() WHERE id = ?",
        [JSON.stringify(falas), resumo, motivo, linha.id]);
    }
  } catch (e) {
    console.error("[transcricao]", linha.id, e?.message);
    await db.query("UPDATE phone_gravacoes SET status = 'erro', erro = ?, arquivo_local = NULL, arquivo_remoto = NULL, concluido_em = NOW() WHERE id = ?", [String(e?.message || "erro").slice(0, 250), linha.id]);
  } finally {
    apagar(linha.arquivo_local, linha.arquivo_remoto); // o áudio nunca fica depois de processado
  }
  try { io?.to?.(`user_${linha.usuario_id}`).emit("phone:transcricao", { id: linha.id, numero: linha.numero, inicioMs: Number(linha.inicio_ms) }); } catch { /* aviso é opcional */ }
}

let rodando = false;
export function iniciarFila(io) {
  if (rodando) return;
  rodando = true;
  (async () => {
    try {
      for (;;) {
        await garantirSchemaTranscricao();
        const [proximos] = await db.query("SELECT * FROM phone_gravacoes WHERE status = 'fila' ORDER BY id ASC LIMIT 1");
        const linha = proximos[0];
        if (!linha) break;
        await db.query("UPDATE phone_gravacoes SET status = 'transcrevendo' WHERE id = ?", [linha.id]);
        await processarGravacao(linha, { io });
      }
    } catch (e) { console.error("[transcricao] fila:", e?.message); }
    finally { rodando = false; }
  })();
}

/** Ao ligar o servidor: o que ficou "transcrevendo" quando ele caiu volta para a fila (se os arquivos ainda existem). */
export async function retomarFila(io) {
  try {
    await garantirSchemaTranscricao();
    await db.query("UPDATE phone_gravacoes SET status = 'fila' WHERE status = 'transcrevendo'");
    iniciarFila(io);
  } catch (e) { console.error("[transcricao] retomar:", e?.message); }
}

/** Apaga as transcrições mais velhas que o prazo de cada empresa (padrão 90 dias). */
export async function limparAntigas() {
  await garantirSchemaTranscricao();
  const [empresas] = await db.query("SELECT DISTINCT empresa_id FROM phone_gravacoes");
  let total = 0;
  for (const { empresa_id } of empresas) {
    const { dias } = await lerConfig(empresa_id);
    const [r] = await db.query("DELETE FROM phone_gravacoes WHERE empresa_id = ? AND criado_em < (NOW() - INTERVAL ? DAY) AND status <> 'fila' AND status <> 'transcrevendo'", [empresa_id, dias]);
    total += r.affectedRows || 0;
  }
  return total;
}
