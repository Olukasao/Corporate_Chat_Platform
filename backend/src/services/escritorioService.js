// Ligação com o Escritório (Office 3D / Workspace-3d). Desligada se não houver ESCRITORIO_URL e ESCRITORIO_TOKEN.
//  - envia o diretório (quem trabalha na empresa, setor e se é administrador);
//  - envia "quem está com o Workspace aberto" (só o fato de estar aberto, nunca conteúdo de conversa);
//  - gera o bilhete do login único (o Workspace abre o Escritório já logado).
import { createHmac } from "node:crypto";
import db from "../db/db.js";
import { listarWorkspace } from "./workspacePresenceService.js";

const cfg = () => ({
    url: String(process.env.ESCRITORIO_URL || "").replace(/\/+$/, ""),
    publicUrl: String(process.env.ESCRITORIO_PUBLIC_URL || process.env.ESCRITORIO_URL || "").replace(/\/+$/, ""),
    token: String(process.env.ESCRITORIO_TOKEN || ""),
    empresaId: Number(process.env.ESCRITORIO_EMPRESA_ID || 1),
    nomeEmpresa: String(process.env.ESCRITORIO_EMPRESA_NOME || "AcessaNet"),
});
export const escritorioAtivo = () => { const c = cfg(); return Boolean(c.url && c.token); };

const COMPANY_ID = "co_acessanet";
const employeeId = (usuarioId) => `emp_chat_${usuarioId}`;
const papel = (perfil) => (perfil === "admin" ? "admin" : "operator");

async function enviar(caminho, corpo) {
    const c = cfg();
    const r = await fetch(`${c.url}/api/integrations/${caminho}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json", "X-Requested-With": "office3d", Authorization: `Bearer ${c.token}` },
        body: JSON.stringify(corpo),
        signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) throw new Error(`${caminho}: HTTP ${r.status}`);
    return r.json();
}

export async function sincronizarDiretorio() {
    if (!escritorioAtivo()) return null;
    const c = cfg();
    const [linhas] = await db.query(
        `SELECT u.id, u.nome, u.perfil, u.deletado_em, s.nome AS setor FROM usuarios u LEFT JOIN setores s ON s.id = u.setor_id WHERE u.empresa_id = ?`,
        [c.empresaId],
    );
    const people = linhas
        .filter((u) => u.nome && String(u.nome).trim())
        .map((u) => ({ ref: String(u.id), name: String(u.nome).trim().slice(0, 160), department: String(u.setor || "Sem setor").slice(0, 80), role: papel(u.perfil), active: !u.deletado_em }));
    return enviar("workspace-directory", { companyName: c.nomeEmpresa, people });
}

export async function enviarPresenca() {
    if (!escritorioAtivo()) return null;
    const c = cfg();
    const ids = listarWorkspace(c.empresaId).map((u) => employeeId(u.usuario_id));
    return enviar("workspace-presence", { companyId: COMPANY_ID, employeeIds: ids });
}

let agendado = null;
/** Chamado quando alguém abre ou fecha o Workspace: junta vários avisos seguidos num só. */
export function agendarPresenca() {
    if (!escritorioAtivo() || agendado) return;
    agendado = setTimeout(() => { agendado = null; enviarPresenca().catch((e) => console.error("[ESCRITORIO] presença:", e.message)); }, 800);
    agendado.unref?.();
}

let iniciado = false;
export function iniciarEscritorio() {
    if (iniciado || !escritorioAtivo()) return;
    iniciado = true;
    const rodarDiretorio = () => sincronizarDiretorio().then((r) => r && console.log("[ESCRITORIO] diretório:", JSON.stringify(r))).catch((e) => console.error("[ESCRITORIO] diretório:", e.message));
    const rodarPresenca = () => enviarPresenca().catch((e) => console.error("[ESCRITORIO] presença:", e.message));
    // o diretório vai primeiro (cria a empresa no Escritório); a presença só depois
    setTimeout(() => rodarDiretorio().then(rodarPresenca), 3000).unref?.();
    setInterval(rodarDiretorio, 5 * 60_000).unref?.();
    // reenvio periódico: o Escritório perde o estado se reiniciar
    setInterval(rodarPresenca, 30_000).unref?.();
}

/** Bilhete de uso único (~60 s) assinado com o segredo compartilhado. O papel vem do perfil gravado no chat, nunca do cliente. */
export function criarBilhete(usuario) {
    const c = cfg();
    const corpo = Buffer.from(JSON.stringify({ ref: String(usuario.id), role: papel(usuario.perfil), exp: Date.now() + 60_000 })).toString("base64url");
    const assinatura = createHmac("sha256", `office3d-sso:${c.token}`).update(corpo).digest("base64url");
    return { ticket: `${corpo}.${assinatura}`, url: `${c.publicUrl}/sso?ticket=${corpo}.${assinatura}`, origem: c.publicUrl };
}
