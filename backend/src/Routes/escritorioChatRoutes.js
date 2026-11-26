// /api/escritorio-s2s — o Escritório (Office 3D) conversa pelo chat interno, em nome da pessoa logada nele.
// Servidor a servidor: autenticado pelo segredo compartilhado (ESCRITORIO_TOKEN), nunca pelo navegador.
// "de" vem da sessão do Escritório (conferida lá); aqui só aceitamos pessoas da empresa ligada.
import { createHash, timingSafeEqual } from "node:crypto";
import { Router } from "express";
import db from "../db/db.js";
import { escritorioAtivo, avisarVisita } from "../services/escritorioService.js";
import { obterResumoAgendaTecnicos } from "../services/agendaTecnicosResumoService.js";
import { dashboardRelay } from "../services/dashboardRelayService.js";
import { listarIncidentesAtivos, oltCloudConfigurada } from "../services/oltCloudService.js";

const empresaId = () => Number(process.env.ESCRITORIO_EMPRESA_ID || 1);
const igual = (a, b) => { const x = createHash("sha256").update(a).digest(), y = createHash("sha256").update(b).digest(); return timingSafeEqual(x, y); };
const id = (v) => (/^\d{1,12}$/.test(String(v ?? "")) ? Number(v) : null);

export function criarRotasEscritorioChat() {
    const router = Router();
    router.use((req, res, next) => {
        if (!escritorioAtivo()) return res.status(404).json({ error: "Ligação com o Escritório desligada." });
        const dado = String(req.headers.authorization || "").replace(/^Bearer /i, "");
        if (!dado || !igual(dado, String(process.env.ESCRITORIO_TOKEN))) return res.status(401).json({ error: "Token inválido." });
        next();
    });

    // as duas pessoas precisam ser da empresa ligada e estar ativas
    const par = async (de, para) => {
        if (!de || !para || de === para) return null;
        const [r] = await db.query("SELECT id, nome, avatar FROM usuarios WHERE id IN (?, ?) AND empresa_id = ? AND deletado_em IS NULL", [de, para, empresaId()]);
        return r.length === 2 ? r : null;
    };
    const conversa = async (a, b, criar) => {
        const q = "SELECT id FROM conversas_diretas WHERE (usuario1_id = ? AND usuario2_id = ?) OR (usuario1_id = ? AND usuario2_id = ?) LIMIT 1";
        let [c] = await db.query(q, [a, b, b, a]);
        if (!c.length && criar) {
            await db.query("INSERT INTO conversas_diretas (usuario1_id, usuario2_id) VALUES (?, ?)", [a, b]);
            [c] = await db.query(q, [a, b, b, a]);
        }
        return c[0]?.id ?? null;
    };

    router.get("/mensagens", async (req, res) => {
        try {
            const de = id(req.query.de), para = id(req.query.para);
            if (!(await par(de, para))) return res.status(404).json({ error: "Pessoa não encontrada." });
            const conversaId = await conversa(de, para, false);
            if (!conversaId) return res.json({ mensagens: [] });
            const [rows] = await db.query(
                `SELECT id, remetente_id, mensagem, tipo_mensagem, criada_em FROM mensagens
                  WHERE conversa_direta_id = ? AND deletada_em IS NULL ORDER BY id DESC LIMIT 100`, [conversaId]);
            res.json({ mensagens: rows.reverse().map((m) => ({
                id: m.id, remetente_id: m.remetente_id, criada_em: m.criada_em,
                // o mapa só mostra texto; figurinha, áudio e anexo aparecem como aviso curto
                texto: m.tipo_mensagem === "texto" ? String(m.mensagem ?? "") : `[${m.tipo_mensagem === "audio" ? "áudio" : m.tipo_mensagem === "sticker" ? "figurinha" : "anexo"}] abra no chat interno`,
            })) });
        } catch (e) { console.error("[ESCRITORIO-CHAT] listar:", e.message); res.status(500).json({ error: "Falha ao carregar a conversa." }); }
    });

    router.post("/mensagem", async (req, res) => {
        try {
            const de = id(req.body?.de), para = id(req.body?.para);
            const texto = typeof req.body?.texto === "string" ? req.body.texto.trim() : "";
            if (!texto || texto.length > 2000) return res.status(400).json({ error: "Mensagem vazia ou longa demais." });
            const pessoas = await par(de, para);
            if (!pessoas) return res.status(404).json({ error: "Pessoa não encontrada." });
            const conversaId = await conversa(de, para, true);
            const [r] = await db.query("INSERT INTO mensagens (remetente_id, conversa_direta_id, mensagem, tipo_mensagem) VALUES (?, ?, ?, 'texto')", [de, conversaId, texto]);
            await db.query("UPDATE conversas_diretas SET atualizada_em = NOW() WHERE id = ?", [conversaId]);
            await db.query("DELETE FROM conversas_ocultas_usuario WHERE conversa_direta_id = ? AND usuario_id IN (?, ?)", [conversaId, de, para]).catch(() => {});
            // tempo real: a mensagem chega na hora no chat de quem recebeu (mesmos eventos do envio pelo chat)
            const io = req.app.get("io");
            const remetente = pessoas.find((p) => p.id === de);
            const msg = { id: r.insertId, remetente_id: de, usuario_id: para, conversa_id: conversaId, remetente_nome: remetente?.nome, remetente_avatar: remetente?.avatar ?? null,
                mensagem: texto, tipo_mensagem: "texto", anexo_nome: null, anexo_mime: null, sticker_id: null, lida: false, entregue_em: null, lida_em: null, reacoes: [], criada_em: new Date() };
            io?.to(`conversa_${conversaId}`).emit("receive_direct_message", msg);
            avisarVisita(de, para);
            io?.to(`user_${para}`).emit("new_direct_message_notification", { ...msg, preview: texto.slice(0, 120) });
            res.status(201).json({ id: r.insertId, criada_em: msg.criada_em });
        } catch (e) { console.error("[ESCRITORIO-CHAT] enviar:", e.message); res.status(500).json({ error: "Falha ao enviar a mensagem." }); }
    });

    // ---------- foto do perfil, ligação e transferência de atendimento (pelo cartão da pessoa no mapa) ----------
    const usuario = async (uid) => {
        if (!uid) return null;
        const [r] = await db.query("SELECT id, nome, email FROM usuarios WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL", [uid, empresaId()]);
        return r[0] ?? null;
    };

    // A foto fica no banco como data URL; o mapa recebe a imagem de verdade (e só dela).
    router.get("/foto", async (req, res) => {
        try {
            const uid = id(req.query.usuario);
            if (!uid || !(await usuario(uid))) return res.status(404).end();
            const [r] = await db.query("SELECT avatar FROM usuarios WHERE id = ?", [uid]);
            const m = /^data:(image\/(?:png|jpeg|jpg|webp|gif));base64,([A-Za-z0-9+/=]+)$/.exec(String(r[0]?.avatar ?? ""));
            if (!m) return res.status(404).end();
            res.set({ "Content-Type": m[1], "Cache-Control": "private, max-age=300", "X-Content-Type-Options": "nosniff" });
            res.send(Buffer.from(m[2], "base64"));
        } catch (e) { console.error("[ESCRITORIO-CHAT] foto:", e.message); res.status(500).end(); }
    });

    // "Ligar": o Workspace de quem clicou recebe o ramal do colega e disca pelo Workscape Phone dele (o mapa não liga sozinho).
    router.post("/ligar", async (req, res) => {
        try {
            const de = id(req.body?.de), para = id(req.body?.para);
            const pessoas = await par(de, para);
            if (!pessoas) return res.status(404).json({ error: "Pessoa não encontrada." });
            const [ramal] = await db.query("SELECT ramal FROM phone_accounts WHERE empresa_id = ? AND usuario_id = ? AND ativo = 1 LIMIT 1", [empresaId(), para]);
            const numero = String(ramal[0]?.ramal ?? "").replace(/\D/g, "");
            if (!numero) return res.status(409).json({ error: "Essa pessoa não tem ramal ativo no Workscape Phone." });
            const nome = pessoas.find((p) => p.id === para)?.nome;
            const io = req.app.get("io");
            const alcancados = io ? (await io.in(`user_${de}`).fetchSockets()).length : 0;
            if (!alcancados) return res.status(409).json({ error: "Seu Workspace não está aberto para discar. Abra o Workspace e tente de novo." });
            io.to(`user_${de}`).emit("escritorio_ligar", { numero, nome });
            res.json({ ok: true, nome, ramal: numero });
        } catch (e) { console.error("[ESCRITORIO-CHAT] ligar:", e.message); res.status(500).json({ error: "Falha ao pedir a ligação." }); }
    });

    // Aviso do Escritório para o Workspace da pessoa (ex.: proposta de troca de monstrinho). Só texto curto; sem conteúdo de conversa.
    router.post("/aviso", async (req, res) => {
        try {
            const para = id(req.body?.para);
            const titulo = typeof req.body?.titulo === "string" ? req.body.titulo.trim().slice(0, 100) : "";
            const texto = typeof req.body?.texto === "string" ? req.body.texto.trim().slice(0, 300) : "";
            if (!para || !titulo) return res.status(400).json({ error: "Pedido inválido." });
            const [r] = await db.query("SELECT id FROM usuarios WHERE id = ? AND empresa_id = ? AND deletado_em IS NULL", [para, empresaId()]);
            if (!r.length) return res.status(404).json({ error: "Pessoa não encontrada." });
            const io = req.app.get("io");
            const alcancados = io ? (await io.in(`user_${para}`).fetchSockets()).length : 0;
            if (alcancados) io.to(`user_${para}`).emit("escritorio_aviso", { titulo, texto, alvo: "/escritorio" });
            res.json({ ok: true, entregue: alcancados > 0 });
        } catch (e) { console.error("[ESCRITORIO-CHAT] aviso:", e.message); res.status(500).json({ error: "Falha ao enviar o aviso." }); }
    });

    // Transferência de atendimento: os atendimentos moram na chat-api; aqui só traduzimos a pessoa (id) para o e-mail do atendente.
    const atendimento = async (caminho, { metodo = "GET", corpo, consulta } = {}) => {
        const base = String(process.env.ATENDIMENTO_S2S_URL || "").replace(/\/+$/, "");
        const token = process.env.ATENDIMENTO_S2S_TOKEN;
        if (!base || !token) { const e = new Error("A ligação com o Atendimento está desligada."); e.status = 503; throw e; }
        let r;
        try {
            r = await fetch(`${base}/api/office/${caminho}${consulta ? `?${new URLSearchParams(consulta)}` : ""}`, {
                method: metodo, headers: { Authorization: `Bearer ${token}`, ...(corpo ? { "Content-Type": "application/json" } : {}) },
                body: corpo ? JSON.stringify(corpo) : undefined, signal: AbortSignal.timeout(8000),
            });
        } catch { const e = new Error("O Atendimento não respondeu."); e.status = 503; throw e; }
        const dados = await r.json().catch(() => ({}));
        if (!r.ok) { const e = new Error(MENSAGENS_ATENDIMENTO[dados.error] || "O Atendimento recusou o pedido."); e.status = r.status === 403 ? 409 : r.status >= 500 ? 503 : r.status; throw e; }
        return dados;
    };
    const MENSAGENS_ATENDIMENTO = {
        agent_not_registered: "Essa pessoa não está cadastrada como atendente.",
        target_is_self: "Escolha outra pessoa para receber.",
        target_not_in_queue: "Essa pessoa está fora da fila de atendimento.",
        no_active_ticket: "Esse atendimento não está mais com você.",
        conversation_closed: "Esse atendimento já foi encerrado.",
        ticket_changed: "O atendimento mudou desde que você abriu a tela. Atualize e tente de novo.",
        conversation_not_found: "Atendimento não encontrado.",
    };
    const falha = (res, e, rotulo) => {
        if (e.status) return res.status(e.status).json({ error: e.message });
        console.error(`[ESCRITORIO-CHAT] ${rotulo}:`, e.message);
        res.status(500).json({ error: "Falha na operação." });
    };

    router.get("/atendimentos", async (req, res) => {
        try {
            const u = await usuario(id(req.query.de));
            if (!u) return res.status(404).json({ error: "Pessoa não encontrada." });
            const d = await atendimento("agent-conversations", { consulta: { email: u.email } }).catch((e) => (e.message.includes("cadastrada") || e.status === 409 ? { conversations: [], naoAtendente: true } : Promise.reject(e)));
            res.json({ tickets: d.conversations, naoAtendente: !!d.naoAtendente });
        } catch (e) { falha(res, e, "atendimentos"); }
    });

    // Incidentes de rede ativos (mesma lista da tela Rede OLT) para o rack do Escritório piscar. Só leitura, sem dados de clientes.
    router.get("/rede/incidentes", async (_req, res) => {
        try {
            if (!oltCloudConfigurada()) return res.json({ configurada: false, incidentes: [] });
            const { atualizadoEm, incidentes } = await listarIncidentesAtivos();
            res.json({ configurada: true, atualizadoEm, incidentes: incidentes.map(({ id, tipo, olt, descricao, dispositivosAtivos, pon }) => ({ id, tipo, olt, descricao, dispositivosAtivos, pon })) });
        } catch (e) { falha(res, e, "rede-incidentes"); }
    });

    // Mensagens ainda não lidas de uma pessoa (conversas diretas e grupos de que ela participa), como os contadores do chat.
    // Usado pela missão "Caixa de entrada zerada" do Escritório. Só números, sem conteúdo de mensagem.
    router.get("/nao-lidas", async (req, res) => {
        try {
            const u = await usuario(id(req.query.usuario));
            if (!u) return res.status(404).json({ error: "Pessoa não encontrada." });
            const oculta = "NOT EXISTS (SELECT 1 FROM mensagens_ocultas_usuario mou WHERE mou.mensagem_id = m.id AND mou.usuario_id = ?)";
            const [[d]] = await db.query(`
                SELECT COUNT(*) AS n FROM mensagens m
                JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id
                WHERE (cd.usuario1_id = ? OR cd.usuario2_id = ?) AND m.remetente_id != ? AND m.deletada_em IS NULL AND m.lida = FALSE
                  AND ${oculta}
                  AND NOT EXISTS (SELECT 1 FROM conversas_ocultas_usuario cou WHERE cou.conversa_direta_id = cd.id AND cou.usuario_id = ?)
            `, [u.id, u.id, u.id, u.id, u.id]);
            const [[g]] = await db.query(`
                SELECT COUNT(*) AS n FROM mensagens m
                JOIN grupo_membros gm ON gm.grupo_id = m.grupo_id AND gm.usuario_id = ?
                JOIN grupos gr ON gr.id = m.grupo_id AND gr.deletado_em IS NULL
                WHERE m.remetente_id != ? AND m.deletada_em IS NULL AND ${oculta}
                  AND m.id > COALESCE((SELECT gmr.last_read_message_id FROM group_message_reads gmr WHERE gmr.user_id = ? AND gmr.group_id = m.grupo_id LIMIT 1), 0)
            `, [u.id, u.id, u.id, u.id]);
            const diretas = Number(d?.n ?? 0), grupos = Number(g?.n ?? 0);
            res.json({ diretas, grupos, total: diretas + grupos });
        } catch (e) { falha(res, e, "nao-lidas"); }
    });

    // Missões do Escritório ligadas ao trabalho: o que a pessoa já fez HOJE (dia de São Paulo, o mesmo fuso do banco).
    // Só sim/não: nenhum texto de mensagem, número de telefone ou nome de lembrete sai daqui.
    router.get("/trabalho-hoje", async (req, res) => {
        try {
            const u = await usuario(id(req.query.usuario));
            if (!u) return res.status(404).json({ error: "Pessoa não encontrada." });
            const tem = async (sql, args) => { try { const [r] = await db.query(sql, args); return r.length > 0; } catch (e) { if (e.code === "ER_NO_SUCH_TABLE") return false; throw e; } };
            // Respondeu rápido: numa conversa direta, mandou mensagem até 5 min depois de uma mensagem do colega
            // (a mensagem anterior da conversa é do outro, não de conta-robô, como o aviso dos lembretes).
            const respondeu = await tem(`
                SELECT 1 FROM mensagens m
                JOIN conversas_diretas cd ON cd.id = m.conversa_direta_id AND (cd.usuario1_id = ? OR cd.usuario2_id = ?)
                JOIN mensagens p ON p.id = (SELECT MAX(q.id) FROM mensagens q WHERE q.conversa_direta_id = m.conversa_direta_id AND q.id < m.id AND q.deletada_em IS NULL)
                JOIN usuarios pu ON pu.id = p.remetente_id AND pu.senha <> '!'
                WHERE m.remetente_id = ? AND m.criada_em >= CURDATE() AND m.deletada_em IS NULL
                  AND p.remetente_id <> m.remetente_id AND p.criada_em >= m.criada_em - INTERVAL 5 MINUTE
                LIMIT 1`, [u.id, u.id, u.id]);
            const aula = await tem("SELECT 1 FROM cursos_progresso WHERE usuario_id = ? AND concluida_em >= CURDATE() LIMIT 1", [u.id])
                || await tem("SELECT 1 FROM wiki_aulas_progresso WHERE usuario_id = ? AND concluida = 1 AND concluida_em >= CURDATE() LIMIT 1", [u.id]);
            // lembrete que tocou hoje e a pessoa marcou "feito" (a limpeza automática só fecha os de 3 dias atrás)
            const lembrete = await tem("SELECT 1 FROM lembrete_disparos WHERE usuario_id = ? AND empresa_id = ? AND status = 'feito' AND disparou_em >= CURDATE() LIMIT 1", [u.id, empresaId()]);
            const ligacao = await tem("SELECT 1 FROM phone_calls WHERE usuario_id = ? AND empresa_id = ? AND direcao = 'in' AND resultado = 'atendida' AND inicio >= CURDATE() LIMIT 1", [u.id, empresaId()]);
            res.json({ respondeu, aula, lembrete, ligacao });
        } catch (e) { falha(res, e, "trabalho-hoje"); }
    });

    // Total de vendas do dia ("ATIVAÇÃO DE CONTRATO - COMUM" do Painel NOC, a mesma do aviso de venda do Workspace) para o Escritório comemorar.
    router.get("/vendas", (_req, res) => {
        dashboardRelay.start();
        const norm = (v) => String(v).normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[–—]/g, "-").replace(/\s*-\s*/g, "-").replace(/\s+/g, " ").trim().toUpperCase();
        const alvo = norm("ATIVAÇÃO DE CONTRATO - COMUM");
        const { connected, update } = dashboardRelay.read();
        if (!connected || !update?.grupos) return res.json({ conectado: false, total: null });
        let total = 0;
        for (const [k, v] of Object.entries(update.grupos)) if (norm(k) === alvo && Number.isFinite(Number(v)) && Number(v) >= 0) total += Number(v);
        res.json({ conectado: true, total });
    });

    // Quem está com OS em execução na Agenda de técnicos (só nome e situação, sem dados de cliente) para os carros do mapa.
    router.get("/tecnicos-campo", (_req, res) => {
        const r = obterResumoAgendaTecnicos();
        res.json({ conectado: r.conectado, tecnicos: (r.tecnicos || []).map((t) => ({ nome: t.nome, situacao: t.situacao })) });
    });

    router.get("/pode-receber", async (req, res) => {
        try {
            const u = await usuario(id(req.query.para));
            if (!u) return res.status(404).json({ error: "Pessoa não encontrada." });
            const d = await atendimento("can-receive", { consulta: { email: u.email } });
            res.json({ canReceive: !!d.canReceive });
        } catch (e) { falha(res, e, "pode-receber"); }
    });

    router.post("/transferir", async (req, res) => {
        try {
            const de = await usuario(id(req.body?.de)), para = await usuario(id(req.body?.para));
            const versao = Number(req.body?.expectedVersion);
            if (!de || !para || de.id === para.id) return res.status(404).json({ error: "Pessoa não encontrada." });
            if (!/^\d{1,12}$/.test(String(req.body?.conversationId ?? "")) || !Number.isInteger(versao)) return res.status(400).json({ error: "Pedido inválido." });
            const d = await atendimento("transfer", { metodo: "POST", corpo: { email: de.email, targetEmail: para.email, conversationId: Number(req.body.conversationId), expectedVersion: versao } });
            res.json(d);
        } catch (e) { falha(res, e, "transferir"); }
    });

    return router;
}
export default criarRotasEscritorioChat();
