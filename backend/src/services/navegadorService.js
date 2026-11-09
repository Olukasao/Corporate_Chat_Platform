// Navegador do Workspace por setor: o administrador escolhe quais sites cada setor vê e pode cadastrar sites novos.
// Sem lista salva, o setor vê todos (como era antes). Administradores veem todos.
import db from "../db/db.js";

export const SITES_PADRAO = [
    { id: "sgp", nome: "SGP" },
    { id: "mundiale", nome: "Mundiale" },
    { id: "olt", nome: "OLT" },
    { id: "callcenter", nome: "Call Center" },
    { id: "zabbix", nome: "Zabbix" },
    { id: "grafana", nome: "Grafana" },
    { id: "comum", nome: "Navegador comum" },
];
const IDS_PADRAO = new Set(SITES_PADRAO.map((s) => s.id));
const ID_PERSONALIZADO = /^site-(\d+)$/;

const erro = (mensagem, status = 400) => Object.assign(new Error(mensagem), { status });

/** Aceita só http/https, sem usuário/senha; devolve a URL normalizada ou lança erro. */
export function validarUrl(entrada) {
    const texto = String(entrada ?? "").trim();
    if (!texto || texto.length > 300) throw erro("Informe o endereço do site (até 300 letras).");
    const candidata = /^[a-z][a-z0-9+.-]*:/i.test(texto) ? texto : `https://${texto}`;
    let u;
    try { u = new URL(candidata); } catch { throw erro("Endereço inválido."); }
    if (u.protocol !== "http:" && u.protocol !== "https:") throw erro("Use um endereço que comece com http:// ou https://.");
    if (u.username || u.password) throw erro("O endereço não pode ter usuário ou senha.");
    if (!u.hostname.includes(".") && u.hostname !== "localhost" && !/^\d+$/.test(u.hostname.replace(/\./g, ""))) throw erro("Endereço inválido.");
    return u.href;
}
export function validarNome(entrada) {
    const nome = String(entrada ?? "").replace(/\s+/g, " ").trim();
    if (nome.length < 2 || nome.length > 30) throw erro("O nome precisa ter de 2 a 30 letras.");
    return nome;
}

export function criarServicoNavegador({ banco = db } = {}) {
    let pronta = null;
    const garantir = () => {
        pronta ??= (async () => {
            await banco.query(`
                CREATE TABLE IF NOT EXISTS navegador_sites (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    empresa_id INT NOT NULL,
                    nome VARCHAR(30) NOT NULL,
                    url VARCHAR(300) NOT NULL,
                    criado_por INT NULL,
                    criado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    KEY idx_navegador_empresa (empresa_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
            await banco.query(`
                CREATE TABLE IF NOT EXISTS navegador_acesso (
                    empresa_id INT NOT NULL,
                    setor_id INT NOT NULL,
                    sites TEXT NOT NULL,
                    atualizado_por INT NULL,
                    atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    PRIMARY KEY (empresa_id, setor_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`);
        })().catch((e) => { pronta = null; throw e; });
        return pronta;
    };

    const todosOsSites = async (empresaId) => {
        await garantir();
        const [rows] = await banco.query("SELECT id, nome, url FROM navegador_sites WHERE empresa_id = ? ORDER BY id", [empresaId]);
        return [...SITES_PADRAO.map((s) => ({ ...s, personalizado: false })), ...rows.map((r) => ({ id: `site-${r.id}`, nome: r.nome, url: r.url, personalizado: true }))];
    };
    const lerLista = (texto) => { try { const l = JSON.parse(texto); return Array.isArray(l) ? l.map(String) : null; } catch { return null; } };
    const acessoDoSetor = async (empresaId, setorId) => {
        if (!setorId) return null;
        await garantir();
        const [rows] = await banco.query("SELECT sites FROM navegador_acesso WHERE empresa_id = ? AND setor_id = ?", [empresaId, setorId]);
        return rows[0] ? lerLista(rows[0].sites) : null;
    };

    return {
        /** Sites que esta pessoa vê. */
        async paraUsuario(usuario) {
            const todos = await todosOsSites(usuario.empresa_id);
            if (usuario.perfil === "admin") return todos;
            const lista = await acessoDoSetor(usuario.empresa_id, usuario.setor_id);
            return lista === null ? todos : todos.filter((s) => lista.includes(s.id));
        },

        async configuracao(empresaId) {
            const sites = await todosOsSites(empresaId);
            const [setores] = await banco.query("SELECT id, nome FROM setores WHERE empresa_id = ? ORDER BY nome ASC", [empresaId]);
            const [acessos] = await banco.query("SELECT setor_id, sites FROM navegador_acesso WHERE empresa_id = ?", [empresaId]);
            const porSetor = new Map(acessos.map((a) => [Number(a.setor_id), lerLista(a.sites)]));
            return { sites, setores: setores.map((s) => ({ id: s.id, nome: s.nome, sites: porSetor.get(Number(s.id)) ?? null })) };
        },

        async criarSite(empresaId, { nome, url }, adminId) {
            await garantir();
            const n = validarNome(nome), u = validarUrl(url);
            const [existentes] = await banco.query("SELECT COUNT(*) AS total FROM navegador_sites WHERE empresa_id = ?", [empresaId]);
            if (Number(existentes[0].total) >= 20) throw erro("Limite de 20 sites extras. Remova algum antes de adicionar outro.");
            const [r] = await banco.query("INSERT INTO navegador_sites (empresa_id, nome, url, criado_por) VALUES (?, ?, ?, ?)", [empresaId, n, u, adminId ?? null]);
            return { id: `site-${r.insertId}`, nome: n, url: u, personalizado: true };
        },

        async atualizarSite(empresaId, id, { nome, url }) {
            const m = ID_PERSONALIZADO.exec(String(id));
            if (!m) throw erro("Só sites extras podem ser editados.", 400);
            await garantir();
            const n = validarNome(nome), u = validarUrl(url);
            const [r] = await banco.query("UPDATE navegador_sites SET nome = ?, url = ? WHERE id = ? AND empresa_id = ?", [n, u, Number(m[1]), empresaId]);
            if (!r.affectedRows) throw erro("Site não encontrado.", 404);
            return { id, nome: n, url: u, personalizado: true };
        },

        async removerSite(empresaId, id) {
            const m = ID_PERSONALIZADO.exec(String(id));
            if (!m) throw erro("Só sites extras podem ser removidos.", 400);
            await garantir();
            const [r] = await banco.query("DELETE FROM navegador_sites WHERE id = ? AND empresa_id = ?", [Number(m[1]), empresaId]);
            if (!r.affectedRows) throw erro("Site não encontrado.", 404);
            // tira o site apagado das listas dos setores
            const [acessos] = await banco.query("SELECT setor_id, sites FROM navegador_acesso WHERE empresa_id = ?", [empresaId]);
            for (const a of acessos) {
                const lista = lerLista(a.sites);
                if (lista?.includes(id)) await banco.query("UPDATE navegador_acesso SET sites = ? WHERE empresa_id = ? AND setor_id = ?", [JSON.stringify(lista.filter((x) => x !== id)), empresaId, a.setor_id]);
            }
        },

        /** sites = null volta ao padrão (o setor vê todos). */
        async salvarAcesso(empresaId, setorId, sites, adminId) {
            await garantir();
            const [s] = await banco.query("SELECT id FROM setores WHERE id = ? AND empresa_id = ?", [setorId, empresaId]);
            if (!s[0]) throw erro("Setor não encontrado.", 404);
            if (sites === null) { await banco.query("DELETE FROM navegador_acesso WHERE empresa_id = ? AND setor_id = ?", [empresaId, setorId]); return null; }
            if (!Array.isArray(sites)) throw erro("Dados inválidos.");
            const validos = new Set((await todosOsSites(empresaId)).map((x) => x.id));
            const lista = [...new Set(sites.map(String).filter((id) => validos.has(id)))];
            await banco.query(
                `INSERT INTO navegador_acesso (empresa_id, setor_id, sites, atualizado_por) VALUES (?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE sites = VALUES(sites), atualizado_por = VALUES(atualizado_por)`,
                [empresaId, setorId, JSON.stringify(lista), adminId ?? null]);
            return lista;
        },
    };
}

export const servicoNavegador = criarServicoNavegador();
export { IDS_PADRAO };
