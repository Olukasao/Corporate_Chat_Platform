import db from "../db/db.js";

// "Funções": o que cada setor enxerga no Acessa Workspace. Sem configuração salva, o setor vê tudo (como era antes).
// Administradores sempre veem tudo, para ninguém se trancar para fora.
export const MODULOS = [
    { id: "resumo", rotulo: "Resumo", grupo: "Visão geral" },
    { id: "dashboard", rotulo: "Dashboard", grupo: "Visão geral" },
    { id: "assistente", rotulo: "Inteligência Artificial", grupo: "Visão geral" },
    { id: "lembretes", rotulo: "Lembretes", grupo: "Visão geral" },
    { id: "chat", rotulo: "Chat Interno", grupo: "Comunicação" },
    { id: "agenda", rotulo: "Agenda de Técnicos", grupo: "Operação" },
    { id: "contratacoes", rotulo: "Contratações", grupo: "Operação" },
    { id: "chamados", rotulo: "Chamados", grupo: "Operação" },
    { id: "rede", rotulo: "Rede (OLT)", grupo: "Operação" },
    { id: "tools", rotulo: "Ferramentas", grupo: "Operação" },
    { id: "terminal", rotulo: "Terminal", grupo: "Operação" },
    { id: "atendimento", rotulo: "Atendimento (chat com clientes)", grupo: "Operação" },
    { id: "navegador", rotulo: "Navegador", grupo: "Operação" },
    { id: "suporte", rotulo: "Suporte T.I.", grupo: "Operação" },
    { id: "cursos", rotulo: "Cursos", grupo: "Conteúdo" },
    { id: "marketing", rotulo: "Marketing", grupo: "Conteúdo" },
];
const IDS = new Set(MODULOS.map((m) => m.id));

let garantida = null;
export const garantirTabelaFuncoes = () => {
    garantida ??= db.query(`
        CREATE TABLE IF NOT EXISTS workspace_funcoes_setor (
            empresa_id INT NOT NULL,
            setor_id INT NOT NULL,
            modulos TEXT NOT NULL,
            atualizado_por INT NULL,
            atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (empresa_id, setor_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `).catch((e) => { garantida = null; throw e; });
    return garantida;
};

const limpar = (lista) => [...new Set((Array.isArray(lista) ? lista : []).map(String).filter((id) => IDS.has(id)))];

/** Módulos liberados para o usuário, ou null quando não há restrição. */
export const modulosDoUsuario = async (usuario) => {
    if (!usuario || usuario.perfil === "admin") return null;
    let setorId = usuario.setor_id;
    let empresaId = usuario.empresa_id;
    if ((setorId === undefined || empresaId === undefined) && usuario.id) {
        const [r] = await db.query("SELECT setor_id, empresa_id FROM usuarios WHERE id = ?", [usuario.id]);
        setorId = r[0]?.setor_id;
        empresaId = r[0]?.empresa_id;
    }
    if (!setorId) return null;
    await garantirTabelaFuncoes();
    const [rows] = await db.query("SELECT modulos FROM workspace_funcoes_setor WHERE empresa_id = ? AND setor_id = ?", [empresaId, setorId]);
    if (!rows[0]) return null;
    try { return limpar(JSON.parse(rows[0].modulos)); } catch { return null; }
};

export const usuarioTemModulo = async (usuario, modulo) => {
    const lista = await modulosDoUsuario(usuario);
    return lista === null || lista.includes(modulo);
};

export const listarFuncoes = async (empresaId) => {
    await garantirTabelaFuncoes();
    const [setores] = await db.query("SELECT id, nome FROM setores WHERE empresa_id = ? ORDER BY nome ASC", [empresaId]);
    const [config] = await db.query("SELECT setor_id, modulos FROM workspace_funcoes_setor WHERE empresa_id = ?", [empresaId]);
    const [contagem] = await db.query("SELECT setor_id, COUNT(*) AS total FROM usuarios WHERE empresa_id = ? AND deletado_em IS NULL GROUP BY setor_id", [empresaId]);
    const porSetor = new Map(config.map((c) => { try { return [c.setor_id, limpar(JSON.parse(c.modulos))]; } catch { return [c.setor_id, null]; } }));
    const pessoas = new Map(contagem.map((c) => [c.setor_id, Number(c.total)]));
    return {
        modulos: MODULOS,
        setores: setores.map((s) => ({ id: s.id, nome: s.nome, pessoas: pessoas.get(s.id) || 0, modulos: porSetor.get(s.id) ?? null })),
    };
};

/** modulos = null volta ao padrão (vê tudo). */
export const salvarFuncao = async (empresaId, setorId, modulos, adminId) => {
    await garantirTabelaFuncoes();
    const [s] = await db.query("SELECT id FROM setores WHERE id = ? AND empresa_id = ?", [setorId, empresaId]);
    if (!s[0]) { const e = new Error("Setor não encontrado."); e.status = 404; throw e; }
    if (modulos === null) {
        await db.query("DELETE FROM workspace_funcoes_setor WHERE empresa_id = ? AND setor_id = ?", [empresaId, setorId]);
        return null;
    }
    const lista = limpar(modulos);
    await db.query(
        `INSERT INTO workspace_funcoes_setor (empresa_id, setor_id, modulos, atualizado_por) VALUES (?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE modulos = VALUES(modulos), atualizado_por = VALUES(atualizado_por)`,
        [empresaId, setorId, JSON.stringify(lista), adminId ?? null],
    );
    return lista;
};
