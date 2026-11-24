// Roteador do cliente: o funcionário procura o cliente (nome, CPF ou contrato) e abre o painel do roteador dele já logado.
// Quem entra no roteador é o agente (mesmo servidor, rede interna): a senha de administrador e o IP do cliente nunca chegam ao Workspace.
// Aqui só ficam a busca no SGP, a permissão, o limite de uso e o registro de quem abriu qual contrato.
import { consultarContratosUra } from "./sgpCustomerService.js";
import { registrarAuditoria, AUDIT_LEVELS, AUDIT_TYPES } from "./auditService.js";

const erro = (mensagem, status = 400) => Object.assign(new Error(mensagem), { status });
const somenteDigitos = (v) => String(v ?? "").replace(/\D/g, "");

/** Decide por onde procurar no SGP: CPF/CNPJ (11 ou 14 dígitos), contrato (até 9 dígitos) ou nome (3+ letras). */
export function interpretarBusca(entrada) {
    const texto = String(entrada ?? "").replace(/\s+/g, " ").trim().slice(0, 80);
    if (!texto) throw erro("Digite o nome, o CPF ou o contrato do cliente.");
    const digitos = somenteDigitos(texto);
    const soNumeros = /^[\d.\-\/\s]+$/.test(texto);
    if (soNumeros && (digitos.length === 11 || digitos.length === 14)) return { campo: "cpfcnpj", valor: digitos, tipo: "cpf" };
    if (soNumeros && digitos.length >= 1 && digitos.length <= 9) return { campo: "contrato", valor: digitos, tipo: "contrato" };
    if (soNumeros) throw erro("CPF/CNPJ tem 11 ou 14 números; contrato tem até 9.");
    if (texto.length < 3) throw erro("Digite pelo menos 3 letras do nome.");
    return { campo: "nome", valor: texto, tipo: "nome" };
}

const mascararDocumento = (doc) => {
    const d = somenteDigitos(doc);
    if (d.length === 11) return `•••.${d.slice(3, 6)}.${d.slice(6, 9)}-••`;
    if (d.length === 14) return `••.${d.slice(2, 5)}.${d.slice(5, 8)}/••••-••`;
    return "";
};
const MINUSCULAS = new Set(["da", "de", "do", "das", "dos", "e"]);
const nomeBonito = (n) => {
    const t = String(n ?? "").trim();
    return t && t === t.toUpperCase() ? t.toLowerCase().split(/\s+/).map((p, i) => (i > 0 && MINUSCULAS.has(p) ? p : p.charAt(0).toUpperCase() + p.slice(1))).join(" ") : t;
};
const SITUACOES = [[/suspen/i, "suspenso"], [/cancel/i, "cancelado"], [/inativ/i, "inativo"], [/ativo|habilit|normal/i, "ativo"]];
const situacaoDe = (c) => {
    const bruta = String(c.contratoStatusDisplay ?? c.contratoStatus ?? "");
    return SITUACOES.find(([re]) => re.test(bruta))?.[1] ?? (bruta.toLowerCase() || "desconhecido");
};

/** Só o que a lista precisa: nunca senha, login PPPoE, MAC nem a senha do Wi-Fi que o SGP devolve junto. */
export function resumirContrato(c = {}) {
    return {
        contrato: somenteDigitos(c.contratoId ?? c.contrato ?? c.id).slice(0, 12),
        nome: nomeBonito(c.razaoSocial ?? c.nome ?? "").slice(0, 120),
        documento: mascararDocumento(c.cpfCnpj ?? c.cpfcnpj),
        situacao: situacaoDe(c),
        local: [c.endereco_bairro, c.endereco_cidade].map((x) => String(x ?? "").trim()).filter(Boolean).join(" · ").slice(0, 100),
        plano: String(c.servico_plano ?? c.planointernet ?? "").trim().slice(0, 60),
    };
}

export function criarServicoRoteadorCliente({
    sgp = { consultarContratosUra },
    auditar = registrarAuditoria,
    fetchImpl = fetch,
    agente = {
        url: () => String(process.env.ROUTER_PANEL_URL || "http://127.0.0.1:8796").replace(/\/+$/, ""),
        token: () => process.env.ROUTER_PANEL_TOKEN || "",
        publica: () => String(process.env.ROUTER_PANEL_PUBLIC_URL || "http://192.168.1.133:8796").replace(/\/+$/, ""),
    },
    agora = () => Date.now(),
} = {}) {
    // limite por pessoa: 12 aberturas por minuto (cada uma entra num roteador de verdade)
    const usos = new Map();
    const limitar = (usuarioId) => {
        const t = agora();
        const recentes = (usos.get(usuarioId) ?? []).filter((x) => t - x < 60_000);
        if (recentes.length >= 12) throw erro("Muitas aberturas seguidas. Espere um minuto.", 429);
        recentes.push(t);
        usos.set(usuarioId, recentes);
    };

    const buscar = async (entrada) => {
        const busca = interpretarBusca(entrada);
        let contratos;
        try {
            contratos = await sgp.consultarContratosUra({ [busca.campo]: busca.valor });
        } catch (e) {
            if (e?.statusCode && e.statusCode < 500) throw erro("O SGP recusou a consulta.", 502);
            throw erro("O SGP não respondeu agora. Tente de novo.", 503);
        }
        const vistos = new Set();
        const lista = [];
        for (const c of contratos ?? []) {
            const r = resumirContrato(c);
            if (!r.contrato || vistos.has(r.contrato)) continue;
            vistos.add(r.contrato);
            lista.push(r);
        }
        // contratos ativos primeiro (é neles que o roteador está ligado)
        lista.sort((a, b) => Number(b.situacao === "ativo") - Number(a.situacao === "ativo"));
        return { busca: busca.tipo, clientes: lista.slice(0, 30), total: lista.length };
    };

    const chamarAgente = async (caminho, corpo, timeoutMs) => {
        const token = agente.token();
        if (!token) throw erro("O painel de roteadores não está ligado neste servidor.", 503);
        try {
            const res = await fetchImpl(`${agente.url()}${caminho}`, {
                method: "POST",
                headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
                body: JSON.stringify(corpo),
                signal: AbortSignal.timeout(timeoutMs),
            });
            if (!res.ok) throw new Error(`agente respondeu ${res.status}`);
            return await res.json();
        } catch (e) {
            if (e?.status) throw e;
            throw erro("O agente de roteadores não respondeu. Avise a T.I.", 503);
        }
    };

    const abrir = async (usuario, contrato, { nome = "", req = null } = {}) => {
        const alvo = somenteDigitos(contrato);
        if (!alvo || alvo.length > 12 || String(contrato).trim() !== alvo) throw erro("Contrato inválido.");
        limitar(usuario.id);
        const rotulo = `${String(nome ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, 50)} · contrato ${alvo}`.replace(/^ · /, "");
        const resposta = await chamarAgente("/panel/open", { contractId: alvo, operator: String(usuario.nome ?? usuario.id), label: rotulo }, 100_000);
        // quem abriu qual contrato fica registrado, com ou sem sucesso (nunca o token da sessão)
        await Promise.resolve(auditar({
            usuario, acao: resposta.ok ? "roteador.painel_aberto" : "roteador.painel_negado", entidade: "contrato", entidadeId: alvo,
            tipo: AUDIT_TYPES.SISTEMA, nivel: AUDIT_LEVELS.IMPORTANT, origem: "WORKSPACE",
            metadata: { resultado: resposta.ok ? "ok" : resposta.code ?? "erro", fabricante: resposta.vendor ?? null, modelo: resposta.model ?? null }, req,
        })).catch((e) => console.error("[roteador] auditoria:", e?.message));
        if (!resposta.ok) return { ok: false, code: String(resposta.code ?? "INTERNAL"), message: String(resposta.message ?? "Não foi possível abrir o painel."), vendor: resposta.vendor ?? null, model: resposta.model ?? null };
        return { ok: true, url: `${agente.publica()}/v/${resposta.token}`, contrato: alvo, vendor: resposta.vendor ?? null, model: resposta.model ?? null };
    };

    const fechar = async (usuario, contrato) => {
        const alvo = somenteDigitos(contrato);
        if (!alvo || alvo.length > 12) throw erro("Contrato inválido.");
        const r = await chamarAgente("/panel/close", { contractId: alvo }, 30_000);
        return { ok: Boolean(r.ok) };
    };

    return { buscar, abrir, fechar };
}

export const servicoRoteadorCliente = criarServicoRoteadorCliente();
