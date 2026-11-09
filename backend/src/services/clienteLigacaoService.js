// Cartão do cliente na ligação: pelo número que liga (ou para o qual se liga), mostra quem é no SGP, os últimos
// chamados e a última avaliação. O SGP que usamos consulta por contrato/CPF; a ligação número -> contrato vem de:
//  1) vínculos já aprendidos (tabela telefone_cliente, criada na primeira vez que alguém vincula);
//  2) uma tentativa no SGP por celular/telefone, aceita SÓ se o telefone do cadastro bater com o número.
import { analisarChamados, conexaoDoContrato, dadosDoCadastro, mediaDeAvaliacoes } from "./fichaClienteDados.js";
import { equipamentosDoContrato, oltCloudConfigurada } from "./oltCloudService.js";
import db from "../db/db.js";
import { consultarContratosUra, getCustomerDetails, listarOcorrenciasUra } from "./sgpCustomerService.js";
import { criarServicoAvaliacoes } from "./avaliacoesSiteService.js";
import { indiceTelefones, parteLocal } from "./indiceTelefonesService.js";

// Curto de propósito: um chamado aberto agora há pouco tem que aparecer na ficha da próxima ligação.
const CACHE_MS = 20_000;
const SEM_CACHE_MS = 60_000;

/** Telefone brasileiro com DDD (10 ou 11 dígitos); null para ramal, curto demais, lixo ou número sem DDD (o DDD nunca é presumido). */
export function normalizarTelefone(bruto) {
    let d = String(bruto ?? "").replace(/\D/g, "");
    if (d.startsWith("55") && (d.length === 12 || d.length === 13)) d = d.slice(2);
    if (d.startsWith("0") && (d.length === 11 || d.length === 12)) d = d.slice(1);
    return d.length === 10 || d.length === 11 ? d : null;
}

/** O número foi discado sem DDD (8 ou 9 dígitos)? Aí o DDD é um palpite e vale tentar outros. */
export function faltaDdd(bruto) {
    let d = String(bruto ?? "").replace(/\D/g, "");
    if (d.startsWith("55") && (d.length === 12 || d.length === 13)) d = d.slice(2);
    if (d.startsWith("0") && (d.length === 11 || d.length === 12)) d = d.slice(1);
    return (d.length === 9 && d.startsWith("9")) || (d.length === 8 && /^[2-5]/.test(d));
}
/** Dois telefones são o mesmo se os últimos 8 dígitos coincidem (ignora DDD, 9º dígito e formatação). */
export function mesmoTelefone(a, b) {
    const x = String(a ?? "").replace(/\D/g, "").slice(-8);
    const y = String(b ?? "").replace(/\D/g, "").slice(-8);
    return x.length === 8 && x === y;
}

const CAMPOS_TELEFONE = /cel|tel|fone|whats|contato/i;
const CAMPOS_NAO_TELEFONE = /mail/i;
/** Todos os valores de telefone que o contrato do SGP traz (celular, celular1, telefone, contatos…). */
export function telefonesDoContrato(contrato) {
    const achados = [];
    const visitar = (valor, chave = "") => {
        if (valor == null) return;
        if (Array.isArray(valor)) return valor.forEach((v) => visitar(v, chave));
        if (typeof valor === "object") return Object.entries(valor).forEach(([k, v]) => visitar(v, CAMPOS_NAO_TELEFONE.test(k) ? k : (CAMPOS_TELEFONE.test(k) ? k : chave)));
        if (CAMPOS_TELEFONE.test(chave) && !CAMPOS_NAO_TELEFONE.test(chave)) achados.push(String(valor));
    };
    visitar(contrato);
    return achados;
}

const prontas = new WeakMap();
export const garantirTabelaTelefones = (banco = db) => {
    if (!prontas.has(banco)) prontas.set(banco, banco.query(`
        CREATE TABLE IF NOT EXISTS telefone_cliente (
            empresa_id INT NOT NULL,
            telefone VARCHAR(11) NOT NULL,
            contrato VARCHAR(40) NOT NULL,
            nome VARCHAR(160) NOT NULL DEFAULT '',
            vinculado_por INT NULL,
            atualizado_em TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (empresa_id, telefone)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `).catch((e) => { prontas.delete(banco); throw e; }));
    return prontas.get(banco);
};

const dataBr = (t) => { const m = /^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?/.exec(String(t ?? "")); return m ? Date.UTC(+m[3], +m[2] - 1, +m[1], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0)) : 0; };
/** Campos do contrato do SGP que usamos para escolher o principal e saber se são do mesmo cliente. */
export function descreverContrato(c = {}) {
    return {
        id: String(c.contratoId ?? c.contrato ?? c.id ?? ""),
        cliente: String(c.clienteId ?? c.cpfCnpj ?? c.cpfcnpj ?? c.razaoSocial ?? ""),
        ativo: /ativo/i.test(String(c.contratoStatusDisplay ?? c.contratoStatus ?? "")) && !/inativ|cancel|suspen/i.test(String(c.contratoStatusDisplay ?? c.contratoStatus ?? "")),
        cadastro: dataBr(c.dataCadastro),
        situacao: String(c.contratoStatusDisplay ?? c.contratoStatus ?? ""),
    };
}

const resumoOcorrencia = (o) => ({
    protocolo: String(o.numero ?? ""),
    tipo: String(o.tipo ?? ""),
    metodo: String(o.metodo ?? ""),
    status: String(o.status ?? ""),
    abertoEm: String(o.data_cadastro ?? ""),
    encerradoEm: String(o.data_finalizacao ?? ""),
    assunto: String(o.conteudo ?? "").replace(/\s+/g, " ").trim().slice(0, 140),
});

export function criarServicoClienteLigacao({
    sgp = { consultarContratosUra, getCustomerDetails, listarOcorrenciasUra },
    olt = { configurada: oltCloudConfigurada, equipamentosDoContrato },
    avaliacoes = criarServicoAvaliacoes(),
    indice = indiceTelefones,
    agora = () => Date.now(),
    banco = db,
} = {}) {
    const cache = new Map();
    const guardar = (chave, dados, ms) => { cache.set(chave, { dados, ate: agora() + ms }); if (cache.size > 300) cache.clear(); return dados; };
    const lembrar = (chave) => { const c = cache.get(chave); return c && c.ate > agora() ? c.dados : null; };

    async function contratoAprendido(empresaId, telefone) {
        await garantirTabelaTelefones(banco);
        const [rows] = await banco.query("SELECT contrato, nome FROM telefone_cliente WHERE empresa_id = ? AND telefone = ?", [empresaId, telefone]);
        return rows[0] || null;
    }

    // O SGP aceita a busca pelo campo "telefone" (com DDD); "celular" não funciona. Mantemos os dois por segurança, o que funciona primeiro.
    async function contratoPeloSgp(telefone) {
        let contratos = [];
        try { contratos = await sgp.consultarContratosUra({ telefone }); } catch { return null; }
        // Só vale contrato cujo cadastro realmente tem esse telefone (evita mostrar a pessoa errada).
        const confere = contratos.filter((c) => telefonesDoContrato(c).some((t) => mesmoTelefone(t, telefone))).map(descreverContrato).filter((c) => c.id);
        if (!confere.length) return null;
        const clientes = new Set(confere.map((c) => c.cliente));
        const ordenados = [...confere].sort((a, b) => Number(b.ativo) - Number(a.ativo) || b.cadastro - a.cadastro);
        // Vários contratos do MESMO cliente viram uma ficha só; clientes diferentes com o mesmo telefone pedem confirmação.
        return { telefone, contratos: ordenados.map((c) => c.id), situacao: ordenados[0].situacao, origem: "sgp", varios: clientes.size > 1 ? ordenados.map((c) => c.id) : null };
    }

    async function resumoDoCliente(contratos, situacaoSgp = "") {
        const [principal] = contratos;
        const comLimite = (promessa, limiteMs) => Promise.race([promessa, new Promise((_, no) => setTimeout(() => no(new Error("tempo esgotado")), limiteMs).unref?.())]);
        const [detalhe, nota, cadastro, equip, ...ocorr] = await Promise.allSettled([
            sgp.getCustomerDetails(principal),
            avaliacoes.listar("365d"),
            sgp.consultarContratosUra({ contrato: principal }),
            olt.configurada() ? comLimite(olt.equipamentosDoContrato(principal), 4000) : Promise.resolve([]),
            ...contratos.slice(0, 3).map((c) => sgp.listarOcorrenciasUra(c)),
        ]);
        const c = detalhe.status === "fulfilled" ? detalhe.value.customer : null;
        const listas = ocorr.filter((o) => o.status === "fulfilled").map((o) => o.value);
        const todas = ocorr.length && listas.length ? listas.flat() : null;
        const ultimas = todas ? [...todas].sort((a, b) => String(b.data_cadastro).localeCompare(String(a.data_cadastro)) || Number(b.id) - Number(a.id)).slice(0, 5).map(resumoOcorrencia) : null;
        const meus = new Set(contratos.map(String));
        const avaliacao = nota.status === "fulfilled" ? (nota.value.itens.find((i) => meus.has(String(i.contrato))) ?? null) : undefined;
        const bruto = cadastro.status === "fulfilled" ? (cadastro.value || []).find((x) => String(x.contratoId ?? x.contrato ?? x.id ?? "") === String(principal)) : null;
        const minhasNotas = nota.status === "fulfilled" ? nota.value.itens.filter((i) => meus.has(String(i.contrato))) : null;
        return {
            ...dadosDoCadastro(bruto),
            historico: analisarChamados(todas, agora()),
            mediaAvaliacoes: minhasNotas ? mediaDeAvaliacoes(minhasNotas) : undefined,
            conexao: equip.status === "fulfilled" ? conexaoDoContrato(equip.value, principal) : undefined,
            contrato: String(principal),
            contratos: contratos.map(String),
            nome: c?.name || "",
            plano: c?.planName || "",
            cidade: c?.city || "",
            situacao: situacaoSgp || todas?.[0]?.contrato_status || "",
            chamados: ultimas,
            totalChamados: todas ? todas.length : null,
            ultimaAvaliacao: avaliacao ? { nota: avaliacao.nota, comentario: avaliacao.comentario, respondidoEm: avaliacao.respondidoEm, tecnico: avaliacao.tecnico } : avaliacao,
        };
    }

    return {
        /** `ddd` só vale quando a PESSOA informou (número discado sem DDD); nunca é adivinhado. */
        async porTelefone(empresaId, numero, ddd = null) {
            const dddInformado = /^[1-9]\d$/.test(String(ddd ?? "")) ? String(ddd) : null;
            let completo = numero;
            if (faltaDdd(numero)) {
                const local = String(numero).replace(/\D/g, "").replace(/^0+/, "");
                if (dddInformado) completo = `${dddInformado}${local}`;
                else {
                    // Sem DDD: o índice de telefones diz com qual DDD esse número existe. Um só: segue; vários: a pessoa escolhe; nenhum: digita.
                    const candidatos = parteLocal(local) ? await indice.candidatos(empresaId, local).catch(() => []) : [];
                    if (candidatos.length === 1) completo = candidatos[0];
                    else return { valido: true, semDdd: true, encontrado: false, ...(candidatos.length > 1 ? { candidatos: candidatos.map((t) => ({ ddd: t.slice(0, 2), telefone: t })) } : {}) };
                }
            }
            const telefone = normalizarTelefone(completo);
            if (!telefone) return faltaDdd(numero) ? { valido: true, semDdd: true, encontrado: false } : { valido: false };
            const chave = `${empresaId}:${telefone}`;
            const guardado = lembrar(chave);
            if (guardado) return guardado;
            let achado = null;
            const aprendido = await contratoAprendido(empresaId, telefone);
            if (aprendido) achado = { contratos: [aprendido.contrato], origem: "vinculo" };
            else {
                achado = await contratoPeloSgp(telefone);
            }
            if (!achado) return guardar(chave, { valido: true, telefone, encontrado: false }, SEM_CACHE_MS);
            // Número identificado: guarda no índice, para as próximas ligações acharem mesmo discadas sem DDD.
            void indice.aprender(empresaId, achado.telefone || telefone).catch(() => undefined);
            const resumo = await resumoDoCliente(achado.contratos, achado.situacao);
            return guardar(chave, { valido: true, telefone: achado.telefone || telefone, encontrado: true, origem: achado.origem, outrosContratos: achado.varios || undefined, cliente: resumo }, CACHE_MS);
        },

        /** Liga o número a um contrato (e lembra para as próximas ligações). Confere que o contrato existe no SGP. */
        async vincular(empresaId, numero, contrato, usuarioId) {
            const telefone = normalizarTelefone(numero);
            const alvo = String(contrato ?? "").replace(/\D/g, "").slice(0, 20);
            if (!telefone || !alvo) { const e = new Error("Informe um telefone e um contrato válidos."); e.status = 400; throw e; }
            let detalhe;
            try { detalhe = await sgp.getCustomerDetails(alvo); } catch { const e = new Error("Contrato não encontrado no SGP."); e.status = 404; throw e; }
            await garantirTabelaTelefones(banco);
            await banco.query(
                `INSERT INTO telefone_cliente (empresa_id, telefone, contrato, nome, vinculado_por) VALUES (?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE contrato = VALUES(contrato), nome = VALUES(nome), vinculado_por = VALUES(vinculado_por)`,
                [empresaId, telefone, alvo, String(detalhe.customer?.name || "").slice(0, 160), usuarioId ?? null],
            );
            cache.delete(`${empresaId}:${telefone}`);
            void indice.aprender(empresaId, telefone).catch(() => undefined);
            return this.porTelefone(empresaId, numero);
        },

        async desvincular(empresaId, numero) {
            const telefone = normalizarTelefone(numero);
            if (!telefone) return;
            await garantirTabelaTelefones(banco);
            await banco.query("DELETE FROM telefone_cliente WHERE empresa_id = ? AND telefone = ?", [empresaId, telefone]);
            cache.delete(`${empresaId}:${telefone}`);
        },
    };
}
