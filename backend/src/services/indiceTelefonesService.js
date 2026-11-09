// Índice local de telefones de clientes: SÓ os números (com DDD), sem nome nem contrato. Serve para descobrir o DDD quando o
// operador disca sem DDD: a busca acha o número completo aqui e só então consulta o SGP (que exige o DDD).
// Alimentado de duas formas: exportação noturna de telefones do SGP ("sgp") e números já identificados em ligações ("aprendido").
import db from "../db/db.js";
import { sgpWebGet } from "./sgpWebTrafficService.js";
import { garantirTabelasIa, gravarConfig, hojeSaoPaulo, lerConfig } from "./iaAdminService.js";
import { relogioSaoPaulo } from "./briefingService.js";

const EXPORT_PATH = "/admin/cliente/search/?tipoq=cliente&botao_consulta=Consultar&printcsvphone=true";
// A exportação da base inteira passa de 5 minutos no SGP; por ano de cadastro cada pedido leva de segundos a ~1 minuto.
const ANO_INICIAL = Number(process.env.INDICE_ANO_INICIAL || 2012);
const PAUSA_ENTRE_PEDIDOS_MS = 2000;

/** Exporta os telefones por ano de cadastro, em sequência (gentil com o SGP). Qualquer ano que falhar derruba tudo: nada é aplicado pela metade. */
export async function baixarCsvPorAno({ ler = (caminho) => sgpWebGet(caminho, { timeoutMs: 4 * 60_000 }), anoFinal = new Date().getFullYear(), pausa = PAUSA_ENTRE_PEDIDOS_MS } = {}) {
    const partes = [];
    for (let ano = ANO_INICIAL; ano <= anoFinal; ano++) {
        const r = await ler(`${EXPORT_PATH}&data_cadastro_inicial=01/01/${ano}&data_cadastro_final=31/12/${ano}`);
        const html = String(r.html);
        const ehPagina = /<html|<!doctype/i.test(html.slice(0, 200));
        // Ano sem clientes: o SGP devolve a própria tela de busca, não um CSV vazio. Login, erro ou qualquer outra página: falha.
        const telaDeBusca = ehPagina && /id="form"/.test(html) && !/id_username|accounts\/login/i.test(html);
        if (r.status !== 200 || (ehPagina && !telaDeBusca)) throw Object.assign(new Error(`O SGP não devolveu o CSV de ${ano} (HTTP ${r.status}).`), { status: 502 });
        if (!telaDeBusca) partes.push(partes.length === 0 ? html : html.split(/\r?\n/).slice(1).join("\n"));
        if (pausa && ano < anoFinal) await new Promise((res) => setTimeout(res, pausa));
    }
    return partes.join("\n");
}
const LOTE = 1000;
const HORA_PADRAO = "03:30";

/** Divide uma linha de CSV respeitando aspas. */
export function dividirCsv(linha) {
    const campos = []; let atual = ""; let aspas = false;
    for (let i = 0; i < linha.length; i++) {
        const c = linha[i];
        if (aspas) { if (c === '"') { if (linha[i + 1] === '"') { atual += '"'; i++; } else aspas = false; } else atual += c; }
        else if (c === '"') aspas = true;
        else if (c === ",") { campos.push(atual); atual = ""; }
        else atual += c;
    }
    campos.push(atual);
    return campos;
}

/** Telefones válidos (10 ou 11 dígitos, com DDD) da coluna "Celular" do CSV do SGP. Descarta nomes e o resto. */
export function telefonesDoCsv(csv) {
    const linhas = String(csv ?? "").split(/\r?\n/).filter(Boolean);
    if (!linhas.length) return [];
    const cab = dividirCsv(linhas[0]).map((x) => x.trim().toLowerCase());
    const col = Math.max(0, cab.findIndex((x) => /celular|telefone|fone/.test(x)));
    const unicos = new Set();
    for (const l of linhas.slice(1)) {
        let d = String(dividirCsv(l)[col] ?? "").replace(/\D/g, "");
        if (d.startsWith("55") && (d.length === 12 || d.length === 13)) d = d.slice(2);
        if (d.startsWith("0") && (d.length === 11 || d.length === 12)) d = d.slice(1);
        if ((d.length === 10 && /^[1-9]{2}[2-5]/.test(d)) || (d.length === 11 && /^[1-9]{2}9/.test(d))) unicos.add(d);
    }
    return [...unicos];
}

/** Parte do número sem DDD (8 ou 9 dígitos) vinda de um número discado; null se não for local. */
export const parteLocal = (digitos) => {
    const d = String(digitos ?? "").replace(/\D/g, "");
    return (d.length === 9 && d.startsWith("9")) || (d.length === 8 && /^[2-5]/.test(d)) ? d : null;
};

export function criarIndiceTelefones({ banco = db, baixarCsv = baixarCsvPorAno, agora = () => Date.now(), registrar = (empresaId, iso) => gravarConfig(empresaId, "indice_telefones_em", iso) } = {}) {
    let pronta = null;
    const rodando = new Set(); const ultimoErro = new Map();
    const garantir = () => {
        pronta ??= banco.query(`
            CREATE TABLE IF NOT EXISTS telefone_indice (
                empresa_id INT NOT NULL,
                telefone VARCHAR(11) NOT NULL,
                fonte VARCHAR(10) NOT NULL DEFAULT 'sgp',
                atualizado_em DATETIME NOT NULL,
                PRIMARY KEY (empresa_id, telefone),
                KEY idx_telefone_indice_fonte (empresa_id, fonte, atualizado_em)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`).catch((e) => { pronta = null; throw e; });
        return pronta;
    };
    // O banco guarda DATETIME sem milissegundos: usar sempre segundos inteiros, senão a limpeza apaga o que acabou de entrar.
    const quando = () => new Date(Math.floor(agora() / 1000) * 1000);

    return {
        /** Números completos do índice que terminam com esta parte local (8 ou 9 dígitos). Vários DDDs possíveis. */
        async candidatos(empresaId, local) {
            const p = parteLocal(local);
            if (!p) return [];
            await garantir();
            const [rows] = await banco.query("SELECT telefone FROM telefone_indice WHERE empresa_id = ? AND RIGHT(telefone, ?) = ? LIMIT 20", [empresaId, p.length, p]);
            return rows.map((r) => String(r.telefone));
        },

        /** Guarda um número (com DDD) que acabou de ser identificado numa ligação. */
        async aprender(empresaId, telefone) {
            if (!/^\d{10,11}$/.test(String(telefone))) return;
            await garantir();
            await banco.query("INSERT IGNORE INTO telefone_indice (empresa_id, telefone, fonte, atualizado_em) VALUES (?, ?, 'aprendido', ?)", [empresaId, telefone, quando()]);
        },

        /** Baixa a exportação do SGP e troca a parte "sgp" do índice. Se vier pouca coisa, não apaga nada. */
        async atualizar(empresaId) {
            await garantir();
            const numeros = telefonesDoCsv(await baixarCsv());
            const [antes] = await banco.query("SELECT COUNT(*) AS n FROM telefone_indice WHERE empresa_id = ? AND fonte = 'sgp'", [empresaId]);
            const anterior = Number(antes[0].n);
            if (numeros.length < 50 || (anterior > 0 && numeros.length < anterior * 0.5)) {
                const e = new Error(`A exportação do SGP veio com ${numeros.length} números (antes: ${anterior}); mantive o índice como estava.`);
                e.status = 502; throw e;
            }
            const marca = quando();
            for (let i = 0; i < numeros.length; i += LOTE) {
                const lote = numeros.slice(i, i + LOTE);
                await banco.query(
                    `INSERT INTO telefone_indice (empresa_id, telefone, fonte, atualizado_em) VALUES ${lote.map(() => "(?, ?, 'sgp', ?)").join(",")}
                     ON DUPLICATE KEY UPDATE fonte = IF(fonte = 'aprendido', 'sgp', fonte), atualizado_em = VALUES(atualizado_em)`,
                    lote.flatMap((t) => [empresaId, t, marca]),
                );
            }
            const [del] = await banco.query("DELETE FROM telefone_indice WHERE empresa_id = ? AND fonte = 'sgp' AND atualizado_em < ?", [empresaId, marca]);
            await registrar(empresaId, marca.toISOString()).catch(() => undefined);
            return { numeros: numeros.length, removidos: Number(del.affectedRows || 0) };
        },

        async estatisticas(empresaId) {
            await garantir();
            const [r] = await banco.query("SELECT COUNT(*) AS total FROM telefone_indice WHERE empresa_id = ?", [empresaId]);
            const cfg = await lerConfig(empresaId).catch(() => ({}));
            return { total: Number(r[0].total), atualizadoEm: cfg.indice_telefones_em || null, atualizando: rodando.has(empresaId), erro: ultimoErro.get(empresaId) || null };
        },

        /** Começa a atualização em segundo plano (leva alguns minutos) e devolve na hora. */
        iniciarAtualizacao(empresaId) {
            if (rodando.has(empresaId)) return false;
            rodando.add(empresaId); ultimoErro.delete(empresaId);
            this.atualizar(empresaId)
                .catch((e) => { ultimoErro.set(empresaId, String(e?.message || "Falhou").slice(0, 200)); console.error("[telefones] atualização manual falhou:", e?.message); })
                .finally(() => rodando.delete(empresaId));
            return true;
        },
    };
}

export const indiceTelefones = criarIndiceTelefones();

/** Atualiza uma vez por dia, depois da hora combinada (padrão 03:30), mesmo se o servidor reiniciar. */
export function iniciarIndiceTelefones({ empresaId = 1, indice = indiceTelefones, intervaloMs = 60_000, hora = HORA_PADRAO } = {}) {
    const tick = async () => {
        try {
            if (relogioSaoPaulo().hora < hora) return;
            await garantirTabelasIa();
            const hoje = hojeSaoPaulo();
            const cfg = await lerConfig(empresaId);
            if (cfg.indice_telefones_dia === hoje) return;
            await gravarConfig(empresaId, "indice_telefones_dia", hoje); // marca antes: falha não repete o dia todo em loop
            const r = await indice.atualizar(empresaId);
            console.log(`[telefones] índice atualizado: ${r.numeros} números`);
        } catch (e) { console.error("[telefones] não atualizei o índice:", e?.message); }
    };
    const timer = setInterval(tick, intervaloMs);
    timer.unref?.();
    return () => clearInterval(timer);
}
