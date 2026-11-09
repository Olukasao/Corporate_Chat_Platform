// Dados extras da ficha do cliente na ligação: endereço, financeiro, contatos, anotações, histórico de chamados e conexão.
// Funções puras (sem rede), para testar sem o SGP. Nunca devolve login/senha da Central do Assinante nem o CPF inteiro.

const texto = (v) => (v === null || v === undefined ? "" : String(v).replace(/\s+/g, " ").trim());
const dinheiro = (v) => { const n = Number(String(v ?? "").replace(",", ".")); return Number.isFinite(n) ? Math.round(n * 100) / 100 : 0; };
const DIA = 86_400_000;

/** "25/08/2026 10:49:12" (SGP) ou "2026-08-25" → "2026-08-25"; vazio se não entender. */
export const dataIso = (t) => {
    const s = texto(t);
    let m = /^(\d{2})\/(\d{2})\/(\d{4})/.exec(s);
    if (m) return `${m[3]}-${m[2]}-${m[1]}`;
    m = /^(\d{4})-(\d{2})-(\d{2})/.exec(s);
    return m ? `${m[1]}-${m[2]}-${m[3]}` : "";
};
const ms = (iso) => (iso ? Date.parse(`${iso}T12:00:00Z`) : NaN);

/** CPF/CNPJ mascarado: mostra só o miolo para conferência ("•••.138.358-••"). */
export const mascararDocumento = (bruto) => {
    const d = texto(bruto).replace(/\D/g, "");
    if (d.length === 11) return `•••.${d.slice(3, 6)}.${d.slice(6, 9)}-••`;
    if (d.length === 14) return `••.${d.slice(2, 5)}.${d.slice(5, 8)}/••••-••`;
    return "";
};

const item = (o) => (typeof o === "string" ? texto(o) : texto(o?.contato ?? o?.valor ?? o?.texto ?? o?.conteudo ?? o?.anotacao ?? o?.nome ?? o?.descricao));

/** Endereço, financeiro, contatos e observações do cadastro do contrato (resposta bruta do SGP). */
export function dadosDoCadastro(c = {}) {
    if (!c || typeof c !== "object") return {};
    const rua = texto(c.endereco_logradouro), numero = texto(c.endereco_numero);
    const ll = texto(c.endereco_ll).split(",").map((x) => Number(x.trim()));
    const coordenadas = ll.length === 2 && ll.every(Number.isFinite) && (ll[0] || ll[1]) ? { lat: ll[0], lng: ll[1] } : null;
    const lista = (v) => (Array.isArray(v) ? v : []);
    const contatos = lista(c.telefones).map((t) => ({ tipo: "telefone", valor: item(t) })).concat(lista(c.emails).map((t) => ({ tipo: "email", valor: item(t) }))).filter((t) => t.valor);
    const emAberto = dinheiro(c.contratoValorAberto);
    return {
        endereco: {
            linha: [rua, numero].filter(Boolean).join(", "),
            complemento: texto(c.endereco_complemento),
            bairro: texto(c.endereco_bairro),
            cidade: texto(c.endereco_cidade),
            uf: texto(c.endereco_uf),
            cep: texto(c.endereco_cep),
            referencia: texto(c.endereco_pontoreferencia),
            coordenadas,
        },
        financeiro: {
            emAberto,
            titulosAReceber: Number(c.contratoTitulosAReceber) || 0,
            vencimentoDia: Number(c.cobVencimento) || null,
            promessasMes: Number(c.promessasPagamentoMes) || 0,
            isento: Number(c.cobIsento) === 0 ? true : false,
        },
        clienteDesde: dataIso(c.dataCadastro),
        motivoStatus: texto(c.motivo_status),
        pop: texto(c.popNome),
        planoTv: texto(c.planotv),
        documento: mascararDocumento(c.cpfCnpj ?? c.cpfcnpj),
        contatos,
        etiquetas: lista(c.tags).map(item).filter(Boolean),
        anotacoes: lista(c.anotacoes).map(item).filter(Boolean).map((t) => t.slice(0, 240)).slice(0, 5),
    };
}

/** Histórico dos chamados: reincidência, tempo médio de resolução, assunto mais comum e visita marcada. */
export function analisarChamados(ocorrencias, hoje = Date.now()) {
    if (!Array.isArray(ocorrencias)) return null;
    const abertas = (o) => !texto(o.data_finalizacao) && !/encerr|fechad|finaliz|conclu/i.test(texto(o.status));
    const cad = (o) => ms(dataIso(o.data_cadastro));
    const ultimos30 = ocorrencias.filter((o) => hoje - cad(o) <= 30 * DIA).length;
    const resolvidos = ocorrencias.filter((o) => !abertas(o)).map((o) => (ms(dataIso(o.data_finalizacao)) - cad(o)) / DIA).filter((d) => Number.isFinite(d) && d >= 0);
    const contagem = new Map();
    for (const o of ocorrencias) { const t = texto(o.tipo); if (t) contagem.set(t, (contagem.get(t) || 0) + 1); }
    const [maisComum] = [...contagem].sort((a, b) => b[1] - a[1]);
    const hojeIso = new Date(hoje).toISOString().slice(0, 10);
    const visitas = ocorrencias.filter(abertas).map((o) => ({ data: dataIso(o.data_agendamento), protocolo: texto(o.numero), tipo: texto(o.tipo) })).filter((v) => v.data && v.data >= hojeIso).sort((a, b) => a.data.localeCompare(b.data));
    return {
        ultimos30Dias: ultimos30,
        abertos: ocorrencias.filter(abertas).length,
        tempoMedioDias: resolvidos.length ? Math.round((resolvidos.reduce((s, d) => s + d, 0) / resolvidos.length) * 10) / 10 : null,
        assuntoMaisComum: maisComum && maisComum[1] > 1 ? { tipo: maisComum[0], vezes: maisComum[1] } : null,
        visitaAgendada: visitas[0] || null,
    };
}

/** Média das avaliações do cliente (todas as que o SGP/site registrou no período). */
export function mediaDeAvaliacoes(itens) {
    const notas = (itens || []).map((i) => Number(i.nota)).filter((n) => n >= 1 && n <= 5);
    return notas.length ? { media: Math.round((notas.reduce((s, n) => s + n, 0) / notas.length) * 10) / 10, total: notas.length } : null;
}

/** Equipamento do cliente na OLT Cloud: só o que casa EXATAMENTE com o contrato (o filtro da OLT Cloud também acha "33005" para "3005"). */
export function conexaoDoContrato(equipamentos, contrato) {
    const meu = (equipamentos || []).find((e) => texto(e.external_client_contract_id) === texto(contrato));
    if (!meu) return null;
    const num = (v) => (v === null || v === undefined || v === "" || !Number.isFinite(Number(v)) ? null : Number(v));
    const status = texto(meu.status);
    return {
        status,
        online: /^online$/i.test(status),
        ultimaQueda: texto(meu.last_disconnection) || null,
        onlineDesde: texto(meu.uptime_since) || null,
        sinalOnuDbm: num(meu.device_rx),
        sinalOltDbm: num(meu.olt_rx),
        modelo: texto(meu.model),
        olt: texto(meu.olt),
        porta: [meu.slot, meu.pon, meu.onu_id].every((x) => x !== undefined && x !== null) ? `${meu.slot}/${meu.pon}/${meu.onu_id}` : "",
        leituraEm: texto(meu.last_signal_update) || null,
    };
}
