import test from "node:test";
import assert from "node:assert/strict";

process.env.OLTCLOUD_BASE_URL = "https://olt.example.test";
process.env.OLTCLOUD_TOKEN = "token-fixo";

const { incidenteRelevante, minimoClientesIncidente, listarIncidentesAtivos, listarEquipamentosOffline, incidenteAtivo, normalizarAlerta, oltCloudConfigurada, resumirEquipamentos, equipamentoAfetado, obterPanorama, contarClientesReais, enriquecerComContratos } =
    await import("../src/services/oltCloudService.js");

const resposta = (corpo, status = 200) => ({ ok: status < 400, status, json: async () => corpo });

test("só incidentes ativos entram, com PON caída primeiro e maior impacto antes", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async (url, opcoes) => {
        assert.equal(opcoes.headers.Authorization, "Bearer token-fixo");
        assert.equal(opcoes.method, "GET");
        return resposta({ data: [
            { id: "1", alert_type: "no_power", olt_name: "OLT A", initial_date: "2026-10-22T10:00:00Z", active_devices_count: 5 },
            { id: "2", alert_type: "pon_loss", olt_name: "OLT A", pon: "3", slot_pon: "1", initial_date: "2026-10-22T10:05:00Z", active_devices_count: 20, total_devices_count: 40 },
            { id: "3", alert_type: "cto_loss", end_date: "2026-10-22T10:30:00Z", active_devices_count: 4 },
            { id: "4", alert_type: "cto_loss", ignored: true, active_devices_count: 9 },
            { id: "5", alert_type: "cto_loss", active_devices_count: 0 },
            { id: "6", alert_type: "cto_loss", cto_name: "CTO 7", active_devices_count: 8 },
        ] });
    };
    try {
        assert.equal(oltCloudConfigurada(), true);
        const { incidentes } = await listarIncidentesAtivos({ forcar: true });
        assert.deepEqual(incidentes.map((i) => i.id), ["2", "6", "1"]);
        assert.equal(incidentes[0].totalDispositivos, 40);
    } finally {
        globalThis.fetch = original;
    }
});

test("equipamentos: segue a paginação e devolve só os offline", async () => {
    const original = globalThis.fetch;
    const urls = [];
    globalThis.fetch = async (url) => {
        urls.push(String(url));
        if (urls.length === 1) return resposta({ data: [{ external_client_contract_id: "10", status: "OFFLINE", serial_number: "A" }, { external_client_contract_id: "11", status: "online" }], next: "https://olt.example.test/api/v2/ftth/equipment/list?page=2" });
        return resposta({ data: [{ external_client_contract_id: "12", status: "offline", serial_number: "B", last_disconnection: "2026-10-22T10:00:00Z" }] });
    };
    try {
        const lista = await listarEquipamentosOffline({ oltId: "9", slotPon: "1", pon: "3", ponId: "" });
        assert.deepEqual(lista.map((e) => e.contrato), ["10", "12"]);
        assert.match(urls[0], /olt_id=9/);
        assert.match(urls[0], /slot=1/);
    } finally {
        globalThis.fetch = original;
    }
});

test("recusa seguir link de paginação para outro domínio", async () => {
    const original = globalThis.fetch;
    let chamadas = 0;
    globalThis.fetch = async () => {
        chamadas += 1;
        return resposta({ data: [], next: "https://evil.example/steal" });
    };
    try {
        await assert.rejects(() => listarEquipamentosOffline({ oltId: "9", ponId: "3" }));
        assert.equal(chamadas, 1);
    } finally {
        globalThis.fetch = original;
    }
});

test("critérios de incidente ativo", () => {
    assert.equal(incidenteAtivo(normalizarAlerta({ id: "x" })), true);
    assert.equal(incidenteAtivo(normalizarAlerta({ id: "x", end_date: "2026-01-01" })), false);
    assert.equal(incidenteAtivo(normalizarAlerta({ id: "x", ignored: true })), false);
    assert.equal(incidenteAtivo(normalizarAlerta({ id: "x", active_devices_count: 0 })), false);
});

test("alertas: com milhares de registros lê as ÚLTIMAS páginas (a API lista do mais antigo ao mais novo)", async () => {
    const original = globalThis.fetch;
    const urls = [];
    globalThis.fetch = async (url) => {
        urls.push(String(url));
        const u = new URL(String(url));
        if (u.searchParams.get("page_size") === "1") return resposta({ count: 1234, results: [{ id: "1" }] });
        const pagina = Number(u.searchParams.get("page"));
        if (pagina === 3) return resposta({ count: 1234, results: [{ id: "9", alert_type: "cto_no_power", cto_name: "CTO 1", active_devices_count: 4 }] });
        if (pagina === 2) return resposta({ count: 1234, results: [{ id: "8", alert_type: "pon_loss", pon: "4", slot_pon: "1/4", active_devices_count: 10 }, { id: "7", alert_type: "pon_loss", end_date: "2026-10-01" }] });
        throw new Error(`pagina inesperada ${pagina}`);
    };
    try {
        const { incidentes } = await listarIncidentesAtivos({ forcar: true });
        assert.deepEqual(incidentes.map((i) => i.id), ["8", "9"]);
        const paginasLidas = urls.map((x) => new URL(x).searchParams.get("page")).filter(Boolean);
        assert.deepEqual(paginasLidas.sort(), ["2", "3"]);
    } finally {
        globalThis.fetch = original;
    }
});

test("status reais da OLT Cloud: só 'Online' é saudável", () => {
    assert.equal(equipamentoAfetado("Online"), false);
    assert.equal(equipamentoAfetado("Sem Energia"), true);
    assert.equal(equipamentoAfetado("LOSS"), true);
    assert.equal(equipamentoAfetado("offline"), true);
    assert.equal(equipamentoAfetado(""), false);
});

test("resumo por OLT e PON soma sem energia e LOSS", () => {
    const eq = (olt, slot, pon) => ({ olt, slot, pon });
    const r = resumirEquipamentos(
        [eq("A", "1", "2"), eq("A", "1", "2"), eq("A", "1", "3"), eq("B", "4", "1")],
        [eq("A", "1", "2"), eq("B", "4", "1"), eq("B", "4", "1")],
    );
    assert.deepEqual(r.porOlt.map((o) => [o.olt, o.semEnergia, o.loss]), [["A", 3, 1], ["B", 1, 2]]);
    assert.deepEqual(r.pons[0], { olt: "A", slot: "1", pon: "2", semEnergia: 2, loss: 1 });
    assert.equal(r.pons.length, 3);
});

test("panorama: totais por estado a partir do equipment/list", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async (url) => {
        const u = new URL(String(url));
        const status = u.searchParams.get("status");
        const so1 = u.searchParams.get("page_size") === "1";
        if (so1 && !status) return resposta({ count: 100, results: [{}] });
        if (so1 && status === "Online") return resposta({ count: 90, results: [{}] });
        if (status === "Sem Energia") return resposta({ count: 2, results: [{ olt: "A", slot: "1", pon: "2" }, { olt: "A", slot: "1", pon: "2" }] });
        if (status === "LOSS") return resposta({ count: 1, results: [{ olt: "B", slot: "3", pon: "1" }] });
        throw new Error("consulta inesperada " + u.search);
    };
    try {
        const p = await obterPanorama({ forcar: true });
        assert.equal(p.total, 100);
        assert.equal(p.online, 90);
        assert.equal(p.semEnergia, 2);
        assert.equal(p.loss, 1);
        assert.equal(p.porOlt[0].olt, "A");
        assert.equal(p.totalPons, 2);
    } finally {
        globalThis.fetch = original;
    }
});

test("incidente pequeno (1 cliente afetado) não entra na lista nem nos avisos", async () => {
    delete process.env.OLT_MIN_CLIENTES_INCIDENTE;
    assert.equal(minimoClientesIncidente(), 2);
    assert.equal(incidenteRelevante(normalizarAlerta({ id: "a", total_devices_count: 1, active_devices_count: 1 })), false); // 1 de 1
    assert.equal(incidenteRelevante(normalizarAlerta({ id: "b", total_devices_count: 20, active_devices_count: 1 })), false);
    assert.equal(incidenteRelevante(normalizarAlerta({ id: "c", total_devices_count: 5, active_devices_count: 2 })), true);
    assert.equal(incidenteRelevante(normalizarAlerta({ id: "d" })), true); // sem contagem: mantém
    process.env.OLT_MIN_CLIENTES_INCIDENTE = "5";
    assert.equal(incidenteRelevante(normalizarAlerta({ id: "e", active_devices_count: 4 })), false);
    assert.equal(incidenteRelevante(normalizarAlerta({ id: "f", active_devices_count: 5 })), true);
    delete process.env.OLT_MIN_CLIENTES_INCIDENTE;

    const original = globalThis.fetch;
    globalThis.fetch = async () => resposta({ data: [
        { id: "1", alert_type: "pon_loss", pon: "1", slot_pon: "1/1", total_devices_count: 1, active_devices_count: 1 },
        { id: "2", alert_type: "pon_loss", pon: "2", slot_pon: "1/2", total_devices_count: 8, active_devices_count: 6 },
    ] });
    try {
        const { incidentes } = await listarIncidentesAtivos({ forcar: true });
        assert.deepEqual(incidentes.map((i) => i.id), ["2"]);
    } finally {
        globalThis.fetch = original;
    }
});

test("clientes reais: só conta equipamento com contrato, nunca mais que o alerta e informa quantos não têm contrato", () => {
    const eq = [
        { contrato: "101", status: "LOSS" }, { contrato: "102", status: "Sem Energia" }, { contrato: "102", status: "LOSS" }, // 2 contratos (102 repetido)
        { contrato: "", status: "LOSS" }, { contrato: "  ", status: "LOSS" }, { contrato: "", status: "Sem Energia" }, // sem contrato
        { contrato: "103", status: "Online" }, { contrato: "", status: "Online" },
    ];
    const r = contarClientesReais({ dispositivosAtivos: 6, totalDispositivos: 8 }, eq);
    assert.deepEqual(r, { dispositivosAtivos: 2, totalDispositivos: 3, semContrato: 4, dispositivosAtivosOlt: 6, totalDispositivosOlt: 8 });
    // a PON tem mais gente offline que o alerta cobre: nunca passa do que o alerta diz
    const muitos = Array.from({ length: 10 }, (_, k) => ({ contrato: String(200 + k), status: "LOSS" }));
    assert.equal(contarClientesReais({ dispositivosAtivos: 4, totalDispositivos: 12 }, muitos).dispositivosAtivos, 4);
    // alerta sem contagem: usa o que a PON mostra
    assert.deepEqual(contarClientesReais({ dispositivosAtivos: null, totalDispositivos: null }, eq).dispositivosAtivos, 2);
    // ninguem com contrato: 0 clientes reais
    assert.equal(contarClientesReais({ dispositivosAtivos: 5, totalDispositivos: 5 }, [{ contrato: "", status: "LOSS" }]).dispositivosAtivos, 0);
});

test("incidente de PON troca a contagem do alerta pela de clientes com contrato; CTO e falha na lista mantêm a do alerta", async () => {
    const original = globalThis.fetch;
    const equipamentos = [
        { serial_number: "a", status: "LOSS", external_client_contract_id: "11" },
        { serial_number: "b", status: "LOSS", external_client_contract_id: "" },
        { serial_number: "c", status: "LOSS", external_client_contract_id: null },
        { serial_number: "d", status: "Online", external_client_contract_id: "12" },
    ];
    globalThis.fetch = async (url) => {
        if (String(url).includes("olt_id=OLT9")) return resposta({ data: equipamentos });
        return resposta({ data: [] });
    };
    try {
        const pon = { id: "p", tipo: "pon_loss", oltId: "OLT9", slotPon: "1/2", pon: "2", dispositivosAtivos: 3, totalDispositivos: 4 };
        const cto = { id: "c", tipo: "cto_loss", oltId: "OLT9", slotPon: "1/2", pon: "2", dispositivosAtivos: 3, totalDispositivos: 4 };
        const semLista = { id: "x", tipo: "pon_down", oltId: "OLT-FALHA", slotPon: "1/3", pon: "3", dispositivosAtivos: 7, totalDispositivos: 9 };
        const [a, b, c] = await enriquecerComContratos([pon, cto, semLista]);
        assert.equal(a.dispositivosAtivos, 1);
        assert.equal(a.totalDispositivos, 2);
        assert.equal(a.semContrato, 2);
        assert.equal(a.dispositivosAtivosOlt, 3);
        assert.equal(b.dispositivosAtivos, 3); // CTO: a lista da PON nao separa por CTO, fica o numero do alerta
        assert.equal(b.semContrato, undefined);
        assert.equal(c.dispositivosAtivos, 0); // lista vazia = ninguem com contrato
    } finally {
        globalThis.fetch = original;
    }
});
