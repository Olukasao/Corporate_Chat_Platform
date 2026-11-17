import test from "node:test";
import assert from "node:assert/strict";

process.env.OLTCLOUD_BASE_URL = "https://olt.example.test";
process.env.OLTCLOUD_TOKEN = "token-fixo";

const { lerDataOlt, contarQuedas, agruparSinalPorPon, classificarSinal, episodiosPorPon, limiteSinal } = await import("../src/services/oltInsightsService.js");
const { desfechoDoIncidente } = await import("../src/services/oltCloudService.js");

const AGORA = Date.parse("2026-11-17T15:00:00Z"); // 12:00 em Brasília

test("data da OLT Cloud é horário de Brasília", () => {
    assert.equal(lerDataOlt("2026-11-17 12:00:00"), AGORA);
    assert.equal(lerDataOlt("2026-11-17T15:00:00Z"), AGORA);
    assert.equal(lerDataOlt(""), null);
    assert.equal(lerDataOlt("lixo"), null);
});

test("quedas: conta a saída de Online, estados ruins seguidos valem uma queda só, e separa 24 h de 7 dias", () => {
    const logs = [ // do mais novo ao mais antigo, como a API devolve
        { date: "2026-11-17 11:30:00", status: "Online" },
        { date: "2026-11-17 11:20:00", status: "Sem Energia" }, // queda 24h
        { date: "2026-11-17 09:05:00", status: "Online" },
        { date: "2026-11-17 09:01:00", status: "LOSS" }, // estados ruins seguidos: uma queda so
        { date: "2026-11-17 09:00:00", status: "Sem Energia" }, // queda 24h
        { date: "2026-11-16 08:00:00", status: "Online" },
        { date: "2026-11-16 07:50:00", status: "LOSS" }, // fora das 24 h (esta a 28 h), dentro de 7 dias
        { date: "2026-11-01 08:00:00", status: "Online" },
        { date: "2026-11-01 07:50:00", status: "LOSS" }, // fora de 7 dias
    ];
    const r = contarQuedas(logs, AGORA);
    assert.equal(r.quedas24h, 2);
    assert.equal(r.quedas7d, 3);
    assert.equal(r.ultimas.length, 4);
    assert.deepEqual(contarQuedas([], AGORA), { quedas24h: 0, quedas7d: 0, ultimas: [] });
    assert.deepEqual(contarQuedas(null, AGORA).quedas24h, 0);
});

test("sinal crítico: só online COM contrato, ignora sem leitura (-99,99) e agrupa por PON", () => {
    const e = (contrato, rxOnu, rxOlt, status = "Online", pon = "1") => ({ contrato, serie: `s${contrato}`, status, olt: "OLT A", slot: "1", pon, rxOnu, rxOlt });
    const lista = [
        e("1", -28.5, -25), // critico (ONU)
        e("2", -24, -31), // critico (OLT 3 dB pior que o limite)
        e("3", -25.5, -26), // aviso
        e("4", -20, -22), // ok
        e("5", -99.99, -99.99), // sem leitura: nao e critico
        e("6", -30, -30, "LOSS"), // offline: nao entra
        e("", -30, -30), // sem contrato: nao e cliente
        e("7", -29, -25, "Online", "2"), // outra PON
    ];
    const g = agruparSinalPorPon(lista, -27);
    assert.equal(g.length, 2);
    const p1 = g.find((p) => p.pon === "1");
    assert.deepEqual([p1.criticos, p1.avisos, p1.total], [2, 1, 6]); // total: 6 com contrato na PON 1
    assert.deepEqual(p1.clientes.map((c) => c.contrato), ["1", "2"].sort((a, b) => (a === "1" ? -28.5 : -24) - (b === "1" ? -28.5 : -24)));
    assert.equal(g[0].criticos >= g[1].criticos, true);
    assert.equal(classificarSinal(-28, -25), "critico");
    assert.equal(classificarSinal(-25.5, -26), "fraco");
    assert.equal(classificarSinal(-20, -22), "ok");
    assert.equal(classificarSinal(-99.99, -99.99), "sem_leitura");
    assert.equal(limiteSinal("-30"), -30);
    assert.equal(limiteSinal("abc"), -27);
    assert.equal(limiteSinal("-5"), -27); // fora de faixa
});

test("ranking: alertas sobrepostos da mesma PON viram UM episódio; separa semana e mês", () => {
    const iso = (h) => new Date(AGORA - h * 3600_000).toISOString();
    const a = (id, tipo, ini, fim, n = 10) => ({ id, tipo, olt: "OLT A", slotPon: "1/2", pon: "2", inicio: iso(ini), fim: fim === null ? null : iso(fim), dispositivosAtivos: n, ignorado: false });
    const alertas = [
        a("1", "pon_down", 3, 2, 20), // mesmo evento...
        a("2", "pon_loss", 3, 1.9, 15), // ...visto como outro tipo: junta
        a("3", "pon_loss", 30, 29, 8), // outro episodio esta semana
        a("4", "pon_loss", 24 * 20, 24 * 20 - 1, 5), // so no mes
        a("5", "cto_loss", 2, 1), // CTO nao entra
        { ...a("6", "pon_loss", 1, 0.5), ignorado: true }, // ignorado nao entra
    ];
    const [pon] = episodiosPorPon(alertas, AGORA);
    assert.equal(pon.semana.quedas, 2);
    assert.equal(pon.mes.quedas, 3);
    assert.equal(pon.semana.maxAfetados, 20);
    assert.ok(pon.semana.minutos >= 60 && pon.semana.minutos < 200);
});

test("normalizou? fim preenchido ou sem ninguém afetado; ignorado e ainda aberto não avisam", () => {
    const base = { inicio: "2026-11-17T14:00:00Z", ignorado: false, dispositivosAtivos: 5 };
    assert.deepEqual(desfechoDoIncidente({ ...base, fim: "2026-11-17T14:30:00Z" }, AGORA), { fim: "2026-11-17T14:30:00.000Z", duracaoMs: 30 * 60_000 });
    assert.equal(desfechoDoIncidente({ ...base, fim: null, dispositivosAtivos: 0 }, AGORA).duracaoMs, 60 * 60_000);
    assert.equal(desfechoDoIncidente({ ...base, fim: null }, AGORA), null); // ainda aberto (so saiu da lista por filtro)
    assert.equal(desfechoDoIncidente({ ...base, fim: "2026-11-17T14:30:00Z", ignorado: true }, AGORA), null);
    assert.equal(desfechoDoIncidente(null, AGORA), null);
});
