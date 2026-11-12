import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { juntarFalas, lerResumo, MOTIVOS, textoDaConversa, validarGravacao } from "./phoneTranscricaoService.js";

const wav = () => Buffer.concat([Buffer.from("RIFF"), Buffer.alloc(4), Buffer.from("WAVE"), Buffer.alloc(60)]);
const arquivos = () => ({ local: [{ buffer: wav() }], remoto: [{ buffer: wav() }] });
const corpo = { direcao: "in", numero: "5575999990000", inicioMs: String(Date.now() - 1000), duracaoSeg: "42" };

describe("transcrição de chamadas", () => {
  it("junta as falas dos dois lados na ordem em que aconteceram e identifica quem falou", () => {
    const falas = juntarFalas(
      [{ ini: 0, fim: 3, texto: "Acessanet, bom dia." }, { ini: 9, fim: 12, texto: "Vou abrir uma visita." }],
      [{ ini: 3.5, fim: 8, texto: "Estou sem internet." }]);
    assert.deepEqual(falas.map((f) => f.quem), ["atendente", "cliente", "atendente"]);
    assert.equal(textoDaConversa(falas), "Atendente: Acessanet, bom dia.\nCliente: Estou sem internet.\nAtendente: Vou abrir uma visita.");
  });

  it("descarta ruído isolado e frases que o Whisper inventa em silêncio", () => {
    const falas = juntarFalas([{ ini: 0, fim: 1, texto: "Legendas pela comunidade Amara.org" }, { ini: 2, fim: 3, texto: "a" }, { ini: 4, fim: 5, texto: "..." }], [{ ini: 1, fim: 2, texto: "Obrigado por assistir!" }]);
    assert.deepEqual(falas, []);
  });

  it("lê o resumo e só aceita motivos da lista", () => {
    assert.deepEqual(lerResumo('{"resumo": "Cliente sem internet.", "motivo": "Suporte técnico: sem conexão"}'), { resumo: "Cliente sem internet.", motivo: "Suporte técnico: sem conexão" });
    assert.equal(lerResumo('Claro! {"resumo": "Teste", "motivo": "algo inventado"} fim').motivo, null);
    assert.equal(lerResumo('{"resumo": "x", "motivo": "cancelamento"}').motivo, "Cancelamento");
    assert.equal(lerResumo("texto solto sem json").resumo, "texto solto sem json");
    assert.ok(MOTIVOS.includes("Outro"));
  });

  it("valida o envio: direção, número, horário e os dois arquivos WAV", () => {
    const ok = validarGravacao(corpo, arquivos());
    assert.equal(ok.direcao, "in"); assert.equal(ok.numero, "5575999990000"); assert.equal(ok.duracaoSeg, 42);
    assert.throws(() => validarGravacao({ ...corpo, direcao: "x" }, arquivos()), /Direção/);
    assert.throws(() => validarGravacao({ ...corpo, numero: "../etc" }, arquivos()), /Número/);
    assert.throws(() => validarGravacao({ ...corpo, inicioMs: "1" }, arquivos()), /Horário/);
    assert.throws(() => validarGravacao(corpo, { local: [{ buffer: Buffer.from("não é wav") }], remoto: arquivos().remoto }), /Áudio/);
    assert.throws(() => validarGravacao(corpo, {}), /Áudio/);
  });
});
