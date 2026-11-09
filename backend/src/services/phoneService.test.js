import { extensaoDeDiscagem } from "./phoneService.js";
import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chaveDeCifra, cifrarSenha, decifrarSenha, telefoniaConfigurada, validarChamada, validarConta } from "./phoneService.js";

const env = { PHONE_SECRET_KEY: randomBytes(32).toString("base64") };

test("cifra e decifra a senha SIP sem deixá-la visível", () => {
  const cifrada = cifrarSenha("senha-secreta-123", env);
  assert.match(cifrada, /^v1:/);
  assert.ok(!cifrada.includes("senha-secreta"));
  assert.equal(decifrarSenha(cifrada, env), "senha-secreta-123");
});

test("duas cifras da mesma senha são diferentes (IV aleatório)", () => {
  assert.notEqual(cifrarSenha("abc", env), cifrarSenha("abc", env));
});

test("chave errada ou texto adulterado não decifra", () => {
  const cifrada = cifrarSenha("abc12345", env);
  assert.throws(() => decifrarSenha(cifrada, { PHONE_SECRET_KEY: randomBytes(32).toString("base64") }));
  const partes = cifrada.split(":");
  partes[3] = Buffer.from("adulterado!").toString("base64");
  assert.throws(() => decifrarSenha(partes.join(":"), env));
});

test("sem PHONE_SECRET_KEY a telefonia fica indisponível (503), nunca cai em texto puro", () => {
  assert.equal(telefoniaConfigurada({}), false);
  assert.equal(chaveDeCifra({ PHONE_SECRET_KEY: "curta" }), null);
  assert.throws(() => cifrarSenha("x", {}), (e) => e.status === 503);
});

test("valida uma conta SIP e normaliza os campos", () => {
  const c = validarConta({ ramal: "7781025", sipDomain: "SIP.Exemplo.com.br", senha: "s3nha", displayName: 'Ana "A"\n' });
  assert.deepEqual({ r: c.ramal, u: c.sipUser, d: c.sipDomain, s: c.sipServer, p: c.sipPort, t: c.transport, n: c.displayName },
    { r: "7781025", u: "7781025", d: "sip.exemplo.com.br", s: "sip.exemplo.com.br", p: 5060, t: "udp", n: "Ana A" });
});

test("recusa entradas perigosas ou inválidas", () => {
  const ok = { ramal: "100", sipDomain: "sip.exemplo.com", senha: "x" };
  for (const ruim of [
    { ...ok, ramal: "10 0" }, { ...ok, ramal: "abc" }, { ...ok, sipDomain: "a b.com" }, { ...ok, sipDomain: "x.com;transport=tls" },
    { ...ok, sipServer: "evil.com/../x" }, { ...ok, sipPort: 70000 }, { ...ok, sipPort: 0 }, { ...ok, transport: "tls" },
    { ...ok, senha: "" }, { ...ok, senha: "a\r\nb" }, { ...ok, sipUser: "a@b" },
  ]) assert.throws(() => validarConta(ruim), (e) => e.status === 400, JSON.stringify(ruim));
});

test("ao editar, a senha é opcional", () => {
  assert.equal(validarConta({ ramal: "100", sipDomain: "sip.exemplo.com" }, { senhaObrigatoria: false }).senha, "");
});

test("valida o registro de chamada", () => {
  const c = validarChamada({ direcao: "out", numero: "1003", resultado: "atendida", duracaoSeg: 11.9, inicioMs: Date.now() });
  assert.equal(c.duracaoSeg, 11);
  for (const ruim of [{ direcao: "x" }, { direcao: "in", numero: "1;DROP", resultado: "atendida" }, { direcao: "in", numero: "1", resultado: "?" },
    { direcao: "in", numero: "1", resultado: "falhou", inicioMs: 1 }])
    assert.throws(() => validarChamada(ruim), (e) => e.status === 400);
});

test("ramal da conta SIP vira o número curto que a central reconhece", () => {
    assert.equal(extensaoDeDiscagem("7781010"), "1010");
    assert.equal(extensaoDeDiscagem("7781003"), "1003");
    assert.equal(extensaoDeDiscagem("1003"), "1003"); // já é curto
    assert.equal(extensaoDeDiscagem("778"), "778"); // sobraria nada
    assert.equal(extensaoDeDiscagem("77812"), "77812"); // sobrariam só 2 dígitos
    assert.equal(extensaoDeDiscagem("7781010", ""), "7781010"); // prefixo desligado
    assert.equal(extensaoDeDiscagem("9991010", "999"), "1010"); // outro prefixo
    assert.equal(extensaoDeDiscagem("abc"), "abc");
});

test("transferência: valida o cliente e devolve o ramal nas duas formas", async () => {
  const { validarTransferencia } = await import("./phoneService.js");
  assert.deepEqual(validarTransferencia({ numero: "(11) 99021-1587", destino: "1010" }, "778"), { numero: "11990211587", ramais: ["1010", "7781010"] });
  assert.deepEqual(validarTransferencia({ numero: "11990211587", destino: "7781010" }, "778").ramais, ["1010", "7781010"]);
  assert.equal(validarTransferencia({ numero: "7781010", destino: "1020" }, "778").numero, "7781010"); // colega
  assert.throws(() => validarTransferencia({ numero: "1", destino: "1010" }), /Número inválido/);
  assert.throws(() => validarTransferencia({ numero: "11990211587", destino: "1" }), /Ramal de destino/);
  assert.throws(() => validarTransferencia(null), /inválido/);
});
