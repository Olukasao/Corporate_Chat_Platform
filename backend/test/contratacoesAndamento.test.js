import test from "node:test";
import assert from "node:assert/strict";
import { normalizarAndamento } from "../src/services/contratacoesPendentesService.js";

test("andamento: normaliza, ignora status desconhecido/novo e ordena pelo mais recente", () => {
  const out = normalizarAndamento({ items: [
    { id: 1, protocol: "AC1", customerName: "Ana", planName: "800", city: "Caieiras", createdAt: "2026-11-01", updatedAt: "2026-11-02", status: "em_atendimento", assignedAdminName: "Bia" },
    { id: 2, protocol: "AC2", customerName: "Caio", status: "cancelado", updatedAt: "2026-11-05", cancelReason: "cliente desistiu" },
    { id: 3, status: "novo", updatedAt: "2026-11-06" },
    { id: "x", status: "contratado" },
  ] });
  assert.deepEqual(out.map((i) => i.id), [2, 1]);
  assert.equal(out[0].motivo, "cliente desistiu");
  assert.equal(out[1].responsavel, "Bia");
  assert.equal(out[1].motivo, null);
});
