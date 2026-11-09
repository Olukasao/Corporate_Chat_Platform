import { sanitizeForLog } from "../validators/networkDiagnosticsValidator.js";

export class IntegrationUnavailableError extends Error {
    constructor(message, details = {}) {
        super(message);
        this.name = "IntegrationUnavailableError";
        this.statusCode = 503;
        this.details = details;
    }
}

const DEFAULT_TIMEOUT_SECONDS = 10;
const DEFAULT_CACHE_TTL_MS = 20_000;
const DEFAULT_URA_CONSULTA_CLIENTE_PATH = "/api/ura/consultacliente/";
const searchCache = new Map();
const customerCache = new Map();

const isTruthy = (valor) => ["1", "true", "yes", "sim", "on"].includes(String(valor || "").toLowerCase());
const isPlainObject = (valor) => valor && typeof valor === "object" && !Array.isArray(valor);

const normalizeFieldName = (valor = "") => String(valor)
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-zA-Z0-9]/g, "")
    .toLowerCase();

const asScalar = (valor) => {
    if (valor === null || valor === undefined || valor === "") return null;
    if (typeof valor === "object") return null;
    return valor;
};

const findFieldDeep = (source, keys = [], maxDepth = 8) => {
    if (!source || typeof source !== "object") return null;

    const normalizedKeys = new Set(keys.map(normalizeFieldName).filter(Boolean));
    const seen = new Set();

    const visit = (value, depth) => {
        if (!value || typeof value !== "object" || depth > maxDepth || seen.has(value)) return null;
        seen.add(value);

        if (Array.isArray(value)) {
            for (const item of value) {
                const found = visit(item, depth + 1);
                if (found !== null) return found;
            }

            return null;
        }

        for (const [key, fieldValue] of Object.entries(value)) {
            if (normalizedKeys.has(normalizeFieldName(key))) {
                const scalar = asScalar(fieldValue);
                if (scalar !== null) return scalar;
            }
        }

        for (const fieldValue of Object.values(value)) {
            const found = visit(fieldValue, depth + 1);
            if (found !== null) return found;
        }

        return null;
    };

    return visit(source, 0);
};

const toNumberOrNull = (valor) => {
    if (valor === null || valor === undefined || valor === "") return null;

    const numero = Number(String(valor).replace(",", ".").replace(/[^\d.-]/g, ""));
    return Number.isFinite(numero) ? Number(numero.toFixed(2)) : null;
};

const pick = (source = {}, keys = []) => {
    for (const key of keys) {
        const value = asScalar(source?.[key]);
        if (value !== undefined && value !== null && value !== "") return value;
    }

    return null;
};

const getNested = (source = {}, paths = []) => {
    for (const path of paths) {
        const value = String(path)
            .split(".")
            .reduce((current, key) => current?.[key], source);
        const scalar = asScalar(value);

        if (scalar !== undefined && scalar !== null && scalar !== "") return scalar;
    }

    return null;
};

const pickSgpValue = (source = {}, directKeys = [], nestedPaths = [], deepKeys = directKeys) => (
    pick(source, directKeys)
    ?? getNested(source, nestedPaths)
    ?? findFieldDeep(source, deepKeys)
);

const parsePlanSpeed = (planName = "", type = "download") => {
    const texto = String(planName || "");
    const matches = [...texto.matchAll(/(\d+(?:[,.]\d+)?)\s*(giga|gb|g|mega|mbps|mb)/gi)];

    if (!matches.length) return null;

    const index = type === "upload" && matches.length > 1 ? 1 : 0;
    const match = matches[index] || matches[0];
    const number = toNumberOrNull(match[1]);

    if (number === null) return null;

    return /giga|gb|^g$/i.test(match[2]) ? number * 1000 : number;
};

const normalizarStatus = (valor = "") => {
    const texto = String(valor || "").trim().toLowerCase();

    if (!texto) return "unknown";
    if (/online|conectado|ativo|habilitado/.test(texto)) return "online";
    if (/instab|aten|degrad|queda|oscila/.test(texto)) return "unstable";
    if (/offline|desconectado|inativo|bloqueado|suspenso|cancelado/.test(texto)) return "offline";

    return texto.slice(0, 40);
};

const extractCollection = (payload) => {
    if (Array.isArray(payload)) return payload;

    const candidates = [
        payload?.results,
        payload?.clientes,
        payload?.customers,
        payload?.data,
        payload?.items,
        payload?.objects,
        payload?.response,
    ];

    for (const candidate of candidates) {
        if (Array.isArray(candidate)) return candidate;
        if (candidate && typeof candidate === "object") {
            const nested = extractCollection(candidate);
            if (nested.length) return nested;
        }
    }

    return payload && typeof payload === "object" ? [payload] : [];
};

const getCache = (cache, key) => {
    const item = cache.get(key);
    if (!item) return null;

    if (Date.now() > item.expiresAt) {
        cache.delete(key);
        return null;
    }

    return item.value;
};

const setCache = (cache, key, value, ttlMs = DEFAULT_CACHE_TTL_MS) => {
    cache.set(key, {
        value,
        expiresAt: Date.now() + ttlMs,
    });
};

const getCacheTtlMs = () => {
    const seconds = Number(process.env.SGP_CACHE_SECONDS || 20);
    if (!Number.isFinite(seconds) || seconds <= 0) return DEFAULT_CACHE_TTL_MS;
    return Math.min(30, Math.max(10, seconds)) * 1000;
};

const getUraConfig = () => {
    const baseUrl = String(process.env.SGP_URA_BASE_URL || process.env.SGP_BASE_URL || "").replace(/\/+$/, "");
    const path = String(process.env.SGP_URA_CONSULTA_CLIENTE_PATH || DEFAULT_URA_CONSULTA_CLIENTE_PATH);

    return {
        baseUrl,
        path,
        username: process.env.SGP_URA_USERNAME || process.env.SGP_USERNAME || "",
        password: process.env.SGP_URA_PASSWORD || process.env.SGP_PASSWORD || "",
        timeoutSeconds: Number(process.env.SGP_TIMEOUT_SECONDS || DEFAULT_TIMEOUT_SECONDS),
    };
};

const buildUraUrl = ({ baseUrl, path }) => {
    const normalizedPath = String(path || DEFAULT_URA_CONSULTA_CLIENTE_PATH);
    return `${baseUrl}${normalizedPath.startsWith("/") ? normalizedPath : `/${normalizedPath}`}`;
};

const buildUraAvailability = (enabled) => {
    const config = getUraConfig();
    const missing = [];

    if (!enabled) missing.push("SGP_API_ENABLED");
    if (!config.baseUrl) missing.push("SGP_URA_BASE_URL");
    if (!config.username) missing.push("SGP_URA_USERNAME");
    if (!config.password) missing.push("SGP_URA_PASSWORD");

    return {
        available: enabled && missing.length === 0,
        hasBaseUrl: Boolean(config.baseUrl),
        hasUsername: Boolean(config.username),
        hasPassword: Boolean(config.password),
        missing,
    };
};

const buildAvailability = () => {
    const provider = String(process.env.SGP_PROVIDER || "").trim().toLowerCase();
    const uraConfig = getUraConfig();
    const hasUraConfig = Boolean(uraConfig.baseUrl && uraConfig.username && uraConfig.password);
    const wantsUra = provider === "ura" || isTruthy(process.env.SGP_URA_ENABLED) || hasUraConfig;
    const enabled = isTruthy(process.env.SGP_API_ENABLED || process.env.SGP_ENABLED || process.env.SGP_URA_ENABLED) || hasUraConfig;
    const searchUrl = process.env.SGP_CUSTOMER_SEARCH_URL || "";
    const detailUrl = process.env.SGP_CUSTOMER_DETAIL_URL || "";
    const ura = buildUraAvailability(enabled);
    const genericAvailable = enabled && Boolean(searchUrl);
    const missing = [];

    if (!enabled) missing.push("SGP_API_ENABLED");
    if (!searchUrl && !ura.available) missing.push("SGP_CUSTOMER_SEARCH_URL ou SGP_URA_*");

    return {
        available: genericAvailable || (wantsUra && ura.available),
        enabled,
        provider: wantsUra ? "ura" : "generic",
        hasSearchUrl: Boolean(searchUrl),
        hasDetailUrl: Boolean(detailUrl),
        generic: {
            available: genericAvailable,
            hasSearchUrl: Boolean(searchUrl),
            hasDetailUrl: Boolean(detailUrl),
        },
        ura,
        missing,
        message: genericAvailable || (wantsUra && ura.available)
            ? "Integração com o SGP configurada."
            : "Integração com o SGP ainda não configurada.",
    };
};

export const getSgpAvailability = () => buildAvailability();

const replaceTemplate = (template, replacements = {}) => {
    let url = String(template || "");

    Object.entries(replacements).forEach(([key, value]) => {
        url = url.replaceAll(`{${key}}`, encodeURIComponent(String(value ?? "")));
    });

    return url;
};

const ensureTemplateHas = (template, token, envName) => {
    if (!String(template || "").includes(`{${token}}`)) {
        throw new IntegrationUnavailableError(
            `Configure ${envName} com o marcador {${token}}.`,
            { missing: [envName] }
        );
    }
};

const buildHeaders = () => {
    const headers = {
        Accept: "application/json",
    };
    const token = process.env.SGP_AUTH_TOKEN || process.env.SGP_API_TOKEN || "";
    const headerName = process.env.SGP_AUTH_HEADER || "Authorization";

    if (token) {
        const prefix = process.env.SGP_AUTH_PREFIX === undefined ? "Bearer " : process.env.SGP_AUTH_PREFIX;
        headers[headerName] = `${prefix}${token}`;
    }

    return headers;
};

const fetchJson = async (url, { signal } = {}) => {
    const timeoutMs = Math.max(1000, Number(process.env.SGP_TIMEOUT_SECONDS || DEFAULT_TIMEOUT_SECONDS) * 1000);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    const abortFromParent = () => controller.abort(signal?.reason);

    if (signal?.aborted) {
        clearTimeout(timeout);
        throw new Error("Operação cancelada.");
    }

    signal?.addEventListener("abort", abortFromParent, { once: true });

    try {
        const response = await fetch(url, {
            method: "GET",
            headers: buildHeaders(),
            signal: controller.signal,
        });

        if (!response.ok) {
            const err = new Error(`SGP retornou HTTP ${response.status}.`);
            err.statusCode = response.status >= 400 && response.status < 500 ? 502 : 503;
            throw err;
        }

        return response.json();
    } finally {
        clearTimeout(timeout);
        signal?.removeEventListener("abort", abortFromParent);
    }
};

const fetchUraJson = async (campos, { signal, caminho, timeoutMs } = {}) => {
    // `campos` é o número do contrato (texto) ou um objeto com os campos do formulário (ex.: { telefone }).
    const campo = typeof campos === "object" && campos !== null ? campos : { contrato: campos };
    const config = getUraConfig();
    const limiteMs = Math.max(1000, timeoutMs || config.timeoutSeconds * 1000);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), limiteMs);
    const abortFromParent = () => controller.abort(signal?.reason);
    const formData = new FormData();

    Object.entries(campo).forEach(([nome, valor]) => formData.append(nome, String(valor ?? "").trim()));

    if (signal?.aborted) {
        clearTimeout(timeout);
        throw new Error("Operação cancelada.");
    }

    signal?.addEventListener("abort", abortFromParent, { once: true });

    try {
        const response = await fetch(buildUraUrl(caminho ? { ...config, path: caminho } : config), {
            method: "POST",
            headers: {
                Accept: "application/json",
                Authorization: `Basic ${Buffer.from(`${config.username}:${config.password}`).toString("base64")}`,
            },
            body: formData,
            signal: controller.signal,
        });

        let payload = null;
        try {
            payload = await response.json();
        } catch {
            payload = null;
        }

        if (!response.ok) {
            const err = new Error(`SGP URA retornou HTTP ${response.status}.`);
            err.statusCode = response.status >= 400 && response.status < 500 ? 502 : 503;
            throw err;
        }

        return payload || {};
    } finally {
        clearTimeout(timeout);
        signal?.removeEventListener("abort", abortFromParent);
    }
};

const extractUraContracts = (payload) => {
    if (!payload || typeof payload !== "object") return [];

    const candidates = [
        payload.contratos,
        payload.contrato,
        payload.data?.contratos,
        payload.data?.contrato,
        payload.response?.contratos,
        payload.response?.contrato,
    ];

    for (const candidate of candidates) {
        if (Array.isArray(candidate)) return candidate;
        if (isPlainObject(candidate)) return [candidate];
    }

    return extractCollection(payload);
};

const comparable = (valor) => {
    const texto = String(valor || "").trim().toLowerCase();
    const numeric = texto.replace(/\D/g, "");
    return numeric || texto;
};

const findMatchingContract = (contracts = [], contrato = "") => {
    const lookup = comparable(contrato);
    if (!lookup) return contracts[0] || null;

    return contracts.find((contract) => {
        const normalized = normalizeSgpCustomer(contract, { idPreference: "contract" });
        return [
            normalized?.contractId,
            normalized?.id,
            pickSgpValue(contract, ["contrato", "id_contrato", "contrato_id", "codigo_contrato"]),
        ].some((value) => comparable(value) === lookup);
    }) || contracts[0] || null;
};

const getContractLookup = (customerId, fallbackCustomer = null) => String(
    pickSgpValue(fallbackCustomer || {}, [
        "contractId",
        "contract_id",
        "contrato_id",
        "codigo_contrato",
        "contrato",
        "id_contrato",
    ]) || customerId || ""
).trim();

const shouldUseUra = (availability, kind = "search") => (
    availability.ura?.available && (
        availability.provider === "ura"
        || (kind === "search" && !availability.generic?.available)
        || (kind === "detail" && !availability.hasDetailUrl)
    )
);

export const normalizeSgpCustomer = (row = {}, options = {}) => {
    const { idPreference = "customer" } = options;
    const planName = String(pickSgpValue(
        row,
        ["planName", "plan_name", "plano_nome", "plano", "servico", "service"],
        ["plano.nome", "servico.plano", "servico.plano_nome", "service.planName"],
        ["planName", "plan_name", "plano_nome", "nome_plano", "plano", "servico", "service"]
    ) || "");
    const customerId = String(pickSgpValue(row, [
        "id",
        "customerId",
        "customer_id",
        "cliente_id",
        "id_cliente",
        "codigo_cliente",
        "codigo",
        "contrato.cliente_id",
    ], ["cliente.id", "customer.id", "contrato.cliente_id"], [
        "customerId",
        "customer_id",
        "cliente_id",
        "id_cliente",
        "codigo_cliente",
        "codigo_cliente_sgp",
    ]) || "").trim();
    const contractId = String(pickSgpValue(row, [
        "contractId",
        "contract_id",
        "contrato_id",
        "codigo_contrato",
        "contrato",
        "id_contrato",
    ], ["contrato.id", "contract.id"], [
        "contractId",
        "contract_id",
        "contrato_id",
        "codigo_contrato",
        "contrato",
        "id_contrato",
    ]) || "").trim();
    const id = idPreference === "contract"
        ? contractId || customerId
        : customerId || contractId;
    const name = String(pickSgpValue(row, [
        "name",
        "nome",
        "razao_social",
        "customer_name",
        "cliente_nome",
    ], ["cliente.nome", "customer.name"], [
        "customer_name",
        "cliente_nome",
        "nome_cliente",
        "razao_social",
        "nome",
    ]) || "").trim();
    const pppoeUsername = String(pickSgpValue(row, [
        "pppoeUsername",
        "pppoe_username",
        "login_pppoe",
        "login",
        "username",
        "usuario",
        "radius_username",
    ], ["pppoe.username", "servico.login", "contrato.login"], [
        "pppoeUsername",
        "pppoe_username",
        "login_pppoe",
        "login",
        "username",
        "usuario",
        "radius_username",
    ]) || "").trim();
    const ip = String(pickSgpValue(row, [
        "ip",
        "currentIp",
        "current_ip",
        "ip_atual",
        "ipv4",
        "framed_ip",
    ], ["sessao.ip", "session.ip", "pppoe.ip"], [
        "currentIp",
        "current_ip",
        "ip_atual",
        "ipv4",
        "framed_ip",
        "ip",
    ]) || "").trim();
    const statusRaw = pickSgpValue(row, [
        "status",
        "connection_status",
        "situacao",
        "status_conexao",
        "online",
        "status_contrato",
    ]) ?? "";
    const street = String(pickSgpValue(row, ["logradouro", "rua", "endereco_logradouro"]) || "").trim();
    const number = String(pickSgpValue(row, ["numero", "endereco_numero"]) || "").trim();
    const district = String(pickSgpValue(row, ["bairro", "endereco_bairro"]) || "").trim();
    const addressParts = [
        street && number ? `${street}, ${number}` : street || number,
        district,
    ].filter(Boolean);

    const normalized = {
        id: id || contractId || pppoeUsername || ip,
        customerId: customerId || null,
        contractId: contractId || null,
        name: name || "Cliente sem nome",
        document: String(pickSgpValue(row, ["document", "cpf_cnpj", "cpf", "cnpj", "documento"]) || "").trim() || null,
        planName: planName || null,
        planDownloadMbps: toNumberOrNull(pickSgpValue(row, ["planDownloadMbps", "download_mbps", "plano_download_mbps", "download"])) || parsePlanSpeed(planName, "download"),
        planUploadMbps: toNumberOrNull(pickSgpValue(row, ["planUploadMbps", "upload_mbps", "plano_upload_mbps", "upload"])) || parsePlanSpeed(planName, "upload"),
        status: typeof statusRaw === "boolean" ? (statusRaw ? "online" : "offline") : normalizarStatus(statusRaw),
        city: String(pickSgpValue(row, ["city", "cidade", "municipio"], ["endereco.cidade"]) || "").trim() || null,
        pppoeUsername: pppoeUsername || null,
        ip: ip || null,
        macOnu: String(pickSgpValue(row, ["macOnu", "mac_onu", "onu_mac", "mac", "mac_address"], ["onu.mac"]) || "").trim() || null,
        phone: String(pickSgpValue(row, ["phone", "telefone", "celular", "whatsapp"]) || "").trim() || null,
        popName: String(pickSgpValue(row, ["popName", "pop_name", "pop", "concentrador", "nas", "cidade_pop"]) || "").trim() || null,
        onuIdentifier: String(pickSgpValue(row, ["onuIdentifier", "onu_identifier", "onu", "serial_onu", "serial", "router", "roteador"]) || "").trim() || null,
        opticalSignalDbm: toNumberOrNull(pickSgpValue(row, ["opticalSignalDbm", "optical_signal_dbm", "sinal_optico", "rx_power", "onu_rx"])),
        sessionUptimeSeconds: toNumberOrNull(pickSgpValue(row, ["sessionUptimeSeconds", "session_uptime_seconds", "uptime_seconds", "tempo_conectado_segundos"])),
        address: String(pickSgpValue(row, ["address", "endereco", "enderecoCompleto"]) || addressParts.join(" - ")).trim() || null,
        rawSource: "sgp",
    };

    return normalized.id ? normalized : null;
};

const searchCustomersUra = async (query, { signal } = {}) => {
    const cacheKey = `search:ura:${query.toLowerCase()}`;
    const cached = getCache(searchCache, cacheKey);
    if (cached) return cached;

    const startedAt = Date.now();
    const payload = await fetchUraJson(query, { signal });
    const customers = extractUraContracts(payload)
        .map((contract) => normalizeSgpCustomer(contract, { idPreference: "contract" }))
        .filter(Boolean)
        .slice(0, 20);

    customers.forEach((customer) => {
        setCache(customerCache, String(customer.id), customer, getCacheTtlMs());
        if (customer.contractId) setCache(customerCache, String(customer.contractId), customer, getCacheTtlMs());
    });

    const result = {
        available: true,
        customers,
        elapsedMs: Date.now() - startedAt,
        source: "sgp-ura",
        warning: customers.length ? null : "A consulta SGP URA pesquisa principalmente por contrato.",
    };

    setCache(searchCache, cacheKey, result, getCacheTtlMs());
    return result;
};

const getCustomerDetailsUra = async (customerId, { signal, fallbackCustomer = null } = {}) => {
    const contrato = getContractLookup(customerId, fallbackCustomer);
    const cacheKey = String(customerId);
    const cacheDetailKey = `detail:ura:${contrato}`;
    const cached = getCache(customerCache, cacheDetailKey);
    if (cached) return cached;

    const startedAt = Date.now();
    const payload = await fetchUraJson(contrato, { signal });
    const contract = findMatchingContract(extractUraContracts(payload), contrato);

    if (!contract) {
        const err = new Error("Cliente não encontrado no SGP.");
        err.statusCode = 404;
        throw err;
    }

    const customer = normalizeSgpCustomer({
        ...(fallbackCustomer || {}),
        ...contract,
    }, { idPreference: "contract" });

    if (!customer) {
        const err = new Error("Cliente não encontrado no SGP.");
        err.statusCode = 404;
        throw err;
    }

    const result = {
        available: true,
        customer,
        elapsedMs: Date.now() - startedAt,
        source: "sgp-ura",
    };

    setCache(customerCache, cacheKey, customer, getCacheTtlMs());
    if (customer.contractId) setCache(customerCache, String(customer.contractId), customer, getCacheTtlMs());
    setCache(customerCache, cacheDetailKey, result, getCacheTtlMs());
    return result;
};

export const searchCustomers = async (query, { signal } = {}) => {
    const availability = buildAvailability();

    if (!availability.available) {
        console.warn("[SGP] Pesquisa indisponível:", sanitizeForLog(availability));
        throw new IntegrationUnavailableError(availability.message, availability);
    }

    if (shouldUseUra(availability, "search")) {
        return searchCustomersUra(query, { signal });
    }

    const cacheKey = `search:${query.toLowerCase()}`;
    const cached = getCache(searchCache, cacheKey);
    if (cached) return cached;

    ensureTemplateHas(process.env.SGP_CUSTOMER_SEARCH_URL, "query", "SGP_CUSTOMER_SEARCH_URL");
    const url = replaceTemplate(process.env.SGP_CUSTOMER_SEARCH_URL, { query });
    const startedAt = Date.now();
    const payload = await fetchJson(url, { signal });
    const customers = extractCollection(payload)
        .map(normalizeSgpCustomer)
        .filter(Boolean)
        .slice(0, 20);

    customers.forEach((customer) => {
        setCache(customerCache, String(customer.id), customer, getCacheTtlMs());
    });

    const result = {
        available: true,
        customers,
        elapsedMs: Date.now() - startedAt,
        source: "sgp",
    };

    setCache(searchCache, cacheKey, result, getCacheTtlMs());
    return result;
};

export const getCustomerDetails = async (customerId, { signal, fallbackCustomer = null } = {}) => {
    const availability = buildAvailability();
    const cacheKey = String(customerId);
    const cached = getCache(customerCache, cacheKey);
    const cacheDetail = getCache(customerCache, `detail:${cacheKey}`);

    if (cacheDetail) return cacheDetail;

    if (shouldUseUra(availability, "detail")) {
        return getCustomerDetailsUra(customerId, { signal, fallbackCustomer });
    }

    if (cached && !process.env.SGP_CUSTOMER_DETAIL_URL) {
        return {
            available: true,
            customer: cached,
            source: "sgp-cache",
            warning: "Detalhe do SGP não configurado; usando dados recentes da pesquisa.",
        };
    }

    if (fallbackCustomer && !process.env.SGP_CUSTOMER_DETAIL_URL) {
        const normalizedFallback = normalizeSgpCustomer(fallbackCustomer);
        if (normalizedFallback) {
            setCache(customerCache, cacheKey, normalizedFallback, getCacheTtlMs());
            return {
                available: true,
                customer: normalizedFallback,
                source: "request-snapshot",
                warning: "Detalhe do SGP não configurado; usando dados enviados pela seleção do cliente.",
            };
        }
    }

    if (!availability.enabled || !process.env.SGP_CUSTOMER_DETAIL_URL) {
        const missing = !availability.enabled ? ["SGP_API_ENABLED"] : ["SGP_CUSTOMER_DETAIL_URL"];
        console.warn("[SGP] Detalhe indisponível:", sanitizeForLog({ missing, customerId }));
        throw new IntegrationUnavailableError("Integração com o SGP ainda não configurada.", { missing });
    }

    ensureTemplateHas(process.env.SGP_CUSTOMER_DETAIL_URL, "customerId", "SGP_CUSTOMER_DETAIL_URL");
    const url = replaceTemplate(process.env.SGP_CUSTOMER_DETAIL_URL, { customerId });
    const startedAt = Date.now();
    const payload = await fetchJson(url, { signal });
    const [customer] = extractCollection(payload)
        .map(normalizeSgpCustomer)
        .filter(Boolean);

    if (!customer) {
        const err = new Error("Cliente não encontrado.");
        err.statusCode = 404;
        throw err;
    }

    const result = {
        available: true,
        customer,
        elapsedMs: Date.now() - startedAt,
        source: "sgp",
    };

    setCache(customerCache, cacheKey, customer, getCacheTtlMs());
    setCache(customerCache, `detail:${cacheKey}`, result, getCacheTtlMs());
    return result;
};

/** Consulta crua à URA do SGP por campos livres (ex.: { telefone }). Devolve os contratos do retorno. */
export const consultarContratosUra = async (campos, { signal } = {}) => {
    const availability = buildAvailability();
    if (!availability.available) throw new IntegrationUnavailableError(availability.message, availability);
    const payload = await fetchUraJson(campos, { signal });
    return extractUraContracts(payload);
};

/** Chamados (ocorrências) de um contrato no SGP, do jeito que o SGP devolve. Contratos com muitos chamados demoram: limite maior. */
export const listarOcorrenciasUra = async (contrato, { signal } = {}) => {
    const availability = buildAvailability();
    if (!availability.available) throw new IntegrationUnavailableError(availability.message, availability);
    const payload = await fetchUraJson({ contrato }, { signal, caminho: "/api/ura/ocorrencia/list/", timeoutMs: 20_000 });
    return Array.isArray(payload?.ocorrencias) ? payload.ocorrencias : [];
};
