import { sanitizeForLog } from "../validators/networkDiagnosticsValidator.js";

const DEFAULT_TIMEOUT_SECONDS = 30;
const DEFAULT_SESSION_TTL_MS = 20 * 60 * 1000;
const DEFAULT_SERVICE_CACHE_TTL_MS = 30 * 60 * 1000;
const DEFAULT_RAW_CACHE_TTL_MS = 2 * 60 * 1000;

const sessionState = {
    cookies: new Map(),
    expiresAt: 0,
    loginPromise: null,
};

const serviceCache = new Map();
const rawCache = new Map();

const isTruthy = (valor) => ["1", "true", "yes", "sim", "on"].includes(String(valor || "").toLowerCase());

const toNumberOrNull = (valor) => {
    if (Array.isArray(valor)) return toNumberOrNull(valor[0]);
    if (valor === null || valor === undefined || valor === "") return null;

    const numero = Number(String(valor).replace(",", ".").replace(/[^\d.-]/g, ""));
    return Number.isFinite(numero) ? numero : null;
};

const roundMetric = (value) => {
    const number = Number(value);
    return Number.isFinite(number) ? Number(number.toFixed(2)) : null;
};

const bytesPerSecondToMbps = (value) => {
    const number = toNumberOrNull(value);
    return number === null ? null : roundMetric((number * 8) / 1_000_000);
};

const normalizeBaseUrl = (value = "") => String(value || "").replace(/\/+$/, "");

const getConfig = () => {
    const baseUrl = normalizeBaseUrl(
        process.env.SGP_WEB_BASE_URL ||
        process.env.SGP_URA_BASE_URL ||
        process.env.SGP_BASE_URL ||
        ""
    );
    const username = process.env.SGP_WEB_USERNAME || process.env.SGP_URA_USERNAME || process.env.SGP_USERNAME || "";
    const password = process.env.SGP_WEB_PASSWORD || process.env.SGP_URA_PASSWORD || process.env.SGP_PASSWORD || "";
    const enabled = isTruthy(process.env.SGP_WEB_TRAFFIC_ENABLED || process.env.SGP_TRAFFIC_ENABLED);

    return {
        enabled,
        baseUrl,
        username,
        password,
        timeoutMs: Math.max(1000, Number(process.env.SGP_WEB_TIMEOUT_SECONDS || DEFAULT_TIMEOUT_SECONDS) * 1000),
    };
};

const buildAvailability = () => {
    const config = getConfig();
    const missing = [];

    if (!config.enabled) missing.push("SGP_WEB_TRAFFIC_ENABLED");
    if (!config.baseUrl) missing.push("SGP_WEB_BASE_URL");
    if (!config.username) missing.push("SGP_WEB_USERNAME");
    if (!config.password) missing.push("SGP_WEB_PASSWORD");

    return {
        available: config.enabled && missing.length === 0,
        enabled: config.enabled,
        baseUrlConfigured: Boolean(config.baseUrl),
        usernameConfigured: Boolean(config.username),
        passwordConfigured: Boolean(config.password),
        missing,
        source: "sgp-web",
        message: config.enabled && missing.length === 0
            ? "Monitoramento de tráfego pelo SGP configurado."
            : "Monitoramento de tráfego pelo SGP ainda não configurado.",
    };
};

export const getSgpWebTrafficAvailability = () => buildAvailability();

const getCache = (cache, key) => {
    const item = cache.get(key);
    if (!item) return null;

    if (Date.now() > item.expiresAt) {
        cache.delete(key);
        return null;
    }

    return item.value;
};

const setCache = (cache, key, value, ttlMs) => {
    cache.set(key, {
        value,
        expiresAt: Date.now() + ttlMs,
    });
};

const readSetCookies = (headers) => {
    if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
    const cookie = headers.get("set-cookie");
    return cookie ? [cookie] : [];
};

const storeCookies = (response) => {
    readSetCookies(response.headers).forEach((cookie) => {
        const [pair] = String(cookie).split(";");
        const separator = pair.indexOf("=");
        if (separator <= 0) return;

        sessionState.cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
    });
};

const getCookieHeader = () => (
    Array.from(sessionState.cookies.entries())
        .map(([key, value]) => `${key}=${value}`)
        .join("; ")
);

const buildUrl = (path) => {
    const config = getConfig();
    if (/^https?:\/\//i.test(path)) return path;
    return `${config.baseUrl}${path.startsWith("/") ? path : `/${path}`}`;
};

const fetchWithTimeout = async (path, {
    method = "GET",
    headers = {},
    body = null,
    signal,
    redirect = "manual",
    timeoutMs = null,
} = {}) => {
    const config = getConfig();
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs || config.timeoutMs);
    const abortFromParent = () => controller.abort(signal?.reason);

    if (signal?.aborted) {
        clearTimeout(timeout);
        throw new Error("Operação cancelada.");
    }

    signal?.addEventListener("abort", abortFromParent, { once: true });

    try {
        const cookie = getCookieHeader();
        const response = await fetch(buildUrl(path), {
            method,
            headers: {
                ...(cookie ? { Cookie: cookie } : {}),
                ...headers,
            },
            body,
            redirect,
            signal: controller.signal,
        });

        storeCookies(response);
        return response;
    } finally {
        clearTimeout(timeout);
        signal?.removeEventListener("abort", abortFromParent);
    }
};

const extractCsrf = (html = "") => (
    String(html).match(/name=['"]csrfmiddlewaretoken['"]\s+value=['"]([^'"]+)/i)?.[1] ||
    sessionState.cookies.get("csrftoken") ||
    ""
);

const clearSession = () => {
    sessionState.cookies.clear();
    sessionState.expiresAt = 0;
};

const login = async ({ next = "/admin/", signal } = {}) => {
    const config = getConfig();

    clearSession();

    const loginPath = `/accounts/login/?next=${encodeURIComponent(next)}`;
    const loginResponse = await fetchWithTimeout(loginPath, { signal });
    const loginHtml = await loginResponse.text();
    const csrf = extractCsrf(loginHtml);

    if (!csrf) {
        throw new Error("Não foi possível obter CSRF do SGP.");
    }

    const body = new URLSearchParams({
        csrfmiddlewaretoken: csrf,
        username: config.username,
        password: config.password,
        next,
    });

    const postResponse = await fetchWithTimeout("/accounts/login/", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": String(Buffer.byteLength(body.toString())),
            Origin: config.baseUrl,
            Referer: `${config.baseUrl}${loginPath}`,
        },
        body: body.toString(),
        signal,
    });

    if (!sessionState.cookies.has("sessionid")) {
        const text = await postResponse.text();
        if (postResponse.status >= 400 || /id_username|login-form|csrfmiddlewaretoken/i.test(text)) {
            throw new Error("Login web no SGP não autorizado.");
        }
    }

    sessionState.expiresAt = Date.now() + DEFAULT_SESSION_TTL_MS;
};

const ensureSession = async ({ next = "/admin/", signal } = {}) => {
    const availability = buildAvailability();
    if (!availability.available) {
        const err = new Error(availability.message);
        err.statusCode = 503;
        err.details = availability;
        throw err;
    }

    if (sessionState.cookies.has("sessionid") && Date.now() < sessionState.expiresAt) return;

    if (!sessionState.loginPromise) {
        sessionState.loginPromise = login({ next, signal }).finally(() => {
            sessionState.loginPromise = null;
        });
    }

    await sessionState.loginPromise;
};

const isLoginResponse = (response, text = "") => (
    [301, 302, 303, 307, 308].includes(response.status) &&
    String(response.headers.get("location") || "").includes("/accounts/login")
) || /id_username|login-form|\/accounts\/login/i.test(text);

const requestText = async (path, {
    signal,
    headers = {},
    next = path,
    retry = true,
} = {}) => {
    await ensureSession({ next, signal });

    const response = await fetchWithTimeout(path, {
        headers: {
            Accept: "text/html,application/json,*/*",
            "X-Requested-With": "XMLHttpRequest",
            Referer: `${getConfig().baseUrl}${next}`,
            ...headers,
        },
        signal,
    });
    const text = await response.text();

    if (retry && isLoginResponse(response, text)) {
        clearSession();
        await ensureSession({ next, signal });
        return requestText(path, { signal, headers, next, retry: false });
    }

    if (!response.ok) {
        const err = new Error(`SGP web retornou HTTP ${response.status}.`);
        err.statusCode = response.status >= 400 && response.status < 500 ? 502 : 503;
        throw err;
    }

    return text;
};

export const extractSgpInternetServiceId = (html = "", contractId = "") => {
    const contractKey = String(contractId || "").trim();
    const infoMatches = Array.from(String(html).matchAll(/info_contrato_(\d+)_internet_(\d+)/gi));

    if (contractKey) {
        const exact = infoMatches.find((match) => String(match[1]) === contractKey);
        if (exact) return exact[2];
    }

    if (infoMatches.length) return infoMatches[0][2];

    return String(html).match(/\/admin\/servicos\/internet\/(\d+)\//i)?.[1] || null;
};

const getContractId = (customer = {}) => String(
    customer.contractId ||
    customer.contract_id ||
    customer.contrato_id ||
    customer.codigo_contrato ||
    customer.contrato ||
    customer.id ||
    ""
).trim();

const resolveServiceId = async (customer = {}, { signal } = {}) => {
    const contractId = getContractId(customer);
    if (!contractId) {
        const err = new Error("Contrato não informado para consultar tráfego no SGP.");
        err.statusCode = 400;
        throw err;
    }

    const cached = getCache(serviceCache, contractId);
    if (cached) return cached;

    const autocompleteText = await requestText(
        `/public/autocomplete/ClienteAutocomplete/?tconsulta=contrato&term=${encodeURIComponent(contractId)}`,
        { signal, next: "/admin/" }
    );
    const autocomplete = JSON.parse(autocompleteText);
    const clientUrl = Array.isArray(autocomplete) ? autocomplete[0]?.url : null;
    const clientId = String(clientUrl || "").match(/\/admin\/cliente\/(\d+)\/edit\//)?.[1];

    if (!clientId) {
        const err = new Error("Cliente não encontrado no SGP web para este contrato.");
        err.statusCode = 404;
        throw err;
    }

    const contractsHtml = await requestText(`/admin/cliente/${clientId}/contratos/`, {
        signal,
        next: clientUrl,
    });
    const serviceId = extractSgpInternetServiceId(contractsHtml, contractId);

    if (!serviceId) {
        const err = new Error("Serviço de internet não encontrado no contrato SGP.");
        err.statusCode = 404;
        throw err;
    }

    const result = {
        contractId,
        clientId,
        serviceId,
    };

    setCache(serviceCache, contractId, result, DEFAULT_SERVICE_CACHE_TTL_MS);
    return result;
};

export const normalizeSgpQueueTraffic = (payload = [], {
    customer = {},
    serviceId = null,
    raw = null,
} = {}) => {
    const items = Array.isArray(payload) ? payload : [];
    const txItem = items.find((item) => String(item?.name || "").toLowerCase() === "tx") || items[0] || {};
    const rxItem = items.find((item) => String(item?.name || "").toLowerCase() === "rx") || items[1] || {};
    const rawItem = items.find((item) => String(item?.name || "").toLowerCase() === "raw") || items[2] || {};
    const txBytesPerSecond = toNumberOrNull(txItem.data);
    const rxBytesPerSecond = toNumberOrNull(rxItem.data);
    const rawData = Array.isArray(rawItem.data)
        ? rawItem.data.map(toNumberOrNull).filter((value) => value !== null).slice(0, 2)
        : null;
    const hasPreviousRaw = Array.isArray(raw) && raw.length === 2;
    const downloadMbps = bytesPerSecondToMbps(txBytesPerSecond);
    const uploadMbps = bytesPerSecondToMbps(rxBytesPerSecond);

    return {
        available: true,
        online: customer.status ? customer.status === "online" : null,
        ip: customer.ip || null,
        username: customer.pppoeUsername || null,
        downloadMbps,
        uploadMbps,
        downloadPeakMbps: downloadMbps,
        uploadPeakMbps: uploadMbps,
        bytesReceived: rawData?.[0] ?? null,
        bytesSent: rawData?.[1] ?? null,
        txBytesPerSecond,
        rxBytesPerSecond,
        serviceId: serviceId ? String(serviceId) : null,
        sessionUptimeSeconds: customer.sessionUptimeSeconds ?? null,
        interface: null,
        popName: customer.popName || null,
        updatedAt: new Date().toISOString(),
        message: !hasPreviousRaw ? "Primeira amostra coletada; a próxima leitura calcula o tráfego atual." : null,
        source: "sgp-web",
    };
};

const buildQueueInfoPath = (serviceId, lastRaw = null) => {
    if (!Array.isArray(lastRaw) || lastRaw.length < 2) {
        return `/admin/servicos/internet/${serviceId}/queue/info/`;
    }

    const params = new URLSearchParams();
    params.append("last_result[]", String(lastRaw[0]));
    params.append("last_result[]", String(lastRaw[1]));
    return `/admin/servicos/internet/${serviceId}/queue/info/?${params.toString()}`;
};

const unavailable = (message, details = {}) => ({
    available: false,
    online: null,
    ip: null,
    username: null,
    downloadMbps: null,
    uploadMbps: null,
    downloadPeakMbps: null,
    uploadPeakMbps: null,
    sessionUptimeSeconds: null,
    interface: null,
    updatedAt: new Date().toISOString(),
    message,
    details,
    source: "sgp-web",
});

export const getSgpWebCurrentTraffic = async (customer = {}, { signal } = {}) => {
    const availability = buildAvailability();

    if (!availability.available) {
        return unavailable(availability.message, availability);
    }

    try {
        const { serviceId } = await resolveServiceId(customer, { signal });
        const rawKey = String(serviceId);
        const previousRaw = getCache(rawCache, rawKey);
        const text = await requestText(buildQueueInfoPath(serviceId, previousRaw), {
            signal,
            next: `/admin/servicos/internet/${serviceId}/infodetail/`,
            headers: {
                Accept: "application/json, text/javascript, */*; q=0.01",
            },
        });
        const payload = JSON.parse(text);
        const traffic = normalizeSgpQueueTraffic(payload, {
            customer,
            serviceId,
            raw: previousRaw,
        });

        if (traffic.bytesReceived !== null && traffic.bytesSent !== null) {
            setCache(rawCache, rawKey, [traffic.bytesReceived, traffic.bytesSent], DEFAULT_RAW_CACHE_TTL_MS);
        }

        return traffic;
    } catch (err) {
        console.warn("[SGP Web] Tráfego indisponível:", sanitizeForLog({
            hasCustomerId: Boolean(customer.id),
            hasContractId: Boolean(customer.contractId),
            error: err.message,
            statusCode: err.statusCode || null,
        }));

        return unavailable("Não foi possível consultar tráfego em tempo real pelo SGP.", {
            statusCode: err.statusCode || null,
            error: err.message,
        });
    }
};

/** Lê uma página do SGP web (GET) com o login do servidor, seguindo redirecionamentos. Só leitura. `timeoutMs` para exportações grandes. */
export const sgpWebGet = async (path, { signal, timeoutMs } = {}) => {
    await ensureSession({ signal });
    const response = await fetchWithTimeout(path, { signal, redirect: "follow", timeoutMs });
    return { status: response.status, url: response.url, html: await response.text() };
};
