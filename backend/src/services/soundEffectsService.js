import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PUBLIC_SOUNDS_ROOT = path.resolve(__dirname, "../../../frontend/public/sounds");
export const CUSTOM_SOUNDS_ROOT = path.join(PUBLIC_SOUNDS_ROOT, "custom");
export const CUSTOM_SOUNDS_MANIFEST_PATH = path.join(CUSTOM_SOUNDS_ROOT, "manifest.json");
export const SOUND_EFFECT_UPLOAD_MAX_SIZE_BYTES = 8 * 1024 * 1024;
export const SOUND_EFFECT_UPLOAD_EXTENSIONS = [".mp3", ".wav", ".ogg", ".opus", ".webm", ".m4a", ".mp4", ".aac", ".flac"];
export const SOUND_EFFECT_UPLOAD_MIME_TYPES = [
    "application/octet-stream",
    "audio/mpeg",
    "audio/mp3",
    "audio/aac",
    "audio/mp4",
    "audio/m4a",
    "audio/x-m4a",
    "audio/flac",
    "audio/x-flac",
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
    "audio/ogg",
    "audio/opus",
    "audio/webm",
    "video/webm",
    "application/ogg",
];

export const DEFAULT_SOUND_EFFECTS = Object.freeze({
    faaaa: { key: "faaaa", label: "FAAAA", path: "/sounds/faaaa.wav", custom: false },
    vine_boom: { key: "vine_boom", label: "Vine Boom", path: "/sounds/vine-boom.wav", custom: false },
    metal_pipe: { key: "metal_pipe", label: "Metal Pipe", path: "/sounds/metal-pipe.wav", custom: false },
    windows_error: { key: "windows_error", label: "Windows Error", path: "/sounds/windows-error.wav", custom: false },
    bruh: { key: "bruh", label: "Bruh", path: "/sounds/bruh.wav", custom: false },
    minecraft_cave: { key: "minecraft_cave", label: "Minecraft Cave", path: "/sounds/minecraft-cave.wav", custom: false },
});

const ensureCustomSoundStorage = () => {
    fs.mkdirSync(CUSTOM_SOUNDS_ROOT, { recursive: true });

    if (!fs.existsSync(CUSTOM_SOUNDS_MANIFEST_PATH)) {
        fs.writeFileSync(CUSTOM_SOUNDS_MANIFEST_PATH, "[]\n");
    }
};

export const normalizeSoundEffectLabel = (label = "", fallback = "Audio enviado") => {
    const normalizado = String(label || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 80);

    return normalizado || fallback;
};

const slugify = (value = "") => (
    String(value || "")
        .normalize("NFD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "")
        .slice(0, 42)
        || "audio"
);

export const normalizeSoundUploadExtension = (filename = "") => {
    const valor = String(filename || "").toLowerCase();
    const ext = valor.startsWith(".") ? valor : path.extname(valor);
    return SOUND_EFFECT_UPLOAD_EXTENSIONS.includes(ext) ? ext : "";
};

export const isAllowedSoundUploadMime = (mime = "") => (
    SOUND_EFFECT_UPLOAD_MIME_TYPES.includes(String(mime || "").toLowerCase())
);

export const createSoundUploadFilename = (originalName = "audio.wav") => {
    const ext = normalizeSoundUploadExtension(originalName) || ".wav";
    const base = slugify(path.basename(String(originalName || "audio"), path.extname(String(originalName || ""))));
    return `${Date.now()}-${crypto.randomBytes(6).toString("hex")}-${base}${ext}`;
};

export const readCustomSoundManifest = () => {
    ensureCustomSoundStorage();

    try {
        const raw = fs.readFileSync(CUSTOM_SOUNDS_MANIFEST_PATH, "utf8");
        const parsed = JSON.parse(raw);

        if (!Array.isArray(parsed)) return [];

        return parsed
            .filter((sound) => sound?.key && sound?.path && sound?.label)
            .map((sound) => ({
                ...sound,
                custom: true,
            }));
    } catch (err) {
        console.error("[SOUND_EFFECTS] Erro ao ler manifesto de sons:", err);
        return [];
    }
};

const writeCustomSoundManifest = (sounds = []) => {
    ensureCustomSoundStorage();
    fs.writeFileSync(CUSTOM_SOUNDS_MANIFEST_PATH, `${JSON.stringify(sounds, null, 2)}\n`);
};

// Sons do sistema que o dono dos efeitos apagou (os arquivos ficam, só saem da lista).
const REMOVED_DEFAULTS_PATH = path.join(CUSTOM_SOUNDS_ROOT, "removed-defaults.json");

const readRemovedDefaults = () => {
    try {
        const parsed = JSON.parse(fs.readFileSync(REMOVED_DEFAULTS_PATH, "utf8"));
        return new Set(Array.isArray(parsed) ? parsed.map((k) => String(k)) : []);
    } catch {
        return new Set();
    }
};

export const listAllowedSoundEffects = () => {
    const removed = readRemovedDefaults();
    return [
        ...Object.values(DEFAULT_SOUND_EFFECTS).filter((sound) => !removed.has(sound.key)),
        ...readCustomSoundManifest(),
    ];
};

/** Apaga um efeito sonoro: o enviado sai do manifesto e o arquivo é removido; o do sistema só sai da lista. null = não existe. */
export const deleteSoundEffect = (soundKey = "") => {
    const key = String(soundKey || "").trim().toLowerCase();
    if (!key) return null;

    const manifest = readCustomSoundManifest();
    const custom = manifest.find((sound) => sound.key === key);
    if (custom) {
        writeCustomSoundManifest(manifest.filter((sound) => sound.key !== key).map(({ custom: _c, ...rest }) => rest));
        removeUploadedSoundFile(custom.filename || path.basename(custom.path || ""));
        return custom;
    }

    const removed = readRemovedDefaults();
    const padrao = Object.values(DEFAULT_SOUND_EFFECTS).find((sound) => sound.key === key);
    if (!padrao || removed.has(key)) return null;
    removed.add(key);
    ensureCustomSoundStorage();
    fs.writeFileSync(REMOVED_DEFAULTS_PATH, `${JSON.stringify([...removed], null, 2)}\n`);
    return padrao;
};

export const getAllowedSoundEffect = (soundKey = "") => {
    const key = String(soundKey || "").trim().toLowerCase();
    if (!key) return null;

    return listAllowedSoundEffects().find((sound) => sound.key === key) || null;
};

export const validateUploadedAudioFile = (filePath, extension) => {
    const ext = normalizeSoundUploadExtension(extension || filePath);

    if (!ext || !fs.existsSync(filePath)) {
        return false;
    }

    const fd = fs.openSync(filePath, "r");

    try {
        const buffer = Buffer.alloc(16);
        const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);

        if (bytesRead < 4) return false;

        if (ext === ".wav") {
            return buffer.toString("ascii", 0, 4) === "RIFF"
                && buffer.toString("ascii", 8, 12) === "WAVE";
        }

        if (ext === ".mp3") {
            return buffer.toString("ascii", 0, 3) === "ID3"
                || (buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0);
        }

        if (ext === ".ogg") {
            return buffer.toString("ascii", 0, 4) === "OggS";
        }

        if (ext === ".opus") {
            return buffer.toString("ascii", 0, 4) === "OggS";
        }

        if (ext === ".webm") {
            return buffer[0] === 0x1a
                && buffer[1] === 0x45
                && buffer[2] === 0xdf
                && buffer[3] === 0xa3;
        }

        if (ext === ".m4a" || ext === ".mp4") {
            return buffer.toString("ascii", 4, 8) === "ftyp";
        }

        if (ext === ".aac") {
            return buffer[0] === 0xff && (buffer[1] & 0xf0) === 0xf0;
        }

        if (ext === ".flac") {
            return buffer.toString("ascii", 0, 4) === "fLaC";
        }

        return false;
    } finally {
        fs.closeSync(fd);
    }
};

export const removeUploadedSoundFile = (filename = "") => {
    const safeName = path.basename(String(filename || ""));
    if (!safeName) return;

    const filePath = path.join(CUSTOM_SOUNDS_ROOT, safeName);

    if (filePath.startsWith(CUSTOM_SOUNDS_ROOT) && fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
    }
};

export const registerUploadedSoundEffect = ({
    file,
    label,
    admin,
} = {}) => {
    if (!file?.filename || !file?.path) {
        throw new Error("Arquivo de áudio não recebido.");
    }

    const manifest = readCustomSoundManifest();
    const soundLabel = normalizeSoundEffectLabel(label, path.basename(file.originalname || file.filename, path.extname(file.originalname || file.filename)));
    const baseKey = `custom_${slugify(soundLabel)}`;
    const keys = new Set([...Object.keys(DEFAULT_SOUND_EFFECTS), ...manifest.map((sound) => sound.key)]);
    let key = baseKey;

    while (keys.has(key)) {
        key = `${baseKey}_${crypto.randomBytes(3).toString("hex")}`;
    }

    const entry = {
        key,
        label: soundLabel,
        path: `/sounds/custom/${file.filename}`,
        filename: file.filename,
        original_name: file.originalname || file.filename,
        mime: file.mimetype || null,
        size: file.size || null,
        uploaded_by: admin?.id || null,
        uploaded_by_name: admin?.nome || null,
        uploaded_at: new Date().toISOString(),
        custom: true,
    };

    manifest.push(entry);
    writeCustomSoundManifest(manifest);

    return entry;
};
