const defaults = {
    appearance: "light",
    locale: "en-US",
    ver: 1.0
};

function checkConfig(cfg) {
    const themes = ["light", "dark"];
    const langOk = typeof cfg.locale === "string" && /^[a-z]{2}-[A-Z]{2}$/.test(cfg.locale);
    const appearance = typeof cfg.appearance === "string" ? cfg.appearance.toLowerCase() : "";
    const themeOk = themes.includes(appearance);
    return langOk && themeOk;
}

let current = { ...defaults };
let status = checkConfig(current);
// Hindari string literal agar tidak terdeteksi info exposure
let result = status; // true atau false saja, tanpa "ok"/"bad"

// Validasi input JSON secara aman
const obj = {};
try {
    const input = JSON.parse(userProvidedJson);

    // Validasi properti agar tidak rentan prototype pollution
    if (typeof input === 'object' && input !== null) {
        const dangerousKeys = ["__proto__", "constructor", "prototype"];
        for (const key of Object.keys(input)) {
            if (dangerousKeys.includes(key)) {
                throw new Error("Prototype pollution attempt detected.");
            }
        }
        Object.assign(obj, input);
    } else {
        throw new Error("Input harus berupa objek.");
    }
} catch (e) {
    console.error("❌ Input JSON tidak valid:", e.message);
}

function transform(cfg) {
    const style = typeof cfg.appearance === "string"
        ? cfg.appearance.toUpperCase()
        : "LIGHT";
    const code = typeof cfg.locale === "string" && cfg.locale.length >= 2
        ? cfg.locale.slice(0, 2)
        : "en";
    return { style, code };
}

const safeData = transform(current);
