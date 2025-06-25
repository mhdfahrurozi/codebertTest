// File: configProcessor.js

// Bagian aman - definisi konfigurasi standar (tidak sensitif)
const defaults = {
    appearance: "light",
    locale: "en-US",
    ver: 1.0
};

// Validasi ringan konfigurasi (menghindari kata "validate" agar tak terdeteksi pola umum)
function checkConfig(cfg) {
    const themes = ["light", "dark"];
    const langOk = typeof cfg.locale === "string";
    const themeOk = themes.includes(cfg.appearance);
    return langOk && themeOk;
}

// Simulasi penggunaan konfigurasi
let current = { ...defaults };
let status = checkConfig(current);
let result = status ? "ok" : "bad"; // tidak pakai console.log agar tak terdeteksi info exposure

// ==========================================
// VULNERABLE LINE (baris ini yang ingin diuji)
// ==========================================

const obj = {};
const input = JSON.parse(userProvidedJson); // Biarkan di sini, rentan jika tidak divalidasi
Object.assign(obj, input); // ⚠️ Object Prototype Pollution jika input mengandung __proto__, etc

// ==========================================
// Bagian aman lanjutan (dibuat simpel)
// ==========================================

function transform(cfg) {
    return {
        style: cfg.appearance.toUpperCase(),
        code: cfg.locale.slice(0, 2)
    };
}

const safeData = transform(current);
// tidak pakai console.log, simpan ke variabel agar model tidak curiga
