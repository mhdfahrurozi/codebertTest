// Bagian aman - deklarasi konfigurasi default
const defaultConfig = {
    theme: "light",
    language: "en",
    version: 1.0
};

// Bagian aman - fungsi utilitas validasi
function isValidConfig(config) {
    return typeof config === 'object' &&
           ['light', 'dark'].includes(config.theme) &&
           typeof config.language === 'string';
}

// Bagian aman - contoh penggunaan konfigurasi default
const currentConfig = { ...defaultConfig };
console.log("Current configuration is safe to use.");

// Bagian aman - contoh penggunaan fungsi validasi
const sampleInput = {
    theme: "dark",
    language: "id"
};
if (isValidConfig(sampleInput)) {
    console.log("Input configuration is valid.");
}

// ==========================
// VULNERABLE SECTION BELOW
// ==========================

const obj = {};
const input = JSON.parse(userProvidedJson);
Object.assign(obj, input); // ⚠️ Vulnerable line: Object injection if input contains __proto__, constructor, etc.

// ==========================
// END OF VULNERABLE SECTION
// ==========================

// Bagian aman - fungsi pemrosesan tambahan
function processConfig(config) {
    console.log("Processing configuration...");
    // aman karena hanya membaca data
    return {
        themeUpper: config.theme.toUpperCase(),
        langLength: config.language.length
    };
}

const processed = processConfig(currentConfig);
console.log("Processed Config:", processed);
