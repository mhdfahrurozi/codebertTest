const obj = {};
const input = JSON.parse(userProvidedJson);
Object.assign(obj, input); // Vulnerable line



const userCode = inputFromUser;
eval(userCode); // Vulnerable line



// Static encryption key used in production (BAD PRACTICE)
const crypto = require('crypto');
const key = '1234567890abcdef'; // Vulnerable line



function encrypt(text) {
    const cipher = crypto.createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0));
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

console.log(encrypt("secret"));


const userSettings = JSON.parse(req.body.config);
let defaultSettings = { theme: "light" };

// Menyisipkan input user ke object default tanpa filter
Object.assign(defaultSettings, userSettings);  // ⚠️ Potensi prototype pollution
// test_generalized.jsonl baris ke-2

document.cookie = "session=abc123";
console.log("Current cookie:", document.cookie);

