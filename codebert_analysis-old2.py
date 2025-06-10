from transformers import AutoTokenizer, AutoModel
import torch
import sys
import os

print("📊 Code Security Report (CodeBERT MTL: Severity + Vulnerability Type)\n")

# --- Load Changed Files ---
if len(sys.argv) < 2:
    print("❌ Tidak ada file yang diteruskan ke skrip.")
    sys.exit(1)

input_file = sys.argv[1]
try:
    with open(input_file, "r") as f:
        changed_files = [line.strip() for line in f if line.strip()]
except Exception as e:
    print(f"❌ Gagal membaca daftar file: {e}")
    sys.exit(1)

if not changed_files:
    print("✅ Tidak ada file yang diubah untuk dianalisis.")
    sys.exit(0)

ext_language_map = {
    ".php": "PHP",
    ".html": "HTML",
    ".js": "JavaScript"
}
target_exts = list(ext_language_map.keys())
target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]

if not target_files:
    print("✅ Tidak ada file relevan yang berubah.")
    sys.exit(0)

# --- Load MTL Model ---
model_name = "fahru1712/codebert-vuln-web-finetune"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModel.from_pretrained(model_name)
model.eval()

# Label mapping sesuai saat fine-tuning
severity_map = {0: "Critical", 1: "High", 2: "Medium", 3: "Low", 4: "None"}
vuln_map = {
    0: "XSS", 1: "SQL Injection", 2: "Hardcoded Credential", 3: "CSRF",
    4: "Path Traversal", 5: "Command Injection", 6: "Insecure Redirect",
    7: "Open Redirect", 8: "LFI", 9: "RFI", 10: "Clickjacking", 11: "Other"
}

def analyze_code_snippet(code, file_path, line_num):
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)

    with torch.no_grad():
        outputs = model(**inputs)
        logits_severity = outputs.logits_severity
        logits_vuln = outputs.logits_vuln

        probs_sev = torch.softmax(logits_severity, dim=1)
        probs_vuln = torch.softmax(logits_vuln, dim=1)

        pred_sev_id = torch.argmax(probs_sev, dim=1).item()
        pred_vuln_id = torch.argmax(probs_vuln, dim=1).item()

        severity = severity_map.get(pred_sev_id, "Unknown")
        vuln_type = vuln_map.get(pred_vuln_id, "Unknown")

        if severity == "None":
            return

        print(f"❗ Severity: {severity}")
        print(f"Jenis kerentanan: {vuln_type}")
        print(f"File: {file_path}")
        print(f"Line: {line_num}")
        print(f"Code: {code.strip()}\n")

# --- Analyze files line-by-line (sliding window) ---
WINDOW_SIZE = 5

for file_path in target_files:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.rstrip() for line in f.readlines() if line.strip()]

        for i in range(len(lines) - WINDOW_SIZE + 1):
            snippet = "\n".join(lines[i:i + WINDOW_SIZE])
            start_line = i + 1
            analyze_code_snippet(snippet, file_path, start_line)

    except Exception as e:
        print(f"⚠️ Gagal analisa {file_path}: {e}")
