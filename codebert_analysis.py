import os
import sys
import json
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel, AutoConfig, PreTrainedModel
from huggingface_hub import hf_hub_download

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
model_id = "fahru1712/codebert-mtl"

tokenizer = AutoTokenizer.from_pretrained(model_id)
config = AutoConfig.from_pretrained(model_id)

severity_map_path = hf_hub_download(model_id, "severity_label_map.json")
vuln_map_path = hf_hub_download(model_id, "vuln_label_map.json")

with open(severity_map_path) as f:
    severity_label_map = json.load(f)
with open(vuln_map_path) as f:
    vuln_label_map = json.load(f)

inv_severity_map = {v: k for k, v in severity_label_map.items()}
inv_vuln_map = {v: k for k, v in vuln_label_map.items()}

num_severity = len(severity_label_map)
num_vuln = len(vuln_label_map)

class CodeBERTMultiTask(PreTrainedModel):
    def __init__(self, config, num_severity, num_vuln):
        super().__init__(config)
        self.codebert = AutoModel.from_config(config)
        self.dropout = nn.Dropout(0.1)
        self.classifier_severity = nn.Linear(config.hidden_size, num_severity)
        self.classifier_vuln = nn.Linear(config.hidden_size, num_vuln)

    def forward(self, input_ids, attention_mask=None):
        outputs = self.codebert(input_ids=input_ids, attention_mask=attention_mask)
        pooled_output = self.dropout(outputs.last_hidden_state[:, 0])
        logits_severity = self.classifier_severity(pooled_output)
        logits_vuln = self.classifier_vuln(pooled_output)
        return {
            "logits_severity": logits_severity,
            "logits_vuln": logits_vuln
        }

model = CodeBERTMultiTask.from_pretrained(
    model_id,
    config=config,
    num_severity=num_severity,
    num_vuln=num_vuln
)
model.eval()
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model.to(device)

# --- HTML Line Filter ---
def is_ignorable_html_line(line):
    IGNORED_TAGS = [
        "<!doctype", "<html", "</html>", "<head", "</head>", "<meta", "<title", "</title>",
        "<body", "</body>", "<footer", "</footer>", "<h1", "<h2", "<h3", "<p", "</p>", "<br",
        "<form", "</form>", "<div", "</div>", "<section", "</section>", "<!--", "-->", "</script>", "</style>"
    ]
    line = line.strip().lower()
    return any(line.startswith(tag) for tag in IGNORED_TAGS) or line.startswith("<!--") or line.startswith("-->")

# --- Analyze Per Line ---
def analyze_file_by_line(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"⚠️ Gagal membaca {filepath}: {e}")
        return

    file_results = []
    for i, line in enumerate(lines):
        code = line.strip()
        if not code or is_ignorable_html_line(code):
            continue

        inputs = tokenizer(code, return_tensors="pt", padding="max_length", truncation=True, max_length=256).to(device)
        with torch.no_grad():
            outputs = model(**inputs)
            sev_idx = torch.argmax(outputs["logits_severity"], dim=1).item()
            vul_idx = torch.argmax(outputs["logits_vuln"], dim=1).item()

        severity = inv_severity_map.get(sev_idx, "Unknown")
        vulnerability = inv_vuln_map.get(vul_idx, "Unknown")

        if severity.lower() != "none":
            file_results.append({
                "line": i + 1,
                "severity": severity,
                "vulnerability": vulnerability,
                "code": code
            })

    if file_results:
        print(f"🔍 {filepath} ({len(lines)} baris)")
        for result in file_results:
            print(f"- Line #{result['line']}, Severity: {result['severity']}, Vulnerability: {result['vulnerability']}")
        print()  # Add empty line between files

# --- Jalankan Analisis ---
for file_path in target_files:
    analyze_file_by_line(file_path)
