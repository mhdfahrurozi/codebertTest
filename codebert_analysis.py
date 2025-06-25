import os
import sys
import json
import re
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModel, AutoConfig, PreTrainedModel
from huggingface_hub import hf_hub_download

# --- Setup Logging ---
class Logger:
    def __init__(self):
        self.summary = []
        self.detailed = []

logger = Logger()

# --- Load Changed Files ---
def load_changed_files(input_file):
    try:
        with open(input_file, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"❌ Gagal membaca daftar file: {e}")
        sys.exit(1)

# --- Model Setup ---
def setup_model():
    model_id = "fahru1712/codebert-mtl"
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    config = AutoConfig.from_pretrained(model_id)
    
    severity_map_path = hf_hub_download(model_id, "severity_label_map.json")
    vuln_map_path = hf_hub_download(model_id, "vuln_label_map.json")
    
    with open(severity_map_path) as f:
        severity_label_map = json.load(f)
    with open(vuln_map_path) as f:
        vuln_label_map = json.load(f)
    
    return {
        'tokenizer': tokenizer,
        'config': config,
        'inv_severity_map': {v: k for k, v in severity_label_map.items()},
        'inv_vuln_map': {v: k for k, v in vuln_label_map.items()},
        'num_severity': len(severity_label_map),
        'num_vuln': len(vuln_label_map)
    }

# --- Model Definition ---
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
        return {
            "logits_severity": self.classifier_severity(pooled_output),
            "logits_vuln": self.classifier_vuln(pooled_output)
        }

# --- Analysis Core ---
def analyze_files(target_files, model_config):
    model = CodeBERTMultiTask.from_pretrained(
        "fahru1712/codebert-mtl",
        config=model_config['config'],
        num_severity=model_config['num_severity'],
        num_vuln=model_config['num_vuln']
    )
    model.eval()
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)

    for file_path in target_files:
        analyze_file(file_path, model, model_config)

# --- File Analysis ---
def analyze_file(filepath, model, model_config):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        logger.detailed.append(f"⚠️ Gagal membaca {filepath}: {e}")
        return

    in_style_block = False

    file_results = []
    for line_num, line in enumerate(lines, 1):  # Start from line 1
        code = line.strip()
        if "<style" in code.lower():
            in_style_block = True
        if "</style>" in code.lower():
            in_style_block = False
            continue  # skip the closing tag line

        if not code or is_ignorable_line(code, filepath) or in_style_block:
            continue

        result = analyze_line(code, model, model_config, line_num)  # Pass line_num
        if result:
            file_results.append(result)
            logger.detailed.append(format_detailed_result(filepath, line_num, result, code))

    if file_results:
        logger.summary.append(f"🔍 {filepath} ({len(lines)} baris)")
        logger.summary.extend([f"- Line #{r['line']}, Severity: {r['severity']}, Vulnerability: {r['vulnerability']}" 
                             for r in file_results])
        logger.summary.append("")

# --- Line Analysis ---
def analyze_line(code, model, model_config, line_num):  # Added line_num parameter
    inputs = model_config['tokenizer'](code, return_tensors="pt", padding="max_length", 
                                     truncation=True, max_length=256).to(model.device)
    with torch.no_grad():
        outputs = model(**inputs)
        sev_idx = torch.argmax(outputs["logits_severity"], dim=1).item()
        vul_idx = torch.argmax(outputs["logits_vuln"], dim=1).item()

    severity = model_config['inv_severity_map'].get(sev_idx, "Unknown")
    vulnerability = model_config['inv_vuln_map'].get(vul_idx, "Unknown")

    if severity.lower() != "none":
        return {
            'line': line_num,  # Use passed line_num
            'severity': severity,
            'vulnerability': vulnerability
        }
    return None


def is_ignorable_line(line, filepath):
    import re

    line = line.strip().lower()

    # Abaikan baris kosong
    if not line:
        return True

    # Abaikan komentar umum
    COMMENT_PATTERNS = [r"^\s*//", r"^\s*/\*", r"\*/", r"^\s*#", r"^\s*<!--", r"^\s*-->"]
    if any(re.match(pattern, line) for pattern in COMMENT_PATTERNS):
        return True

    # Deteksi baris seperti HTML meskipun file-nya .php atau .js
    looks_like_html = bool(re.match(r"^\s*</?\w+", line)) or bool(re.search(r"</?\w+>", line))

    if filepath.endswith(('.html', '.xml')) or looks_like_html:
        if line.strip() in ("<script>", "</script>"):
            return True
            
        IGNORED_HTML_PATTERNS = [
            r"^<!doctype", r"^<\?xml", r"^<!--", r"^-->", 
            r"^<html", r"^<head", r"^<meta", r"^<link", r"^<style", r"^<title",
            r"^<body", r"^<div", r"^<span", r"^<p", r"^<h[1-6]", r"^<br", r"^<footer", r"^<section",
            r"^<article", r"^<main",
            r"^</?(html|head|body|div|p|h[1-6]|section|footer|label|title|meta|link|style|main)>?",
        ]
        if any(re.match(p, line) for p in IGNORED_HTML_PATTERNS):
            return True

        # Deteksi teks biasa di HTML
        if (
            not re.search(r"[;{}()=<>]", line) and
            not re.search(r"(script|alert|onerror|onload|eval|document\.|window\.)", line) and
            len(line) < 200
        ):
            return True

    # Deteksi teks natural biasa (bukan kode) di semua jenis file
    is_natural_text = (
        not re.search(r"[;{}()=<>\"']", line) and
        not re.search(r"(script|alert|onerror|onload|eval|document\.|window\.)", line) and
        len(line.split()) > 5 and
        len(re.findall(r"\w+", line)) > 5 and
        line[0].isalpha() and line[-1] in ".?!"
    )
    if is_natural_text:
        return True

    return False



def format_detailed_result(filepath, line_num, result, code):
    return (
        f"🔍 File: {filepath} (Line {line_num})\n"
        f"Severity      : {result['severity']}\n"
        f"Vulnerability : {result['vulnerability']}\n"
        f"Code Preview  : {code}\n"
        f"{'-'*50}"
    )

def write_report():
    with open("codebert-report.log", "w") as f:
        f.write("="*50 + "\n")
        f.write("🔍 CODEBERT SECURITY ANALYSIS REPORT\n")
        f.write("="*50 + "\n\n")

        f.write("[[SUMMARY]]\n")
        f.write("📊 Ringkasan Hasil Analisis:\n\n")

        if logger.summary:
            f.write("\n".join(logger.summary) + "\n\n")
        else:
            f.write("✅ Tidak ditemukan kerentanan\n\n")

        f.write("="*50 + "\n")
        f.write("[[DETAILED FINDINGS]]\n")
        f.write("📋 Detail Temuan Kerentanan:\n\n")
        f.write("\n".join(logger.detailed) if logger.detailed else "Tidak ada temuan.")


# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Error: Harap tentukan file input")
        sys.exit(1)

    changed_files = load_changed_files(sys.argv[1])
    if not changed_files:
        print("✅ Tidak ada file yang diubah")
        sys.exit(0)

    target_exts = ['.php', '.html', '.js']
    target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]
    
    if not target_files:
        print("✅ Tidak ada file yang relevan")
        sys.exit(0)

    model_config = setup_model()
    analyze_files(target_files, model_config)
    write_report()

    total_vuln = len(logger.detailed)
    if total_vuln == 0:
        with open(os.environ['GITHUB_ENV'], 'a') as f:
            f.write("NO_VULN=true\n")
