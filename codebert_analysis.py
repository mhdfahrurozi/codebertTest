import os
import sys
import json
import torch
import torch.nn as nn
import re
from transformers import AutoTokenizer, AutoModel, AutoConfig, PreTrainedModel
from huggingface_hub import hf_hub_download

# --- Enhanced Logger ---
class Logger:
    def __init__(self):
        self.summary = []
        self.detailed = []
        self.stats = {
            'files_processed': 0,
            'vulnerabilities_found': 0,
            'false_positives_caught': 0
        }

logger = Logger()

# --- Load Changed Files ---
def load_changed_files(input_file):
    try:
        with open(input_file, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"❌ Failed to read file list: {e}")
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

# --- Advanced Filtering System ---
def is_false_positive(code, filepath):
    """Enhanced false positive detection with filetype awareness"""
    SAFE_PATTERNS = {
        'all': [
            r'^[\w\s.,!?\'"\-]+$',  # Plain text
            r'^<\?xml\b',           # XML declaration
            r'^<!--.*-->$'          # HTML comments
        ],
        '.html': [
            r'^</?(html|head|body|div|span|p|br|section|footer|header|nav|ul|ol|li)\b',
            r'^<(meta|title|link|style|script)\s[^>]*>',
            r'^\{\{.+?\}\}'         # Template variables
        ],
        '.js': [
            r'^//.*',               # JS comments
            r'^import\s.+',         # ES6 imports
            r'^export\s.+'
        ]
    }

    # Check against universal safe patterns
    for pattern in SAFE_PATTERNS['all']:
        if re.fullmatch(pattern, code, re.IGNORECASE):
            return True

    # Check filetype-specific patterns
    for ext, patterns in SAFE_PATTERNS.items():
        if filepath.endswith(ext):
            for pattern in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    return True

    return False

def is_ignorable_line(line, filepath):
    """Check for structural/boilerplate code"""
    line = line.strip()
    if not line:
        return True
        
    # Filetype-specific ignore rules
    if filepath.endswith('.html'):
        HTML_IGNORE = [
            r'^<!doctype', r'^<!--', r'^-->',
            r'^</?(html|head|body|div|section|footer|header|nav|ul|ol|li|p|br)\b',
            r'^<(meta|title|link|style|script)\s[^>]*>'
        ]
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in HTML_IGNORE)
        
    elif filepath.endswith('.js'):
        JS_IGNORE = [
            r'^//', r'^/\*', r'^\*/',
            r'^import\s', r'^export\s',
            r'^}\s*$', r'^{\s*$'  # Braces only
        ]
        return any(re.search(pattern, line, re.IGNORECASE) for pattern in JS_IGNORE)
        
    return False

# --- Core Analysis Functions ---
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
        logger.stats['files_processed'] += 1

def analyze_file(filepath, model, model_config):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception as e:
        logger.detailed.append(f"⚠️ Failed to read {filepath}: {e}")
        return

    file_results = []
    for line_num, line in enumerate(lines, 1):
        code = line.strip()
        if not code or is_ignorable_line(code, filepath):
            continue

        # Skip verified false positives before model inference
        if is_false_positive(code, filepath):
            logger.stats['false_positives_caught'] += 1
            continue

        result = analyze_line(code, model, model_config, line_num)
        if result:
            file_results.append(result)
            logger.stats['vulnerabilities_found'] += 1
            logger.detailed.append(format_detailed_result(filepath, line_num, result, code))

    if file_results:
        logger.summary.append(f"🔍 {filepath} ({len(lines)} lines)")
        logger.summary.extend([
            f"- Line #{r['line']}, Severity: {r['severity']}, Vulnerability: {r['vulnerability']}"
            for r in file_results
        ])
        logger.summary.append("")

def analyze_line(code, model, model_config, line_num):
    inputs = model_config['tokenizer'](
        code,
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=256
    ).to(model.device)

    with torch.no_grad():
        outputs = model(**inputs)
        sev_idx = torch.argmax(outputs["logits_severity"], dim=1).item()
        vul_idx = torch.argmax(outputs["logits_vuln"], dim=1).item()

    severity = model_config['inv_severity_map'].get(sev_idx, "Unknown")
    vulnerability = model_config['inv_vuln_map'].get(vul_idx, "Unknown")

    if severity.lower() != "none":
        return {
            'line': line_num,
            'severity': severity,
            'vulnerability': vulnerability
        }
    return None

# --- Reporting Functions ---
def format_detailed_result(filepath, line_num, result, code):
    return (
        f"🔍 File: {filepath} (Line {line_num})\n"
        f"Severity      : {result['severity']}\n"
        f"Vulnerability : {result['vulnerability']}\n"
        f"Code Preview  : {code[:100]}{'...' if len(code) > 100 else ''}\n"
        f"{'-'*50}"
    )

def write_report():
    with open("codebert-report.log", "w", encoding="utf-8") as f:
        f.write("="*50 + "\n")
        f.write("🔍 CODEBERT SECURITY ANALYSIS REPORT\n")
        f.write("="*50 + "\n\n")
        
        f.write("[[ STATISTICS ]]\n")
        f.write(f"📊 Files Processed: {logger.stats['files_processed']}\n")
        f.write(f"🔎 Vulnerabilities Found: {logger.stats['vulnerabilities_found']}\n")
        f.write(f"🚫 False Positives Caught: {logger.stats['false_positives_caught']}\n\n")
        
        f.write("[[ SUMMARY ]]\n")
        f.write("📊 Analysis Summary:\n\n")
        f.write("\n".join(logger.summary) + "\n\n")
        
        f.write("="*50 + "\n")
        f.write("[[ DETAILED FINDINGS ]]\n")
        f.write("📋 Vulnerability Details:\n\n")
        f.write("\n".join(logger.detailed))

# --- Main Execution ---
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Error: Please specify input file")
        sys.exit(1)

    changed_files = load_changed_files(sys.argv[1])
    if not changed_files:
        print("✅ No files changed")
        sys.exit(0)

    target_exts = ['.php', '.html', '.js']
    target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]
    
    if not target_files:
        print("✅ No relevant files found")
        sys.exit(0)

    model_config = setup_model()
    analyze_files(target_files, model_config)
    write_report()
