import os
import sys
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModelForSequenceClassification

print("📊 Code Security Report (CodeBERT AI - Branch: main)\n")

# Baca daftar file yang berubah dari file input
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

print(">> File yang berubah:")
print("\n".join(changed_files))

# Filter ekstensi file yang relevan
target_exts = [".js", ".php", ".html", ".css", ".py"]
target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]

if not target_files:
    print("✅ Tidak ada file relevan untuk dianalisis.")
    sys.exit(0)

# Load model dari HuggingFace
model_name = "fahru1712/codebert-vuln-web-finetune" 
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

# Mapping prediksi
labels_map = {
    0: "Aman",
    1: "Medium",
    2: "High",
    3: "Critical",
}

# Warnanya
color_map = {
    "Critical": "\033[91m",
    "High": "\033[93m",
    "Medium": "\033[93m",
    "Aman": "\033[92m",
}
reset_color = "\033[0m"

def analyze_code_snippet(code, file_path, line_num):
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)

    logits = outputs.logits
    probs = F.softmax(logits, dim=-1)
    pred_class = torch.argmax(probs, dim=-1).item()
    risk = labels_map.get(pred_class, "Unknown")
    color = color_map.get(risk, "\033[0m")
    icon = "❗" if risk != "Aman" else "✅"

    print(f"{color}{icon} Tingkat: {risk}{reset_color}")
    print(f"{color}📄 File: {file_path}{reset_color}")
    print(f"{color}🔢 Baris: {line_num}{reset_color}")
    print(f"{color}🔎 Kode: {code.strip()}{reset_color}\n")

def scan_files(file_list):
    for filepath in file_list:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
                for line_num, line in enumerate(file, 1):
                    if line.strip():
                        analyze_code_snippet(line, filepath, line_num)
        else:
            print(f"⚠️ File tidak ditemukan: {filepath}")

# Mulai scan file-file yang berubah
scan_files(target_files)
