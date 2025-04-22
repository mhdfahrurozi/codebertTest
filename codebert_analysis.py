from transformers import RobertaTokenizer, RobertaModel
import torch
import os
import subprocess

print("📊 Code Security Report (CodeBERT AI - Smart File Detection)\n")

def get_changed_files():
    try:
        return subprocess.check_output(
            ["git", "diff", "--name-only", "origin/main...HEAD"],
            encoding="utf-8"
        ).splitlines()
    except Exception:
        print("⚠️ Gagal diff origin/main...HEAD, coba fallback ke HEAD")
        try:
            return subprocess.check_output(
                ["git", "show", "--pretty=", "--name-only", "HEAD"],
                encoding="utf-8"
            ).splitlines()
        except Exception as e:
            print(f"🚨 Gagal ambil file dari HEAD: {e}")
            return []


changed_files = get_changed_files()

# 🔍 Debug: tampilkan file yang akan dianalisis
print(">> Changed files:")
print("\n".join(changed_files))

# Filter hanya file target (JS, PHP, HTML, CSS)
target_exts = [".js", ".php", ".html", ".css"]
target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]

# Load CodeBERT
tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
model = RobertaModel.from_pretrained("microsoft/codebert-base")

def analyze_code_snippet(code, file_path, line_num):
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
    cls_embedding = outputs.last_hidden_state[:, 0, :]
    score = torch.sigmoid(cls_embedding.mean()).item()

    if score > 0.75:
        risk = "Tinggi"
    elif score > 0.5:
        risk = "Sedang"
    elif score > 0.3:
        risk = "Rendah"
    else:
        risk = "Aman"

    print(f"{'❗' if risk != 'Aman' else '✅'} Tingkat: {risk}")
    print(f"File: {file_path}")
    print(f"Baris: {line_num}")
    print(f"Kode: {code.strip()}\n")

# Analisis
for file_path in target_files:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f.readlines(), start=1):
                if len(line.strip()) > 10:
                    analyze_code_snippet(line.strip(), file_path, i)
    except Exception as e:
        print(f"⚠️ Gagal analisa {file_path}: {e}")

if not target_files:
    print("✅ Tidak ada file yang relevan untuk dianalisis.")
