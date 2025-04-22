from transformers import RobertaTokenizer, RobertaModel
import torch
import os
import sys

print("📊 Code Security Report (CodeBERT AI - Branch: main)\n")

# Mengambil daftar file yang diubah (melalui parameter yang diteruskan ke skrip)
changed_files = sys.argv[1:]  # File yang akan dianalisis diteruskan sebagai argumen

if not changed_files:
    print("✅ Tidak ada file yang diubah untuk dianalisis.")
    sys.exit()

print(">> File yang berubah di branch main:")
print("\n".join(changed_files))

# Filter ekstensi file yang relevan untuk analisis
target_exts = [".js", ".php", ".html", ".css"]
target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]

# Inisialisasi tokenizer dan model dari CodeBERT
tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
model = RobertaModel.from_pretrained("microsoft/codebert-base")

# Fungsi untuk menganalisis kode snippet
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

# Analisis file yang relevan
for file_path in target_files:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f.readlines(), start=1):
                if len(line.strip()) > 10:
                    analyze_code_snippet(line.strip(), file_path, i)
    except Exception as e:
        print(f"⚠️ Gagal analisa {file_path}: {e}")

if not target_files:
    print("✅ Tidak ada file relevan yang berubah di branch main.")
