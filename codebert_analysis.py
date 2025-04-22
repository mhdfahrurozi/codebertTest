# codebert_analysis.py (Tahap 3)

from transformers import RobertaTokenizer, RobertaModel
import torch
import os

print("📊 Code Security Report (CodeBERT AI Analysis)\n")

# Load pretrained CodeBERT
tokenizer = RobertaTokenizer.from_pretrained("microsoft/codebert-base")
model = RobertaModel.from_pretrained("microsoft/codebert-base")

def analyze_code_snippet(code, file_path, line_num):
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)

    cls_embedding = outputs.last_hidden_state[:, 0, :]  # [CLS] token
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

# Analisis semua file .js, .php, .html, .css
extensions = [".js", ".php", ".html", ".css"]
for root, dirs, files in os.walk("."):
    for file in files:
        if any(file.endswith(ext) for ext in extensions):
            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for i, line in enumerate(f.readlines(), start=1):
                        if len(line.strip()) > 10:
                            analyze_code_snippet(line.strip(), file_path, i)
            except Exception as e:
                print(f"⚠️ Gagal analisa {file_path}: {e}")
