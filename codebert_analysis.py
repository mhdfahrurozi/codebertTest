from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch
import sys
import os

print("📊 Code Security Report (CodeBERT AI - Fine-tuned for Vulnerability Severity)\n")

# Ambil file yang berubah
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

# Filter hanya file dengan ekstensi tertentu
ext_language_map = {
    ".php": "PHP",
    ".html": "HTML",
    ".js": "JavaScript",
    ".css": "CSS"
}
target_exts = list(ext_language_map.keys())
target_files = [f for f in changed_files if any(f.endswith(ext) for ext in target_exts)]

# Load model & tokenizer dari Hugging Face Hub
model_name = "fahru1712/codebert-severity"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)
model.eval()

# Label mapping sesuai saat training
label_map = {
    0: "Critical",
    1: "High",
    2: "Low",
    3: "Medium",
    4: "None"
}

def analyze_code_snippet(code, file_path, line_num):
    inputs = tokenizer(code, return_tensors="pt", truncation=True, max_length=512)
    with torch.no_grad():
        outputs = model(**inputs)
        logits = outputs.logits
        probs = torch.softmax(logits, dim=1)
        pred_label = torch.argmax(probs, dim=1).item()
        confidence = probs[0][pred_label].item()

    severity = label_map.get(pred_label, "Unknown")
    if severity == "None":
        return

    ext = os.path.splitext(file_path)[1]
    language = ext_language_map.get(ext, "Unknown")

    print(f"- Language: {language}")
    print(f"- Code: {code.strip()}")
    print(f"- Severity: {severity} ({confidence:.2f})")
    print(f"- File: {file_path}")
    print(f"- Line: {line_num}\n")

# Proses setiap baris kode
for file_path in target_files:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f.readlines(), start=1):
                if len(line.strip()) > 10:
                    analyze_code_snippet(line.strip(), file_path, i)
    except Exception as e:
        print(f"⚠️ Gagal analisa {file_path}: {e}")

if not target_files:
    print("✅ Tidak ada file relevan yang berubah.")
