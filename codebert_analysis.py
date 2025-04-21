# codebert_analysis.py

import os
import re

print("📊 Code Security Report (Static Analysis v2 - Multi-language)\n")

patterns = {
    ".js": [
        {"pattern": r"\beval\s*\(", "risk": "Tinggi", "type": "JavaScript eval()"},
        {"pattern": r"innerHTML\s*=", "risk": "Sedang", "type": "Direct DOM Manipulation"},
        {"pattern": r"document\.write\s*\(", "risk": "Sedang", "type": "Document Write Usage"}
    ],
    ".php": [
        {"pattern": r"\beval\s*\(", "risk": "Tinggi", "type": "PHP eval()"},
        {"pattern": r"\b(system|exec|passthru)\s*\(", "risk": "Tinggi", "type": "Command Execution"},
        {"pattern": r"\$_(GET|POST|REQUEST|COOKIE)\s*\[", "risk": "Sedang", "type": "User Input Without Sanitization"}
    ],
    ".html": [
        {"pattern": r"<script.*?>", "risk": "Sedang", "type": "Inline Script Tag"},
    ],
    ".css": [
        {"pattern": r"expression\s*\(", "risk": "Rendah", "type": "CSS Expression (Deprecated)"}
    ]
}

def analyze_file(file_path, ext):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for i, line in enumerate(lines, start=1):
                for p in patterns[ext]:
                    if re.search(p["pattern"], line):
                        print(f"❗ Tingkat: {p['risk']}")
                        print(f"Jenis: {p['type']}")
                        print(f"File: {file_path}")
                        print(f"Baris: {i}")
                        print(f"Kode: {line.strip()}\n")
    except Exception as e:
        print(f"⚠️ Error analyzing {file_path}: {e}")

for root, dirs, files in os.walk("."):
    for file in files:
        ext = os.path.splitext(file)[1]
        if ext in patterns:
            analyze_file(os.path.join(root, file), ext)
