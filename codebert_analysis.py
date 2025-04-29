import os

def analyze_code_snippet(code, file_path, line_num):
    # Mulai dengan tingkat "Aman"
    risk = "Aman"
    
    # Analisis sederhana berdasarkan pola kode yang bisa menunjukkan kerentanannya
    if "eval(" in code or "exec(" in code:
        risk = "Tinggi"  # Remote Code Execution
    elif "SELECT" in code and "FROM" in code and "$id" in code:
        risk = "Tinggi"  # SQL Injection
    elif "<script>" in code and "alert(" in code:
        risk = "Sedang"  # Cross Site Scripting (XSS)
    elif "action=" in code and "http" in code:
        risk = "Tinggi"  # Insecure Form Action
    elif "include(" in code or "require(" in code:
        risk = "Tinggi"  # File Inclusion
    
    # Menampilkan hasil analisis
    print(f"{'❗' if risk != 'Aman' else '✅'} Tingkat: {risk}")
    print(f"📄 File: {file_path}")
    print(f"🔢 Baris: {line_num}")
    print(f"🔎 Kode: {code.strip()}\n")

def scan_files(file_list):
    for filepath in file_list:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
                for line_num, line in enumerate(file, 1):
                    if line.strip():
                        analyze_code_snippet(line.strip(), filepath, line_num)
        else:
            print(f"⚠️ File tidak ditemukan: {filepath}")

# Daftar file yang ingin dianalisis
changed_files = ["test.php", "file1.php", "file2.js"]

# Fungsi untuk menganalisis file yang diubah
scan_files(changed_files)
