from docx import Document
from docx.shared import Pt, Cm, Inches
from docx.enum.text import WD_PARAGRAPH_ALIGNMENT
from datetime import date
import subprocess

def add_header(document):
    # Add Header
    header_section = document.sections[0]
    header = header_section.header
    header_paragraph = header.paragraphs[0]
    header_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.LEFT
    
    # Add the logo
    logo_path = "Logo Horizontal.png"
    logo_height = Cm(1.5)
    run = header_paragraph.add_run()
    run.add_picture(logo_path, height=logo_height)
    
    # Add space after header
    header.add_paragraph()

def create_cover_page(document):
    add_header(document)
    
    # Add the logo image
    document.add_picture('tri.png', width=Inches(2))
    document.paragraphs[-1].alignment = WD_PARAGRAPH_ALIGNMENT.CENTER  # Center align the image
    
    # Add spacer
    document.add_paragraph()
    document.paragraphs[-1].add_run().add_break()
    
    while len(document.paragraphs) % 4 != 0:
        document.add_paragraph()
    
    title = """Sample Penetration Test Report
    Example Company"""
    document.add_heading(title, level=0).alignment = WD_PARAGRAPH_ALIGNMENT.CENTER  # Center align the text
    
    # Add spacer
    document.add_paragraph()
    document.paragraphs[-1].add_run().add_break()
    
    while len(document.paragraphs) % 14 != 0:
        document.add_paragraph()
    
    # Add details
    text = f"""
    Company: Customer Name
    Date: {date.today().strftime('%d %B %Y')}
    Version 1.0"""
    document.add_paragraph(text)

def add_pendahuluan(document):
    document.add_heading("Pendahuluan", level=2)
    pendahuluan_paragraph = document.add_paragraph()
    pendahuluan_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
    pendahuluan_text = (
        "Laporan ini disusun sebagai hasil pengujian penetrasi terhadap CVE-2022-46169, "
        "sebuah kerentanan yang ditemukan dalam perangkat lunak Cacti. Kerentanan ini "
        "memungkinkan serangan tanpa autentikasi untuk melakukan eksekusi perintah sistem "
        "secara sewenang-wenang pada server yang menjalankan Cacti. Dalam laporan ini, kami "
        "akan memberikan detail mengenai temuan kerentanan CVE-2022-46169 yang kami identifikasi "
        "selama penilaian. Kami akan menjelaskan dengan rinci potensi dampak dan risiko yang "
        "terkait dengan kerentanan ini, serta memberikan rekomendasi tindakan untuk memperbaiki "
        "kerentanan tersebut dan meningkatkan keamanan sistem secara menyeluruh."
    )
    pendahuluan_paragraph.add_run(pendahuluan_text)

def add_ruang_lingkup(document):
    document.add_heading("Ruang Lingkup", level=2)
    ruang_lingkup_paragraph = document.add_paragraph()
    ruang_lingkup_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
    ruang_lingkup_text = (
        "Evaluasi keamanan sistem informasi pada Cacti dilakukan di lingkungan produksi "
        "dengan melakukan upaya peretasan berdasarkan kerentanan yang ditemukan. Host dan "
        "alamat IP yang diuji adalah sebagai berikut:"
    )
    ruang_lingkup_paragraph.add_run(ruang_lingkup_text)
    
    # Add the hosts and IP addresses
    hosts = [
        ("Sistem Utama", "10.33.102.224"),
        ("Target", "10.33.102.225"),
        ("Target", "10.33.102.226")
    ]
    for host, ip in hosts:
        document.add_paragraph(f"- Host: {host}, IP: {ip}", style='List Bullet')

def add_metodologi(document):
    document.add_heading("Metodologi", level=2)
    metodologi_paragraph = document.add_paragraph()
    metodologi_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY # Rata kanan-kiri
    metodologi_text = (
        "Metodologi yang digunakan dalam pengujian penetrasi ini terdiri dari beberapa tahap "
        "yang sistematis untuk memastikan pengujian yang menyeluruh dan efektif. Tahap-tahap "
        "ini meliputi information gathering, vulnerability scanning, vulnerability analysis, "
        "vulnerability exploitation, recommendation and reporting. Metodologi ini dirancang untuk "
        "mengidentifikasi dan mengatasi potensi celah keamanan dalam sistem secara menyeluruh."
    )
    metodologi_paragraph.add_run(metodologi_text)


def add_vulnerability_identification(document):
    document.add_heading("Identifikasi Kerentanan", level=2)
    identification_paragraph = document.add_paragraph()
    identification_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY # Rata kanan-kiri
    identification_text = (
        "Pemindaian menggunakan Nmap pada alamat IP 10.33.102.212, 10.33.102.225, dan 10.33.102.226 "
        "dilakukan dengan perintah nmap -sV -sC -Pn --script http-title -iL targets.txt -oN nmap_results.txt. "
        "Perintah ini digunakan untuk memindai jaringan terhadap sejumlah alamat IP yang terdaftar dalam file targets.txt. "
        "Hasil pemindaian mencakup identifikasi versi perangkat lunak yang berjalan, eksekusi skrip otomatis untuk analisis keamanan, "
        "dan pengambilan judul halaman utama dari server web yang terdeteksi. Informasi hasil pemindaian akan disimpan dalam file "
        "nmap_results.txt untuk referensi dan analisis lebih lanjut."
    )
    identification_paragraph.add_run(identification_text)

    # Adding content from nmap_results.txt
    with open("nmap_results.txt", "r") as scan_file:
        scan_content = scan_file.read()
    document.add_paragraph(scan_content)
    
    scan_results = (
        "\n\nHasil pemindaian menunjukkan bahwa pada alamat IP 10.33.102.225:\n"
        "- Port 22/tcp terbuka dengan layanan SSH menggunakan OpenSSH versi 8.2p1 pada Ubuntu.\n"
        "- Port 80/tcp terbuka dengan layanan HTTP menggunakan Apache HTTP Server versi 2.4.54 pada Debian, "
        "judul halamannya adalah 'Login to Cacti'.\n"
        "- Sistem operasi yang terdeteksi adalah Linux.\n\n"
        
        "Pada alamat IP 10.33.102.226:\n"
        "- Port 22/tcp terbuka dengan layanan SSH menggunakan OpenSSH versi 8.9p1 pada Ubuntu.\n"
        "- Port 80/tcp terbuka dengan layanan HTTP menggunakan Apache HTTP Server versi 2.4.52 pada Ubuntu, "
        "judul halamannya adalah 'Login to Cacti'.\n"
        "- Sistem operasi yang terdeteksi adalah Linux.\n\n"
        
        "Informasi hasil pemindaian ini disimpan dalam file nmap_results.txt untuk referensi dan analisis lebih lanjut."
    )
    
    document.add_paragraph(scan_results)
    
def add_vulnerability_scanning(document):
    document.add_heading("Vulnerability Scanning", level=2)
    scanning_paragraph = document.add_paragraph()
    scanning_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
    scanning_text = (
        "Vulnerability scanning dilakukan menggunakan perangkat lunak Metasploit. Metasploit adalah open-source, "
        "platform pengujian penetrasi berbasis Ruby yang memungkinkan pengguna untuk menulis, menguji, dan mengeksekusi "
        "kode eksploit. Sistem pengujian penetrasi atau pengujian pena bekerja dengan mensimulasikan serangan cyber untuk "
        "memeriksa kerentanan yang rentan. Dibawah ini menampilkan hasil dari pemindaian kerentanan yang ditemukan oleh Metasploit."
    )
    scanning_paragraph.add_run(scanning_text)
    
    # Add vulnerability scan results from file
    with open("vuln_scan.txt", "r") as vuln_file:
        vuln_content = vuln_file.read()
    document.add_paragraph(vuln_content)
    
    # Add additional information about specific vulnerabilities
    additional_info = (
        "Metasploit melakukan pemindaian kerentanan pada target sistem dan berhasil mengidentifikasi bahwa alamat IP "
        "10.33.102.225, pada port 80, menjalankan aplikasi Cacti versi 1.2.22 yang rentan, dengan "
        "celah keamanan yang dapat dieksploitasi. Sementara itu, target dengan alamat IP 10.33.102.226 menjalankan aplikasi "
        "Cacti versi 1.2.27 yang tidak rentan terhadap eksploitasi yang sama seperti versi sebelumnya, mungkin karena telah "
        "diperbarui atau diperbaiki untuk menutup kerentanan yang ada pada versi 1.2.22."
    )
    document.add_paragraph(additional_info)

def add_vulnerability_exploitation(document):
    document.add_heading("Vulnerability Exploitation", level=2)
    exploitation_paragraph = document.add_paragraph()
    exploitation_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
    exploitation_text = (
        "Pada bagian ini, dilakukan beberapa serangan untuk menguji kerentanan yang telah "
        "diidentifikasi sebelumnya. Serangan pertama adalah eksploitasi kerentanan Command Injection "
        "pada aplikasi Cacti menggunakan Metasploit. Langkah ini dilakukan untuk memanfaatkan celah "
        "keamanan yang ditemukan dalam versi 1.2.22 dari Cacti, dengan tujuan memperoleh akses ilegal "
        "ke dalam sistem yang rentan."
    )
    exploitation_paragraph.add_run(exploitation_text)
    document.add_paragraph("10.33.102.225")
    with open("10.33.102.225_exploit.txt", "r") as exploit_file:
        exploit_content = exploit_file.read()
    document.add_paragraph(exploit_content)

    # Add additional information about exploitation
    additional_info = (
        "Metasploit berhasil mengeksploitasi kerentanan yang ada pada aplikasi Cacti versi 1.2.22 yang dijalankan pada "
        "alamat IP 10.33.102.225 dengan menggunakan port 80. Dalam proses eksploitasi ini, Metasploit "
        "menggunakan payload linux/x86/meterpreter/reverse_tcp untuk menciptakan koneksi TCP terbalik dari target ke alamat "
        "IP Metasploit (10.33.102.224) pada port 4444. Meskipun awalnya eksploitasi tidak menghasilkan sesi Meterpreter, "
        "setelah beberapa upaya tambahan termasuk bruteforce terhadap host_id dan local_data_id, Metasploit berhasil memperoleh akses.\n\n"
        "Hasilnya, sesi Meterpreter berhasil dibuka, memberikan penyerang kontrol penuh terhadap sistem target. Melalui sesi ini, "
        "penyerang menggunakan perintah ls -la untuk menjelajahi isi direktori dari perspektif pengguna www-data. Informasi yang "
        "diperoleh dari hasil eksekusi perintah tersebut memungkinkan penyerang untuk memahami struktur file serta hak akses yang "
        "terkait dengan aplikasi Cacti yang disusupi."
    )
    exploitation_paragraph.add_run(additional_info) 

def add_recommendations(document):
    document.add_heading("Recommendation", level=2)
    recommendations_paragraph = document.add_paragraph()
    recommendations_paragraph.alignment = WD_PARAGRAPH_ALIGNMENT.JUSTIFY  # Rata kanan-kiri
    recommendations_text = "Untuk mengurangi risiko dari CVE-2022-46169, disarankan untuk mengambil langkah-langkah berikut:"
    recommendations_paragraph.add_run(recommendations_text)

    # Add the recommendations list
    recommendations_list = [
        "Memperbarui Cacti ke versi terbaru yang tersedia.",
        "Menerapkan aturan firewall yang membatasi akses ke layanan Cacti.",
        "Melakukan evaluasi keamanan secara berkala dan pengujian penetrasi untuk mengidentifikasi dan mengatasi kerentanan.",
        "Menerapkan kebijakan sandi yang kuat dan menghindari penggunaan kredensial default.",
        "Rutin memperbarui perangkat untuk mengatasi masalah keamanan."
    ]
    for recommendation in recommendations_list:
        document.add_paragraph(recommendation, style='List Bullet')


def generate_report():
    # Create a new Word document
    document = Document()

    # Generate the cover page
    create_cover_page(document)

    # Add Pendahuluan
    add_pendahuluan(document)

    # Add Ruang Lingkup
    add_ruang_lingkup(document)

    # Add Metodologi
    add_metodologi(document)

    # Add Vulnerability Identification
    add_vulnerability_identification(document)

    # Add Vulnerability Scanning
    add_vulnerability_scanning(document)

    # Add Vulnerability Exploitation
    add_vulnerability_exploitation(document)

    # Add Recommendations
    add_recommendations(document)

    # Save the document
    document.save("Penetration_Test_Report.docx")

    # Convert to PDF
    subprocess.run(["unoconv", "-f", "pdf", "Penetration_Test_Report.docx"], stderr=subprocess.DEVNULL)

    print("Penetration test report generated successfully.")

if __name__ == "__main__":
    generate_report()
