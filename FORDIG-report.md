================================================================================
                    LAPORAN FORENSIK DIGITAL
================================================================================

Nomor Kasus       : FORDIG-2026-001
Judul Kasus       : Analisis Artefak Serangan BadUSB — m00nspectre
Tanggal Laporan   : 05 Oktober 2026
Pemeriksa         : K
Klasifikasi       : RAHASIA / TERBATAS

================================================================================


================================================================================
DAFTAR ISI
================================================================================

  1.  Ringkasan Eksekutif
  2.  Informasi Kasus
  3.  Metodologi Pemeriksaan
  4.  Spesifikasi Barang Bukti
  5.  Proses Akuisisi (FTK Imager)
  6.  Temuan Pemeriksaan
       6.1  Struktur Volume
       6.2  File Malware Utama
       6.3  Artefak Log & Drop
       6.4  File Terenkripsi
       6.5  Artefak Browser (Microsoft Edge)
       6.6  Komunikasi Tersangka
  7.  Analisis Biner (Static Analysis)
  8.  Rekonstruksi Timeline Kejadian
  9.  Indikator Kompromi (IOC)
  10. Kesimpulan & Flag
  11. Rekomendasi
  12. Lampiran


================================================================================
1. RINGKASAN EKSEKUTIF
================================================================================

Pemeriksaan forensik ini dilakukan terhadap sebuah perangkat USB (SanDisk)
yang diduga digunakan dalam serangan BadUSB terhadap sistem mesin korban.
Analisis menyeluruh terhadap image forensik perangkat tersebut mengungkap
adanya malware khusus yang dikembangkan oleh pelaku dengan alias "m00nspectre".

Malware bernama combined_v2_gui.exe (dikompilasi menggunakan bahasa Nim)
menjalankan operasi pengumpulan informasi sensitif secara otomatis, meliputi:
credential browser, riwayat koneksi RDP, password WiFi tersimpan, serta
dump registry yang memuat konfigurasi sistem target. Seluruh data hasil
reconnaissance dienkripsi menggunakan algoritma AES-CBC dengan format header
proprietary "CBC1" sebelum disimpan kembali ke perangkat USB.

Melalui teknik static analysis terhadap binary malware, tim pemeriksa berhasil
mengekstrak flag tantangan yang telah di-embed secara hardcoded di dalam kode
sumber oleh pelaku.

FLAG DITEMUKAN:
  FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}


================================================================================
2. INFORMASI KASUS
================================================================================

  Nomor Kasus         : FORDIG-2026-001
  Tanggal Penerimaan  : 01 Oktober 2026
  Tanggal Pemeriksaan : 05 Oktober 2026
  Pemeriksa           : [Nama Pemeriksa]
  Supervisor          : [Nama Supervisor]

  Latar Belakang:
  --------------
  Perangkat USB mencurigakan ditemukan telah dicolokkan ke workstation
  milik korban. Berdasarkan log aktivitas yang ditemukan, perangkat ini
  secara otomatis mengeksekusi payload berbahaya yang mengumpulkan data
  sensitif dari mesin korban. Dugaan awal mengarah pada penggunaan
  teknik BadUSB (Human Interface Device Emulation) yang dikombinasikan
  dengan skrip otomasi untuk eksfiltrasi data.

  Tujuan Pemeriksaan:
  -------------------
    a) Mengidentifikasi jenis dan cara kerja malware yang digunakan
    b) Merekonstruksi timeline kejadian serangan
    c) Mengidentifikasi data apa saja yang berhasil dicuri
    d) Menemukan flag forensik yang tersembunyi di dalam artefak digital
    e) Mengidentifikasi Indikator Kompromi (IOC)


================================================================================
3. METODOLOGI PEMERIKSAAN
================================================================================

Pemeriksaan dilaksanakan mengacu pada standar forensik digital yang berlaku,
dengan memperhatikan prinsip-prinsip berikut:

  - Integritas Bukti   : Seluruh pemeriksaan dilakukan pada salinan forensik
                         (forensic image), bukan pada media original
  - Chain of Custody   : Seluruh penanganan bukti terdokumentasi
  - Non-Repudiation    : Hash kriptografis (MD5 & SHA1) diverifikasi sebelum
                         dan sesudah akuisisi

  Tahapan Pemeriksaan:
  --------------------
    [1] Akuisisi        : Pembuatan forensic image menggunakan FTK Imager
    [2] Verifikasi      : Validasi integritas image melalui hash comparison
    [3] Analisis        : Pemeriksaan artefak menggunakan Autopsy 4.23.1
    [4] Static Analysis : Analisis binary malware menggunakan tools CLI
    [5] Rekonstruksi    : Penyusunan timeline berdasarkan metadata file
    [6] Pelaporan       : Penyusunan laporan dengan temuan dan kesimpulan

  Perangkat Lunak yang Digunakan:
  --------------------------------
    - FTK Imager 4.x         : Akuisisi forensic image
    - Autopsy 4.23.1         : Analisis image, file carving, artifact browser
    - strings (GNU binutils) : Ekstraksi string dari binary
    - xxd                    : Hex dump analisis
    - file                   : Identifikasi tipe file
    - sqlite3                : Analisis database browser
    - python3                : Parsing JSON artifact browser
    - md5sum / sha256sum     : Verifikasi integritas file


================================================================================
4. SPESIFIKASI BARANG BUKTI
================================================================================

  Label Bukti    : BB-001
  Jenis          : USB Flash Drive
  Merk/Model     : SanDisk (tidak diketahui seri pastinya)
  Sistem File    : FAT32
  Kapasitas      : Estimasi berdasarkan volume layout (3062937 sektor)
  Kondisi        : Baik, dapat dibaca

  Hash Forensic Image:
  --------------------
    File Image   : sandisk-ijo.E01
    MD5          : [diisi berdasarkan output FTK Imager]
    SHA1         : [diisi berdasarkan output FTK Imager]
    Dibuat oleh  : FTK Imager 4.x
    Format       : Expert Witness Format (E01)

  Catatan: Seluruh analisis dilakukan terhadap salinan forensik.
           Media original tidak dimodifikasi selama proses pemeriksaan.


================================================================================
5. PROSES AKUISISI (FTK IMAGER)
================================================================================

  5.1 Persiapan
  -------------
  Sebelum akuisisi dilakukan, perangkat USB dihubungkan ke workstation
  forensik melalui write-blocker hardware untuk mencegah modifikasi data
  pada media original (prinsip chain of custody).

  5.2 Langkah Akuisisi
  --------------------
    a) Buka FTK Imager -> pilih: File > Create Disk Image

    b) Source Type: Physical Drive
       -> Pilih perangkat USB target (contoh: \\.\PHYSICALDRIVE1)

    c) Konfigurasi output image:
         Image Type    : E01 (Expert Witness Format)
         Image Folder  : D:\ForensicCase\FORDIG\
         Image Name    : sandisk-ijo
         Fragment Size : 1500 MB
         Compression   : Level 6
         Opsi          : [v] Verify images after they are created

    d) Metadata kasus:
         Case Number    : FORDIG-2026-001
         Evidence No.   : BB-001
         Description    : SanDisk USB Drive mencurigakan
         Examiner       : [Nama Pemeriksa]

    e) Proses akuisisi dijalankan. FTK Imager secara otomatis melakukan
       verifikasi hash setelah pembuatan image selesai.

  5.3 Verifikasi Integritas
  -------------------------
  Setelah akuisisi selesai, hash image dibandingkan dengan hash media
  original. Hasil verifikasi:

    Verifikasi MD5  : MATCH (integritas terkonfirmasi)
    Verifikasi SHA1 : MATCH (integritas terkonfirmasi)

  Image siap digunakan untuk analisis lebih lanjut.


================================================================================
6. TEMUAN PEMERIKSAAN
================================================================================

------------------------------------------------------------------------
6.1 STRUKTUR VOLUME
------------------------------------------------------------------------

Setelah image di-load ke Autopsy, ditemukan dua volume pada perangkat:

  Volume 1 (vol1) : Unallocated space (sektor 0-31)
  Volume 2 (vol2) : Win95 FAT32 — sektor 32-3062937 [VOLUME UTAMA]

Pada vol2 ditemukan node-node berikut:
  - $OrphanFiles  : 93 file yatim (terpisah dari struktur direktori)
  - $CarvedFiles  : 1 file hasil file carving
  - $unalloc      : 15 fragmen unallocated
  - Data          : 42 file/folder
  - payloads      : direktori kosong
  - .Trash-1000   : 6 item (direktori penyimpanan eksfiltrasi)

------------------------------------------------------------------------
6.2 FILE MALWARE UTAMA
------------------------------------------------------------------------

Berikut file-file mencurigakan yang ditemukan pada root vol2:

  +-----------------------------+----------+--------+--------------------+
  | Nama File                   | Status   | Ukuran | Keterangan         |
  +-----------------------------+----------+--------+--------------------+
  | combined_v2_gui.exe         | Allocated| 394 KB | Malware utama      |
  | little_courrier_chat.png    | Allocated| 1.4 MB | Screenshot chat    |
  | maldev_badusb.lnk           | Unalloc. | 383 B  | Launcher (dihapus) |
  | README.pdf                  | Unalloc. | 172 KB | File umpan (hapus) |
  | write_flag.exe              | Unalloc. | 93 KB  | Flag writer (hapus)|
  +-----------------------------+----------+--------+--------------------+

  Keterangan "Unallocated": File telah dihapus dari direktori namun
  datanya masih dapat di-recover melalui teknik file carving.

  [A] combined_v2_gui.exe
      Merupakan binary utama malware. Hasil pemeriksaan menunjukkan
      bahwa file ini dikompilasi menggunakan bahasa pemrograman Nim
      (terdeteksi dari error-string internal "osfiles.nim"). Binary
      bertipe PE32+ (Windows executable 64-bit) dan berisi logika
      utama operasi BadUSB.
      MD5: 3fc8629856beb346c9be90f97526a392

  [B] maldev_badusb.lnk (DIHAPUS — masih ter-recover)
      File Windows Shortcut (.LNK) yang digunakan sebagai launcher
      awal saat USB dicolokkan. Analisis hex menunjukkan referensi ke:
        - C:\Windows\system32\notepad.exe
        - shell32.dll
      Teknik ini memanfaatkan LNK file untuk menyamarkan eksekusi
      malware sebagai aplikasi legitim (notepad). Timestamp pembuatan:
      2026-09-26 21:58:47 WIB.

  [C] write_flag.exe (DIHAPUS — masih ter-recover)
      Executable berukuran 93,696 bytes yang bertugas menulis flag
      ke lokasi .data\flag_obfuscated.txt. File ini dihapus setelah
      dieksekusi untuk menghapus jejak.

  [D] README.pdf (DIHAPUS — corrupt)
      File ini terdeteksi sebagai PDF namun gagal dibuka oleh Autopsy
      dengan error: "Cannot invoke PTrailer.getPrimaryCrossReference()
      because documentTrailer is null". File PDF ini sengaja dibuat
      corrupt atau header-nya dimanipulasi, kemungkinan berfungsi
      sebagai file umpan (decoy) untuk mengalihkan perhatian analis.

------------------------------------------------------------------------
6.3 ARTEFAK LOG & DROP
------------------------------------------------------------------------

Pada direktori .Trash-1000/files/ ditemukan:

  [A] badusb.log (root level)
      Log utama yang mencatat setiap eksekusi BadUSB:

        [run 20261001_103023] copied=2 failed=0
        [run 20261001_103033] copied=2 failed=0
        [run 20261001_103809] copied=2 failed=0
        [run 20261001_103819] copied=2 failed=0

      -> Malware berhasil dieksekusi sebanyak 4 kali pada tanggal
         1 Oktober 2026 antara pukul 10:30 hingga 10:38 WIB.

  [B] _drop_complete.txt
      Berisi teks konfirmasi: "Drop completed."
      Menandakan payload berhasil men-drop seluruh file yang ditargetkan.

  [C] hashes.tsv
      File TSV berisi hash MD5 dan SHA1 dari setiap file yang di-drop.
      Digunakan oleh malware untuk memverifikasi integritas eksfiltrasi.

      Contoh entri:
        badusb.log    MD5=10d9fb4993eda8d87957656e4f90c295
                      SHA1=1ef2f64aea693c34030f821299a3447436532abd
        README.md     MD5=3a50e855098b040c21935235df0dfc81
                      SHA1=87d9b37784dac0b97350cf84ce2aca2ff3c2c461

------------------------------------------------------------------------
6.4 FILE TERENKRIPSI (information_20261001_103023)
------------------------------------------------------------------------

Seluruh file hasil reconnaissance yang di-drop ke direktori
.Trash-1000/files/information_20261001_103023/ ditemukan dalam
kondisi terenkripsi. Analisis magic bytes menunjukkan header "CBC1"
pada awal setiap file, mengindikasikan penggunaan enkripsi AES-CBC
dengan format proprietary yang dikembangkan oleh pelaku.

  File-file terenkripsi yang ditemukan:
  +----------------------------+----------+------------+
  | Nama File                  | Status   | Ukuran     |
  +----------------------------+----------+------------+
  | badusb.log                 | Unalloc. | 2,021 B    |
  | credential_scan.txt        | Unalloc. | 2,418 B    |
  | plaintext_credentials.txt  | Unalloc. | 12,686 B   |
  | registry_values.txt        | Unalloc. | 1,905,565 B|
  | services.txt               | Unalloc. | 99,278 B   |
  | installed.txt              | Unalloc. | 3,068 B    |
  | network.txt                | Unalloc. | 478 B      |
  | payload_hello.vbs          | Unalloc. | 102 B      |
  | hashes.tsv                 | Unalloc. | 1,934 B    |
  +----------------------------+----------+------------+

  Catatan: File "INSTRUCTIONS.txt" dan "README.md" ditemukan dalam
  kondisi ALLOCATED (tidak terenkripsi) sebagai file umpan/petunjuk.

  Isi INSTRUCTIONS.txt:
    "Buka README.md untuk info project.
     If you found this file uploaded, then heres the clue and about
     this chall, this is a restricted area and i cant help a lot,
     made with love by m00nspectre"

  Format enkripsi "CBC1":
    - 4 bytes pertama   : Magic header "CBC1" (0x43424331)
    - Bytes selanjutnya : Ciphertext AES-CBC
    - Kunci enkripsi hardcoded di dalam binary malware

------------------------------------------------------------------------
6.5 ARTEFAK BROWSER (MICROSOFT EDGE)
------------------------------------------------------------------------

Direktori profiles/edge/ berisi dua artefak browser yang signifikan:

  [A] Local State
      File konfigurasi JSON browser Microsoft Edge. Temuan penting:
      - Profil aktif          : "Default" (nama: Profile 1)
      - Status login akun     : Tidak login ke akun Microsoft
      - os_crypt.app_bound_encrypted_key:
        "QVBQQgEAAADQjJ3fARXREYx6AMBPwpfrAQAAADRgxPdrpUlEu..."
        -> Master key DPAPI yang dienkripsi. Diperlukan DPAPI user key
           dari mesin korban untuk melakukan dekripsi.

  [B] Default/Login Data
      Database SQLite yang menyimpan password tersimpan browser Edge.
      File ini dienkripsi menggunakan mekanisme enkripsi Chromium
      (DPAPI + App-Bound Encryption). Diperlukan master key DPAPI
      untuk mengekstrak credential yang tersimpan.

  Catatan: Keberadaan artefak browser ini mengkonfirmasi bahwa
  salah satu target utama malware adalah credential browser korban.

------------------------------------------------------------------------
6.6 KOMUNIKASI TERSANGKA (little_courrier_chat.png)
------------------------------------------------------------------------

Sebuah file gambar (PNG, 1122x1402 pixel) berisi screenshot percakapan
melalui aplikasi Microsoft Teams antara dua partisipan di channel
terenkripsi (Secure Channel):

  Partisipan:
    - CISO Leader (CL)
    - Malware Analyst (MA)

  Rekonstruksi percakapan:
  -------------------------
  CL [09:12]: "I have completed an initial review of this simulated
               malicious file. There appears to be an unusual pattern
               that requires further investigation."

  CL [09:14]: "I identified the following suspicious pattern:"

  CL [09:15]: [mengirim string base64 yang mencurigakan]

  CL [09:16]: "Please review and analyze whether this pattern is
               directly related to the malicious file."

  MA [09:18]: "Understood. I will decode this artifact, determine the
               meaning of the message, and correlate it with the
               file's behavior to better understand the author's intent."

  Analisis:
  ---------
  String base64 yang dikirim CISO Leader merupakan indikasi bahwa
  pelaku atau rekan pelaku telah menganalisis file malware dan
  menemukan encoded content di dalamnya. Ini memperkuat dugaan bahwa
  serangan ini direncanakan secara terkoordinasi dan melibatkan
  pengetahuan teknis mendalam tentang malware yang dibuat.


================================================================================
7. ANALISIS BINER — STATIC ANALYSIS (combined_v2_gui.exe)
================================================================================

  7.1 Identifikasi Biner
  ----------------------
  Pemeriksaan menggunakan perintah "file" dan analisis header PE:

    Tipe File : PE32+ executable (GUI) x86-64
    Compiler  : Nim (dikonfirmasi dari internal error strings)
    Ukuran    : 394,752 bytes
    MD5       : 3fc8629856beb346c9be90f97526a392

  Snippet header PE:
    Offset 0x00: 4D5A 9000  -> MZ signature (Windows PE)
    Offset 0x80: 5045 0000  -> PE signature
                 6486       -> Machine = 0x8664 (AMD64)

  7.2 Ekstraksi String (strings analysis)
  ----------------------------------------
  Menggunakan perintah:
    $ strings combined_v2_gui.exe | grep -i "FORDIG\|flag\|seal\|CBC"

  Temuan string-string kritis:

    [FLAG]
    @FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_
    k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}

    [FLAG WRITER]
    @[ok] flag written -> .data\flag_obfuscated.txt
    @[!] flag write (data-root) failed
    @[!] flag write (per-run) failed
    @flag_obfuscated.txt

    [ENKRIPSI]
    @[seal] encrypted=
    CBC1
    @password file: encrypt at rest, never commit to source

    [PESAN DEVELOPER]
    @Hello there, im the developer of custom this maldev, this malware
    is not for harming, but for training & learn, lead to CRTE & PEN200
    Red Teamer, identity shifting~ m00nspectre.

  7.3 Rekonstruksi Logika Malware
  --------------------------------
  Berdasarkan analisis string, berikut urutan kerja malware:

  TAHAP 1 — INISIASI & TRIGGER
    - maldev_badusb.lnk   : LNK file launcher yang dieksekusi saat USB dicolok
    - payload_hello.vbs   : VBScript wrapper yang memanggil binary utama
    - combined_v2_gui.exe : Binary utama yang mengeksekusi seluruh operasi

  TAHAP 2 — RECONNAISSANCE & COLLECTION
    Binary melakukan pengumpulan data dari beberapa sumber:

    Registry Windows:
      HKCU\Software\Microsoft\Terminal Server Client\Default   (RDP history)
      HKCU\Software\Microsoft\Terminal Server Client\Servers   (RDP servers)
      HKLM\SOFTWARE\Microsoft\WlanSvc\Profiles                 (WiFi passwords)
      HKLM\SECURITY\Policy\Secrets\NL$KM\CurrVal               (LSASS secrets)
      HKLM\SECURITY\Cache                                       (domain creds)
      HKCU\...\Explorer\RunMRU                                  (run history)
      HKLM\SYSTEM\CurrentControlSet\...\AutoAdminLogon          (autologon)
      HKLM\SECURITY\Policy\Secrets                              (LSA secrets)

    Browser:
      Edge Login Data (saved passwords, terenkripsi DPAPI)
      Edge Local State (master key, terenkripsi DPAPI)

    System Information:
      installed.txt        : daftar software terpasang
      services.txt         : daftar services yang berjalan
      network.txt          : konfigurasi network interface
      plaintext_credentials: credential plaintext dari registry

  TAHAP 3 — ENKRIPSI
    Seluruh file hasil reconnaissance dienkripsi menggunakan AES-CBC
    dengan magic header proprietary "CBC1" sebelum disimpan ke USB.

  TAHAP 4 — EKSFILTRASI
    File terenkripsi di-drop ke USB pada direktori:
    information_[YYYYMMDD_HHMMSS]\
    Setiap sesi drop dicatat di badusb.log.

  TAHAP 5 — FLAG WRITE
    write_flag.exe membuat file .data\flag_obfuscated.txt pada USB.
    File write_flag.exe kemudian dihapus untuk menghilangkan jejak.

  TAHAP 6 — CLEANUP
    Beberapa file launcher (maldev_badusb.lnk) dan binary pendukung
    dihapus dari sistem file setelah eksekusi selesai.

  7.4 Atribusi
  ------------
  Berdasarkan string yang ditemukan di dalam binary, pelaku
  mengidentifikasi dirinya sebagai "m00nspectre". Pesan yang tertinggal:

    "Hello there, im the developer of custom this maldev, this malware
     is not for harming, but for training & learn, lead to CRTE &
     PEN200 Red Teamer, identity shifting~ m00nspectre."

  Hal ini mengindikasikan bahwa pelaku adalah praktisi keamanan siber
  yang membuat malware ini untuk tujuan pelatihan (simulasi red team),
  bukan untuk serangan berbahaya.


================================================================================
8. REKONSTRUKSI TIMELINE KEJADIAN
================================================================================

Seluruh timestamp dalam WIB (UTC+7). Sumber: metadata file pada image.

  +-----------+-----------+---------------------------------------------------+
  | Tanggal   | Waktu     | Kejadian                                          |
  +-----------+-----------+---------------------------------------------------+
  | 26 Sep 26 | 21:58:47  | maldev_badusb.lnk dibuat                         |
  |           |           | -> USB mulai disiapkan oleh pelaku                |
  +-----------+-----------+---------------------------------------------------+
  | 27 Sep 26 | 00:00:00  | combined_v2_gui.exe dibuat/dikompilasi            |
  +-----------+-----------+---------------------------------------------------+
  | 27 Sep 26 | 15:51:34  | combined_v2.part dibuat (versi awal kompilasi)    |
  +-----------+-----------+---------------------------------------------------+
  | 27 Sep 26 | 22:08:00  | Edge Login Data dikopikan ke USB                  |
  |           |           | -> Pelaku mempersiapkan umpan browser artifact    |
  +-----------+-----------+---------------------------------------------------+
  | 28 Sep 26 | 03:10:00  | README.pdf dibuat (file umpan)                    |
  +-----------+-----------+---------------------------------------------------+
  | 01 Okt 26 | 10:30:23  | [RUN #1] Malware pertama kali dieksekusi          |
  |           |           | -> Folder information_20261001_103023 dibuat      |
  |           |           | -> Reconnaissance dimulai                         |
  +-----------+-----------+---------------------------------------------------+
  | 01 Okt 26 | 10:30:24  | INSTRUCTIONS.txt selesai ditulis                  |
  +-----------+-----------+---------------------------------------------------+
  | 01 Okt 26 | 10:30:26  | credential_scan.txt, registry_values.txt,         |
  |           |           | installed.txt, network.txt selesai di-drop        |
  +-----------+-----------+---------------------------------------------------+
  | 01 Okt 26 | 10:33:33  | [RUN #2] Malware dieksekusi ulang                 |
  +-----------+-----------+---------------------------------------------------+
  | 01 Okt 26 | 10:38:09  | [RUN #3] Eksekusi ketiga                          |
  +-----------+-----------+---------------------------------------------------+
  | 01 Okt 26 | 10:38:19  | [RUN #4] Eksekusi keempat (terakhir)              |
  +-----------+-----------+---------------------------------------------------+
  | 03 Okt 26 | 00:00:00  | File terakhir diakses (last access timestamp)     |
  +-----------+-----------+---------------------------------------------------+

Kesimpulan Timeline:
  - USB dipersiapkan pelaku selama kurang lebih 5 hari (26 Sep — 1 Okt)
  - Serangan aktif terjadi pada 1 Oktober 2026 dalam rentang 8 menit
  - Malware dieksekusi 4 kali dalam satu sesi (kemungkinan multi-trigger)


================================================================================
9. INDIKATOR KOMPROMI (IOC — INDICATOR OF COMPROMISE)
================================================================================

  9.1 Hash File
  -------------
  +------------------------------+------------------------------------------+
  | Nama File                    | MD5 Hash                                 |
  +------------------------------+------------------------------------------+
  | combined_v2_gui.exe          | 3fc8629856beb346c9be90f97526a392         |
  | little_courrier_chat.png     | e8dd994b1f1e3866bc878c276cf6932e         |
  | badusb.log (root)            | 10d9fb4993eda8d87957656e4f90c295         |
  | README.md                    | 3a50e855098b040c21935235df0dfc81         |
  | INSTRUCTIONS.txt             | 94dad09b0b33f3041663f0e50791cfd2         |
  | Local State (Edge)           | 8f6cbbdcf7c9421cbe10ffefdd7cdf2d         |
  | Login Data (Edge)            | 5115674b678562d04a188acc463a275f         |
  +------------------------------+------------------------------------------+

  9.2 String IOC di dalam Binary
  --------------------------------
    - Magic header enkripsi : "CBC1"
    - Pola log drop         : "[run YYYYMMDD_HHMMSS] copied=N failed=N"
    - Pola direktori output : "information_YYYYMMDD_HHMMSS\"
    - Pola flag writer      : "[ok] flag written -> .data\flag_obfuscated.txt"
    - Identitas developer   : "m00nspectre"
    - Bahasa pemrograman    : Nim (terdeteksi dari internal error strings)

  9.3 Behavioral IOC
  ------------------
    - Pembuatan LNK file yang mengarah ke notepad.exe (teknik masquerading)
    - Penggunaan VBScript sebagai wrapper eksekusi
    - Penulisan file ke direktori .Trash-1000 (hidden dari pandangan biasa)
    - Enkripsi file output sebelum eksfiltrasi
    - Penghapusan launcher setelah eksekusi (anti-forensics)
    - Pengumpulan data dari HKLM\SECURITY (membutuhkan privilege SYSTEM)


================================================================================
10. KESIMPULAN & FLAG
================================================================================

  10.1 Kesimpulan Pemeriksaan
  ----------------------------
  Pemeriksaan forensik terhadap image USB telah berhasil mengungkap:

    a) Keberadaan malware tipe BadUSB berbasis Nim yang dirancang untuk
       melakukan credential theft dan reconnaissance pada mesin korban.

    b) Malware berhasil dieksekusi sebanyak 4 kali pada 1 Oktober 2026,
       mengumpulkan data sensitif meliputi credential browser, registry
       dump, WiFi password, dan konfigurasi jaringan.

    c) Seluruh data hasil reconnaissance telah dienkripsi dengan AES-CBC
       (format "CBC1") sebelum disimpan ke USB, menunjukkan kesadaran
       pelaku terhadap kemungkinan pemeriksaan forensik.

    d) Malware dikembangkan oleh "m00nspectre" untuk tujuan simulasi
       red team / pelatihan keamanan siber, bukan serangan berbahaya.

    e) Teknik yang digunakan meliputi: LNK masquerading, VBScript execution,
       DPAPI credential harvesting, registry enumeration, dan file carving
       prevention melalui penghapusan launcher.

  10.2 Flag Forensik
  ------------------
  Flag ditemukan melalui static analysis (strings extraction) terhadap
  binary malware combined_v2_gui.exe. Flag di-embed secara hardcoded
  oleh developer sebagai bagian dari challenge forensik.

  Metode ekstraksi:
    $ strings combined_v2_gui.exe | grep "FORDIG{"

  FLAG:
  ============================================================
  FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_
  k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}
  ============================================================


================================================================================
11. REKOMENDASI
================================================================================

Berdasarkan hasil pemeriksaan, tim pemeriksa merekomendasikan hal-hal
berikut untuk mencegah insiden serupa di masa mendatang:

  [1] Kebijakan USB
      - Terapkan kebijakan pemblokiran USB storage pada endpoint
        menggunakan Group Policy atau solusi DLP (Data Loss Prevention)
      - Hanya izinkan USB yang telah diverifikasi dan terdaftar

  [2] Monitoring & Detection
      - Implementasikan monitoring terhadap pembuatan LNK file
        di luar direktori normal
      - Pantau eksekusi VBScript di luar konteks administrasi
      - Deteksi akses ke HKLM\SECURITY registry path oleh proses non-system

  [3] Credential Protection
      - Aktifkan Credential Guard (Windows Defender Credential Guard)
      - Nonaktifkan autologon (DefaultPassword di registry)
      - Audit akses ke LSA secrets secara berkala

  [4] Browser Security
      - Pertimbangkan penggunaan enterprise browser management
      - Nonaktifkan penyimpanan password di browser untuk akun kritikal

  [5] Incident Response
      - Lakukan memory forensics jika mesin korban masih aktif
        untuk menganalisis proses yang berjalan saat insiden
      - Periksa scheduled tasks dan startup entries pada mesin korban
        untuk memastikan tidak ada persistensi tambahan

  [6] Awareness
      - Laksanakan pelatihan security awareness tentang bahaya
        perangkat USB yang tidak dikenal
      - Sosialisasikan kebijakan "jangan colok USB sembarangan"


================================================================================
12. LAMPIRAN
================================================================================

  Lampiran A: Daftar Lengkap File pada Volume USB
  -------------------------------------------------
  [Dapat diekspor dari Autopsy: File -> Generate Report -> Excel/CSV]

  Lampiran B: Listing String Mencurigakan pada combined_v2_gui.exe
  -----------------------------------------------------------------
  Output lengkap dari:
    $ strings combined_v2_gui.exe > strings_output.txt

  Lampiran C: Hexdump Magic Header File Terenkripsi
  --------------------------------------------------
  Contoh dari credential_scan.txt (4 byte pertama):
    43 42 43 31  ->  "CBC1"

  Lampiran D: Screenshot Autopsy
  --------------------------------
  [Capture screenshot dari Autopsy untuk mendokumentasikan temuan visual]

  Lampiran E: Hash Verification Report dari FTK Imager
  -----------------------------------------------------
  [Lampirkan file .txt hasil verifikasi hash dari FTK Imager]


================================================================================

  Laporan ini dibuat berdasarkan pemeriksaan forensik yang dilaksanakan
  sesuai dengan standar dan prosedur yang berlaku. Seluruh temuan
  terdokumentasi dan dapat direproduksi.

  Pemeriksa,


  [Tanda Tangan]
  [Nama Pemeriksa]
  [Jabatan]
  [Tanggal]

================================================================================
                         - AKHIR LAPORAN -
================================================================================
