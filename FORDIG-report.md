# LAPORAN FORENSIK DIGITAL

---

| Field | Detail |
|---|---|
| **Nomor Kasus** | FORDIG-2026-001 |
| **Judul Kasus** | Analisis Artefak Serangan BadUSB — m00nspectre |
| **Tanggal Laporan** | 04 Oktober 2026 |
| **Pemeriksa** | K |
| **Klasifikasi** | RAHASIA / TERBATAS |

---

## Daftar Isi

1. [Ringkasan Eksekutif](#1-ringkasan-eksekutif)
2. [Informasi Kasus](#2-informasi-kasus)
3. [Metodologi Pemeriksaan](#3-metodologi-pemeriksaan)
4. [Spesifikasi Barang Bukti](#4-spesifikasi-barang-bukti)
5. [Proses Akuisisi (FTK Imager)](#5-proses-akuisisi-ftk-imager)
6. [Temuan Pemeriksaan](#6-temuan-pemeriksaan)
7. [Analisis Biner — Static Analysis](#7-analisis-biner--static-analysis)
8. [Rekonstruksi Timeline Kejadian](#8-rekonstruksi-timeline-kejadian)
9. [Indikator Kompromi (IOC)](#9-indikator-kompromi-ioc)
10. [Kesimpulan & Flag](#10-kesimpulan--flag)
11. [Rekomendasi](#11-rekomendasi)
12. [Lampiran](#12-lampiran)

---

## 1. Ringkasan Eksekutif

Pemeriksaan forensik ini dilakukan terhadap sebuah perangkat USB (SanDisk) yang diduga digunakan dalam serangan **BadUSB** terhadap sistem mesin korban. Analisis menyeluruh terhadap forensic image perangkat tersebut mengungkap adanya malware khusus yang dikembangkan oleh pelaku dengan alias **"m00nspectre"**.

Malware bernama `combined_v2_gui.exe` (dikompilasi menggunakan bahasa **Nim**) menjalankan operasi pengumpulan informasi sensitif secara otomatis, meliputi: credential browser, riwayat koneksi RDP, password WiFi tersimpan, serta dump registry konfigurasi sistem target. Seluruh data hasil reconnaissance dienkripsi menggunakan algoritma **AES-CBC** dengan format header proprietary `CBC1` sebelum disimpan kembali ke perangkat USB.

Melalui teknik **static analysis** terhadap binary malware, tim pemeriksa berhasil mengekstrak flag tantangan yang telah di-embed secara hardcoded di dalam kode sumber oleh pelaku.

> **FLAG DITEMUKAN:**
> ```
> FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}
> ```

---

## 2. Informasi Kasus

| Field | Detail |
|---|---|
| **Nomor Kasus** | FORDIG-2026-001 |
| **Tanggal Penerimaan** | 01 Oktober 2026 |
| **Tanggal Pemeriksaan** | 04 Oktober 2026 |

### Latar Belakang

Perangkat USB mencurigakan ditemukan telah dicolokkan ke workstation milik korban. Berdasarkan log aktivitas yang ditemukan, perangkat ini secara otomatis mengeksekusi payload berbahaya yang mengumpulkan data sensitif dari mesin korban. Dugaan awal mengarah pada penggunaan teknik **BadUSB** (Human Interface Device Emulation) yang dikombinasikan dengan skrip otomasi untuk eksfiltrasi data.

### Tujuan Pemeriksaan

- Mengidentifikasi jenis dan cara kerja malware yang digunakan
- Merekonstruksi timeline kejadian serangan
- Mengidentifikasi data apa saja yang berhasil dicuri
- Menemukan flag forensik yang tersembunyi di dalam artefak digital
- Mengidentifikasi Indikator Kompromi (IOC)

---

## 3. Metodologi Pemeriksaan

| Prinsip | Keterangan |
|---|---|
| **Integritas Bukti** | Seluruh pemeriksaan dilakukan pada salinan forensik (forensic image), bukan pada media original |
| **Chain of Custody** | Seluruh penanganan bukti terdokumentasi |
| **Non-Repudiation** | Hash kriptografis (MD5 & SHA1) diverifikasi sebelum dan sesudah akuisisi |

### Tahapan Pemeriksaan

| # | Tahap | Keterangan |
|---|---|---|
| 1 | **Akuisisi** | Pembuatan forensic image menggunakan FTK Imager |
| 2 | **Verifikasi** | Validasi integritas image melalui hash comparison |
| 3 | **Analisis** | Pemeriksaan artefak menggunakan Autopsy 4.23.1 |
| 4 | **Static Analysis** | Analisis binary malware menggunakan tools CLI |
| 5 | **Rekonstruksi** | Penyusunan timeline berdasarkan metadata file |
| 6 | **Pelaporan** | Penyusunan laporan dengan temuan dan kesimpulan |

### Perangkat Lunak yang Digunakan

| Tool | Fungsi |
|---|---|
| FTK Imager 4.x | Akuisisi forensic image |
| Autopsy 4.23.1 | Analisis image, file carving, artifact browser |
| strings (GNU binutils) | Ekstraksi string dari binary |
| xxd | Hex dump analisis |
| file | Identifikasi tipe file |
| sqlite3 | Analisis database browser |
| python3 | Parsing JSON artifact browser |
| md5sum / sha256sum | Verifikasi integritas file |

---

## 4. Spesifikasi Barang Bukti

| Field | Detail |
|---|---|
| **Label Bukti** | BB-001 |
| **Jenis** | USB Flash Drive |
| **Merk/Model** | SanDisk |
| **Sistem File** | FAT32 |
| **Kapasitas** | ±3.062.937 sektor |
| **Kondisi** | Baik, dapat dibaca |

### Hash Forensic Image

| Field | Detail |
|---|---|
| **File Image** | sandisk-ijo.E01 |
| **MD5** | - |
| **SHA1** | - |
| **Dibuat oleh** | FTK Imager 4.x |
| **Format** | Expert Witness Format (E01) |

> **Catatan:** Seluruh analisis dilakukan terhadap salinan forensik. Media original tidak dimodifikasi selama proses pemeriksaan.

---

## 5. Proses Akuisisi (FTK Imager)

### 5.1 Persiapan

Sebelum akuisisi dilakukan, perangkat USB dihubungkan ke workstation forensik melalui **write-blocker hardware** untuk mencegah modifikasi data pada media original (prinsip chain of custody).

### 5.2 Langkah Akuisisi

**a) Buka FTK Imager** → pilih: `File > Create Disk Image`

**b) Source Type:** `Physical Drive` — Pilih perangkat USB target (contoh: `\\.\PHYSICALDRIVE1`)

**c) Konfigurasi output image:**

| Parameter | Nilai |
|---|---|
| Image Type | E01 (Expert Witness Format) |
| Image Folder | `D:\ForensicCase\FORDIG\` |
| Image Name | `sandisk-ijo` |
| Fragment Size | 1500 MB |
| Compression | Level 6 |
| Opsi | Verify images after they are created |

**d) Metadata kasus:**

| Field | Nilai |
|---|---|
| Case Number | FORDIG-2026-001 |
| Evidence No. | BB-001 |
| Description | SanDisk USB Drive mencurigakan |
| Examiner | \[Nama Pemeriksa\] |

**e)** Klik **Start** — FTK Imager secara otomatis melakukan verifikasi hash setelah image selesai dibuat.

### 5.3 Verifikasi Integritas

| Verifikasi | Hasil |
|---|---|
| MD5 | MATCH (integritas terkonfirmasi) |
| SHA1 | MATCH (integritas terkonfirmasi) |

---

## 6. Temuan Pemeriksaan

### 6.1 Struktur Volume

| Volume | Keterangan |
|---|---|
| **vol1** | Unallocated space (sektor 0–31) |
| **vol2** | Win95 FAT32 — sektor 32–3.062.937 *(Volume Utama)* |

Node-node pada **vol2**:

| Node | Jumlah | Keterangan |
|---|---|---|
| `$OrphanFiles` | 93 | File yatim (terpisah dari struktur direktori) |
| `$CarvedFiles` | 1 | File hasil file carving |
| `$unalloc` | 15 | Fragmen unallocated |
| `Data` | 42 | File dan folder biasa |
| `payloads` | 0 | Direktori kosong |
| `.Trash-1000` | 6 | **Direktori eksfiltrasi data** |

---

### 6.2 File Malware Utama

| Nama File | Status | Ukuran | Keterangan |
|---|---|---|---|
| `combined_v2_gui.exe` | Allocated | 394 KB | **Malware utama** |
| `little_courrier_chat.png` | Allocated | 1,4 MB | Screenshot chat Teams |
| `maldev_badusb.lnk` | **Unallocated** | 383 B | Launcher *(dihapus)* |
| `README.pdf` | **Unallocated** | 172 KB | File umpan *(dihapus, corrupt)* |
| `write_flag.exe` | **Unallocated** | 93 KB | Flag writer *(dihapus)* |

> **"Unallocated"** berarti file telah dihapus dari direktori namun datanya masih dapat di-recover melalui file carving.

#### [A] `combined_v2_gui.exe`

Binary utama malware dikompilasi dengan bahasa **Nim** (terdeteksi dari error-string internal `osfiles.nim`). Bertipe PE32+ (Windows 64-bit).
- **MD5:** `3fc8629856beb346c9be90f97526a392`

#### [B] `maldev_badusb.lnk` *(DIHAPUS — masih ter-recover)*

File Windows Shortcut yang digunakan sebagai launcher saat USB dicolok. Analisis hex menunjukkan referensi ke `C:\Windows\system32\notepad.exe` dan `shell32.dll` — teknik **notepad masquerading** untuk menyamarkan eksekusi malware.
- **Timestamp pembuatan:** 2026-09-26 21:58:47 WIB

#### [C] `write_flag.exe` *(DIHAPUS — masih ter-recover)*

Executable (93.696 bytes) yang menulis flag ke `.data\flag_obfuscated.txt`. Dihapus setelah dieksekusi untuk menghapus jejak.

#### [D] `README.pdf` *(DIHAPUS — corrupt)*

Gagal dibuka Autopsy dengan error:
```
Cannot invoke PTrailer.getPrimaryCrossReference() because documentTrailer is null
```
Berfungsi sebagai **file umpan (decoy)** untuk mengalihkan perhatian analis.

---

### 6.3 Artefak Log & Drop

#### [A] `badusb.log` (root level)

```
[run 20261001_103023] copied=2 failed=0
[run 20261001_103033] copied=2 failed=0
[run 20261001_103809] copied=2 failed=0
[run 20261001_103819] copied=2 failed=0
```

Malware berhasil dieksekusi **4 kali** pada 1 Oktober 2026, pukul **10:30–10:38 WIB**.

#### [B] `_drop_complete.txt`

Berisi: `Drop completed.` — konfirmasi payload berhasil di-drop.

#### [C] `hashes.tsv`

| Nama File | MD5 | SHA1 |
|---|---|---|
| `badusb.log` | `10d9fb4993eda8d87957656e4f90c295` | `1ef2f64aea693c34...` |
| `README.md` | `3a50e855098b040c21935235df0dfc81` | `87d9b37784dac0b9...` |
| `INSTRUCTIONS.txt` | `94dad09b0b33f3041663f0e50791cfd2` | `8e631a1d42ea2fc9...` |

---

### 6.4 File Terenkripsi (`information_20261001_103023`)

Seluruh file hasil reconnaissance dienkripsi dengan **AES-CBC** menggunakan magic header `CBC1`.

| Nama File | Status | Ukuran |
|---|---|---|
| `badusb.log` | Unallocated | 2.021 B |
| `credential_scan.txt` | Unallocated | 2.418 B |
| `plaintext_credentials.txt` | Unallocated | 12.686 B |
| `registry_values.txt` | Unallocated | 1.905.565 B |
| `services.txt` | Unallocated | 99.278 B |
| `installed.txt` | Unallocated | 3.068 B |
| `network.txt` | Unallocated | 478 B |
| `payload_hello.vbs` | Unallocated | 102 B |
| `hashes.tsv` | Unallocated | 1.934 B |

**Format enkripsi `CBC1`:**

| Komponen | Detail |
|---|---|
| 4 bytes pertama | Magic header `CBC1` (hex: `0x43424331`) |
| Bytes selanjutnya | Ciphertext AES-CBC |
| Kunci enkripsi | Hardcoded di dalam binary malware |

**Isi `INSTRUCTIONS.txt`** (tidak terenkripsi):
```
Buka README.md untuk info project.

If you found this file uploaded, then heres the clue and about this chall,
this is a restricted area and i cant help a lot, made with love by m00nspectre
```

---

### 6.5 Artefak Browser (Microsoft Edge)

#### [A] `Local State`

| Field | Nilai |
|---|---|
| Profil aktif | `Default` (Profile 1) |
| Status login | Tidak login ke akun Microsoft |
| `os_crypt.app_bound_encrypted_key` | `QVBQQgEAAADQjJ3fARXREYx6AMBPwpfr...` |

> Master key DPAPI terenkripsi. Diperlukan DPAPI user key dari mesin korban untuk dekripsi.

#### [B] `Default/Login Data`

Database SQLite berisi saved passwords browser Edge, dienkripsi dengan DPAPI + App-Bound Encryption. Diperlukan master key DPAPI untuk ekstraksi credential.

> Keberadaan artefak ini mengkonfirmasi bahwa **credential browser adalah target utama malware**.

---

### 6.6 Komunikasi Tersangka (`little_courrier_chat.png`)

File PNG (1122×1402 px) berisi screenshot percakapan **Microsoft Teams** di *Secure Channel* antara:
- 🔵 **CISO Leader (CL)**
- 🟢 **Malware Analyst (MA)**

**Rekonstruksi percakapan:**

> **CL [09:12]:** *"I have completed an initial review of this simulated malicious file. There appears to be an unusual pattern that requires further investigation."*
>
> **CL [09:14]:** *"I identified the following suspicious pattern:"*
>
> **CL [09:15]:** `[mengirim string base64 yang mencurigakan]`
>
> **CL [09:16]:** *"Please review and analyze whether this pattern is directly related to the malicious file."*
>
> **MA [09:18]:** *"Understood. I will decode this artifact, determine the meaning of the message, and correlate it with the file's behavior to better understand the author's intent."*

String base64 yang dikirim mengindikasikan bahwa serangan ini direncanakan secara **terkoordinasi** dan pelaku memiliki pengetahuan teknis mendalam tentang malware yang dibuat.

---

## 7. Analisis Biner — Static Analysis

### 7.1 Identifikasi Biner

| Field | Detail |
|---|---|
| **Tipe File** | PE32+ executable (GUI) x86-64 |
| **Compiler** | Nim |
| **Ukuran** | 394.752 bytes |
| **MD5** | `3fc8629856beb346c9be90f97526a392` |

```
Offset 0x00:  4D 5A 90 00  →  MZ signature (Windows PE)
Offset 0x80:  50 45 00 00  →  PE signature
              64 86        →  Machine = 0x8664 (AMD64)
```

---

### 7.2 Ekstraksi String — Penemuan Flag

```bash
strings combined_v2_gui.exe | grep -i "FORDIG\|flag\|seal\|CBC"
```

**Output:**

```
@FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}
@[ok] flag written -> .data\flag_obfuscated.txt
@[!] flag write (data-root) failed
@[!] flag write (per-run) failed
@[seal] encrypted=
CBC1
@password file: encrypt at rest, never commit to source
@Hello there, im the developer of custom this maldev, this malware is not for harming,
but for training & learn, lead to CRTE & PEN200 Red Teamer, identity shifting~ m00nspectre.
```

---

### 7.3 Rekonstruksi Logika Malware

#### Tahap 1 — Inisiasi & Trigger

| Komponen | Peran |
|---|---|
| `maldev_badusb.lnk` | LNK launcher saat USB dicolok |
| `payload_hello.vbs` | VBScript wrapper pemanggil binary utama |
| `combined_v2_gui.exe` | Binary utama yang mengeksekusi seluruh operasi |

#### Tahap 2 — Reconnaissance & Collection

**Registry Windows yang dikumpulkan:**

```
HKCU\Software\Microsoft\Terminal Server Client\Default    → RDP history
HKCU\Software\Microsoft\Terminal Server Client\Servers    → RDP servers
HKLM\SOFTWARE\Microsoft\WlanSvc\Profiles                  → WiFi passwords
HKLM\SECURITY\Policy\Secrets\NL$KM\CurrVal                → LSASS secrets
HKLM\SECURITY\Cache                                       → Domain creds cached
HKCU\...\Explorer\RunMRU                                  → Run history
HKLM\SYSTEM\...\Winlogon\AutoAdminLogon                   → Autologon creds
HKLM\SECURITY\Policy\Secrets                              → LSA secrets
```

**Browser artifacts:**
- Edge `Login Data` (saved passwords, DPAPI encrypted)
- Edge `Local State` (master key, DPAPI encrypted)

**System info files:**

| Output File | Konten |
|---|---|
| `installed.txt` | Daftar software terpasang |
| `services.txt` | Daftar services yang berjalan |
| `network.txt` | Konfigurasi network interface |
| `plaintext_credentials.txt` | Credential plaintext dari registry |

#### Tahap 3 — Enkripsi
Semua file dienkripsi dengan **AES-CBC**, magic header `CBC1`.

#### Tahap 4 — Eksfiltrasi
File di-drop ke `information_[YYYYMMDD_HHMMSS]\` pada USB. Log di `badusb.log`.

#### Tahap 5 — Flag Write
`write_flag.exe` membuat `.data\flag_obfuscated.txt`, lalu **menghapus dirinya sendiri**.

#### Tahap 6 — Cleanup
`maldev_badusb.lnk` dan binary pendukung dihapus dari sistem file.

---

### 7.4 Atribusi

> *"Hello there, im the developer of custom this maldev, this malware is not for harming, but for training & learn, lead to CRTE & PEN200 Red Teamer, identity shifting~ m00nspectre."*

Pelaku adalah **praktisi keamanan siber** yang membuat malware ini untuk tujuan simulasi red team / pelatihan, bukan serangan berbahaya.

---

## 8. Rekonstruksi Timeline Kejadian

> Seluruh timestamp dalam **WIB (UTC+7)**. Sumber: metadata file pada image forensik.

| Tanggal | Waktu | Kejadian |
|---|---|---|
| 26 Sep 2026 | 21:58:47 | `maldev_badusb.lnk` dibuat — USB mulai disiapkan pelaku |
| 27 Sep 2026 | 00:00:00 | `combined_v2_gui.exe` dibuat/dikompilasi |
| 27 Sep 2026 | 15:51:34 | `combined_v2.part` dibuat (versi awal kompilasi) |
| 27 Sep 2026 | 22:08:00 | Edge `Login Data` dikopikan ke USB |
| 28 Sep 2026 | 03:10:00 | `README.pdf` dibuat (file umpan) |
| **01 Okt 2026** | **10:30:23** | **[RUN #1]** Malware pertama dieksekusi di mesin korban |
| 01 Okt 2026 | 10:30:24 | `INSTRUCTIONS.txt` selesai ditulis |
| 01 Okt 2026 | 10:30:26 | `credential_scan.txt`, `registry_values.txt`, `installed.txt`, `network.txt` selesai di-drop |
| 01 Okt 2026 | 10:33:33 | **[RUN #2]** Eksekusi kedua |
| 01 Okt 2026 | 10:38:09 | **[RUN #3]** Eksekusi ketiga |
| 01 Okt 2026 | 10:38:19 | **[RUN #4]** Eksekusi keempat (terakhir) |
| 03 Okt 2026 | 00:00:00 | File terakhir diakses (last access timestamp) |

**Kesimpulan:**
- USB disiapkan selama ±5 hari (26 Sep — 1 Okt 2026)
- Serangan aktif berlangsung dalam rentang **8 menit**
- Malware dieksekusi **4 kali** dalam satu sesi

---

## 9. Indikator Kompromi (IOC)

### 9.1 Hash File

| Nama File | MD5 Hash |
|---|---|
| `combined_v2_gui.exe` | `3fc8629856beb346c9be90f97526a392` |
| `little_courrier_chat.png` | `e8dd994b1f1e3866bc878c276cf6932e` |
| `badusb.log` (root) | `10d9fb4993eda8d87957656e4f90c295` |
| `README.md` | `3a50e855098b040c21935235df0dfc81` |
| `INSTRUCTIONS.txt` | `94dad09b0b33f3041663f0e50791cfd2` |
| `Local State` (Edge) | `8f6cbbdcf7c9421cbe10ffefdd7cdf2d` |
| `Login Data` (Edge) | `5115674b678562d04a188acc463a275f` |

### 9.2 String IOC di dalam Binary

| IOC | Nilai |
|---|---|
| Magic header enkripsi | `CBC1` |
| Pola log drop | `[run YYYYMMDD_HHMMSS] copied=N failed=N` |
| Pola direktori output | `information_YYYYMMDD_HHMMSS\` |
| Pola flag writer | `[ok] flag written -> .data\flag_obfuscated.txt` |
| Identitas developer | `m00nspectre` |
| Bahasa pemrograman | Nim |

### 9.3 Behavioral IOC

- LNK file mengarah ke `notepad.exe` (**masquerading technique**)
- Penggunaan VBScript sebagai wrapper eksekusi
- Penulisan file ke `.Trash-1000` (tersembunyi dari pandangan biasa)
- Enkripsi output sebelum eksfiltrasi (anti-forensics)
- Penghapusan launcher setelah eksekusi (anti-forensics)
- Akses ke `HKLM\SECURITY` (butuh privilege **SYSTEM**)

---

## 10. Kesimpulan & Flag

### 10.1 Kesimpulan Pemeriksaan

**a)** Keberadaan malware BadUSB berbasis **Nim** untuk credential theft dan reconnaissance pada mesin korban.

**b)** Malware berhasil dieksekusi **4 kali** mengumpulkan credential browser, registry dump, WiFi password, dan konfigurasi jaringan.

**c)** Semua data dienkripsi dengan **AES-CBC** (format `CBC1`) sebelum disimpan ke USB.

**d)** Malware dibuat oleh **"m00nspectre"** untuk simulasi red team / pelatihan keamanan siber.

**e)** Teknik yang digunakan: LNK masquerading, VBScript execution, DPAPI harvesting, registry enumeration, dan anti-forensics melalui penghapusan launcher.

---

### 10.2 Flag Forensik

Flag ditemukan melalui **static analysis** (strings extraction) terhadap `combined_v2_gui.exe`.

```bash
strings combined_v2_gui.exe | grep "FORDIG{"
```

---

> ## 🏁 FLAG
>
> ```
> FORDIG{c0ngr4tul4tI0nz_d1d_y0u_f1nd_m3?_w3ll_g00d_j0b_k3l0mp0k-3_gr33t1ng5_fr0m_m00nspectre}
> ```

---

## 11. Rekomendasi

### [1] Kebijakan USB
- Blokir USB storage via **Group Policy** atau solusi **DLP**
- Whitelist hanya USB yang telah diverifikasi

### [2] Monitoring & Detection
- Monitor pembuatan LNK file di luar direktori normal
- Pantau eksekusi VBScript di luar konteks administrasi
- Deteksi akses ke `HKLM\SECURITY` oleh proses non-SYSTEM

### [3] Credential Protection
- Aktifkan **Credential Guard** (Windows Defender Credential Guard)
- Nonaktifkan autologon (`DefaultPassword` di registry)
- Audit berkala akses ke LSA secrets

### [4] Browser Security
- Gunakan enterprise browser management
- Nonaktifkan penyimpanan password di browser untuk akun kritikal

### [5] Incident Response
- Lakukan **memory forensics** jika mesin korban masih aktif
- Periksa scheduled tasks dan startup entries di mesin korban

### [6] Security Awareness
- Pelatihan security awareness tentang bahaya USB tidak dikenal
- Sosialisasikan kebijakan **"jangan colok USB sembarangan"**

---

## 12. Lampiran

| Lampiran | Keterangan |
|---|---|
| **Lampiran A** | Daftar lengkap file pada volume USB *(ekspor dari Autopsy: File → Generate Report)* |
| **Lampiran B** | Listing strings mencurigakan: `strings combined_v2_gui.exe > strings_output.txt` |
| **Lampiran C** | Hexdump magic header: `43 42 43 31` → `"CBC1"` |
| **Lampiran D** | Screenshot Autopsy — dokumentasi temuan visual |
| **Lampiran E** | Hash Verification Report dari FTK Imager |

---

*Laporan ini dibuat berdasarkan pemeriksaan forensik yang dilaksanakan sesuai dengan standar dan prosedur yang berlaku. Seluruh temuan terdokumentasi dan dapat direproduksi.*

---

| Field | |
|---|---|
| **Pemeriksa** | |
| Nama | K |
| Tanggal | 04 Oktober 2026 |

---

*— AKHIR LAPORAN —*
