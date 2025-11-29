# 👻 GhostLink: Zero-Trace Secure Communication Protocol

> **"Görünmez ol. İz bırakma. Sadece fısılda."**

**GhostLink**, merkezi olmayan, metaveri (metadata) sızdırmayan, adli bilişim (forensics) analizlerine ve aktif trafik izlemeye (DPI) karşı dirençli, askeri sınıf bir anlık mesajlaşma ve iletişim protokolüdür.

Standart şifreli mesajlaşma uygulamalarının (Signal, WhatsApp, Telegram) aksine, bu proje sadece mesaj içeriğini şifrelemekle kalmaz; **RAM kullanımını, trafik desenini, kullanıcı stilini (stylometry), donanım izlerini ve hatta varlığını** gizler.

---

## 🚀 Öne Çıkan Özellikler

### 🔐 1. Kriptografik Mimari (Military Grade)
*   **Double Ratchet Protokolü:** Her mesaj için ayrı bir anahtar üretilir (Forward Secrecy). Bir anahtar ele geçirilse bile geçmiş veya gelecek mesajlar çözülemez.
*   **Hibrit Şifreleme (Matryoshka):** Veriler iç içe geçmiş iki katmanla şifrelenir:
    *   *Katman 1 (İç):* **ChaCha20-Poly1305** (Hız ve Güvenlik)
    *   *Katman 2 (Dış):* **AES-256-GCM** (Endüstri Standardı)
*   **Sender Keys Mimarisi:** Grup sohbetlerinde Signal benzeri "Sender Keys" yapısı kullanılarak 100+ kişilik gruplarda gecikmesiz, O(1) karmaşıklığında şifreleme sağlanır.
*   **Replay Attack Koruması:**
    *   *Client:* Mesajlara milisaniyelik zaman damgası gömülür. 5 saniyeden eski mesajlar reddedilir.
    *   *Server:* Paketlerin hash özetleri bellekte tutulur. Aynı paket tekrar gelirse sunucu tarafından anında düşürülür.

### 👻 2. İleri Seviye Gizlilik (Stealth & Obfuscation)
*   **Chameleon Memory (Bukalemun Bellek):** RAM'deki şifreli veriler ve anahtarlar asla sabit durmaz. Arka planda sürekli XOR maskelemesi ile yer ve değer değiştirir. Cold Boot saldırılarına karşı korumalıdır.
*   **Trafik Kamuflajı (Steganography):** Giden şifreli paketler, dışarıdan bakıldığında **Windows Update**, **Google Analytics**, **Weather API** veya **Instagram Upload** trafiği gibi görünür (HTTP Header Manipulation). DPI (Deep Packet Inspection) sistemlerini atlatır.
*   **Gürültü Jeneratörü (Noise Generator):** Sistem boşta olsa bile rastgele aralıklarla sahte (decoy) şifreli paketler göndererek trafik analizini (Traffic Analysis) imkansız kılar. Ne zaman mesaj attığınız, ne zaman sustuğunuz anlaşılamaz.

### 🛡️ 3. Adli Bilişim Koruması (Anti-Forensics)
*   **Dead Man's Switch (Ölü Adam Anahtarı):** 5 dakika boyunca klavye hareketi algılanmazsa sistem kendini otomatik imha eder.
*   **Secure Wipe & Timestomping:** `/nuke` komutu veya panik anında dosyalar **DoD 5220.22-M** standardında (3 geçişli: Sıfır, Bir, Rastgele) silinir. Dosya tarihleri 2000 yılına çekilerek (Timestomping) adli analiz yanıltılır.
*   **Memory Locking:** İşletim sisteminin RAM'i diske (Swap/Pagefile) yazması Kernel seviyesinde (`ctypes` ve `mlockall` ile) engellenir.
*   **Anti-Debug & Anti-VM:** Debugger, Sanal Makine veya analiz aracı tespit edilirse sistem sahte hata mesajları vererek kendini kapatır.

### 🧠 4. Yapay Zeka ve Davranışsal Koruma
*   **Stylometry Guard (Yazım Stili Gizleme):** Siz mesajı nasıl yazarsanız yazın, sistem yazım tarzınızı (büyük/küçük harf, noktalama alışkanlıkları, emojiler) analiz eder ve standartlaştırır. Bu sayede yazışma stilinizden kimliğinizin tespit edilmesini (Stylometric Analysis) engeller.
*   **Screen Shield (Ekran Koruması):** Windows Kernel API'leri (`SetWindowDisplayAffinity`) kullanılarak, pencerenin ekran görüntüsü alınması veya OBS/Discord/RAT gibi uygulamalarla izlenmesi engellenir. Ekran görüntüsü alındığında pencere simsiyah çıkar.

---

## 🛠️ Kurulum ve Başlatma

Proje **Windows, Linux, macOS, Android (Termux) ve iOS (iSH)** üzerinde çalışacak şekilde tasarlanmıştır.

### Gereksinimler
*   Python 3.8 veya üzeri
*   İnternet bağlantısı (Tor motorunu otomatik indirmek için)

### Adım 1: Projeyi İndirin
```bash
git clone https://github.com/Muhammedpyz/Ghost-Link-Zero-Trace-Secure-Communication.git
cd Ghost-Link-Zero-Trace-Secure-Communication
```

### Adım 2: Başlatma (Otomatik Kurulum)
Sistem, eksik kütüphaneleri (cryptography, stem, colorama vb.) ve Tor motorunu işletim sisteminize uygun olarak **otomatik** algılar, indirir ve kurar.

**Windows:**
```cmd
python start.py
```

**Linux / macOS:**
```bash
python3 start.py
```

**Android (Termux):**
```bash
pkg install python
python start.py
```

---

## 💻 Kullanım Kılavuzu

Uygulamayı başlattığınızda (`start.py`), karşınıza iki seçenek çıkar:

### 1. Oda Kur (HOST)
*   Otomatik olarak yerel bir **Tor Hidden Service (.onion)** başlatır.
*   Size, arkadaşınıza vermeniz için `v2/v3 onion` adresi üretir.
*   Sunucu ve İstemci (Client) aynı anda açılır.
*   Kişi sayısını (Kapasite) belirlemenizi ister.

### 2. Odaya Katıl (JOIN)
*   Karşı tarafın size verdiği `.onion` adresini girmenizi ister.
*   Tor ağı üzerinden güvenli tünel kurar ve odaya bağlanır.
*   IP adresiniz asla karşı tarafa veya sunucuya gitmez.

---

## ⚠️ Güvenlik Komutları

Sohbet sırasında kullanabileceğiniz özel komutlar:

| Komut | Açıklama |
| :--- | :--- |
| `/clear` | Terminal ekranını ve geçmişini temizler. |
| `/nuke` | **ACİL DURUM:** Tüm proje dosyalarını, RAM'i ve geçmişi kalıcı olarak siler, sistemi kapatır. Geri dönüşü yoktur. |

---

## 📂 Teknik Dosya Yapısı

*   **`start.py`**: Başlatıcı. Güvenlik kontrollerini yapar, ortamı hazırlar ve menüyü açar.
*   **`server/server.py`**:
    *   Tor Hidden Service yöneticisi.
    *   Paket yönlendirici (Router).
    *   Replay Guard (Tekrar saldırısı koruması).
    *   Metadata sızıntısını minimize eden yönlendirme mantığı.
*   **`client/client.py`**:
    *   **Kripto Motoru:** Double Ratchet, Sender Keys, Hybrid Encryption.
    *   **Güvenlik Modülleri:** Chameleon Memory, Anti-Debug, Screen Shield, Stylometry Guard.
    *   **Ağ Modülü:** Tor Proxy bağlantısı, Traffic Camouflage.
*   **`Tor/`**: Tor Expert Bundle (İlk çalıştırmada otomatik indirilir, sistemde kurulu değilse).

---

## ❌ Sorun Giderme

1.  **"Tor başlatılamadı" Hatası:**
    *   İnternet bağlantınızı kontrol edin.
    *   Antivirüs veya Güvenlik Duvarı `tor.exe` uygulamasını engelliyor olabilir. İzin verin.
2.  **Mesajlar gitmiyor:**
    *   Tor ağında ilk bağlantı (Handshake) 30-60 saniye sürebilir. Sabırlı olun.
    *   Karşı tarafın da çevrimiçi olduğundan emin olun.
3.  **Android/Termux Hataları:**
    *   `pkg update && pkg upgrade` komutunu çalıştırıp tekrar deneyin.
    *   `pkg install tor` komutu ile Tor'u manuel kurmayı deneyin.

---

## 📜 Yasal Uyarı ve Lisans

Bu yazılım **Eğitim ve Araştırma** amaçlı geliştirilmiştir. Kötü amaçlı kullanımlardan geliştirici sorumlu tutulamaz.

Bu proje **The Unlicense** ile lisanslanmıştır. Kamu malıdır. Kodu istediğiniz gibi değiştirebilir, dağıtabilir, satabilir veya yok edebilirsiniz.

> *Kodun içinde gizlenmiş "Dead Man's Switch" mekanizmasını devre dışı bırakmadan production ortamında kullanmayınız.*

---

## 🧠 1. ÇEKİRDEK: HİBRİT "MATRUŞKA" ŞİFRELEME MİMARİSİ
Sıradan uygulamalar tek bir şifreleme (AES veya RSA) kullanır. Ghost Link ise **"Split-Key Double Ratchet"** (Bölünmüş Anahtar) mimarisini kullanır.

### 🔐 Split-Key (Anahtar Bölme) Teknolojisi
Her mesaj için üretilen anahtar, tek bir algoritma için kullanılmaz. `HKDF-SHA256` ile türetilen 64-byte'lık anahtar bloğu ortadan ikiye bölünür:
1.  **İlk 32 Byte (Inner Key):** ChaCha20-Poly1305 motoruna beslenir.
2.  **Son 32 Byte (Outer Key):** AES-256-GCM motoruna beslenir.

### 🪆 Matruşka (İç İçe) Şifreleme
Veri ağa çıkmadan önce iki farklı matematiksel evrenden geçer:
1.  **Katman 1 (İç):** Ham veri, Google'ın geliştirdiği **ChaCha20-Poly1305** ile şifrelenir. Bu katman "Hız ve Bütünlük" sağlar.
2.  **Katman 2 (Dış):** Şifrelenmiş veri, bu sefer endüstri standardı **AES-256-GCM** ile tekrar şifrelenir.
*   **Sonuç:** Bir saldırgan AES'i kırsa bile, karşısına anlamsız bir veri yığını (ChaCha20 çıktısı) çıkar.

---

## 🧬 2. RAM GÜVENLİĞİ: CHAMELEON MEMORY (BUKALEMUN BELLEK)
Bilgisayarınız açıkken ele geçirilse bile (Cold Boot Attack), RAM analizi işe yaramaz.

*   **XOR Maskeleme:** Şifreleme anahtarları RAM'de asla "çıplak" (plaintext) durmaz.
    *   `Saklanan Veri = Gerçek Veri ^ Maske_A ^ Maske_B`
    *   Anahtarı kullanmak için anlık olarak kilit açılır ve işlem biter bitmez `ctypes.memset` ile RAM sıfırlanır.
*   **Memory Reshuffling (Bellek Karıştırma):** Arka planda çalışan bir "Daemon", her 10-30 saniyede bir RAM'deki maskeleri değiştirir. Verinin RAM üzerindeki fiziksel izi sürekli yer değiştirir.
*   **Kernel Level Locking:** İşletim sisteminin (Windows/Linux) bu verileri diske (Swap/Pagefile) yazması kernel seviyesinde engellenir (`VirtualLock` / `mlockall`).

---

## 🕸️ 3. AĞ GİZLİLİĞİ: POLİMORFİK TRAFİK & TOR
Sadece şifrelemek yetmez, "şifreli iletişim kurduğunuzu" da gizlemeniz gerekir.

*   **Tor Hidden Services (.onion):** IP adresi yok. Port yönlendirme yok. Bağlantı, dünyanın etrafında 3 farklı düğümden seker.
*   **Traffic Camouflage (Trafik Kamuflajı):** Giden veri paketleri, sıradan HTTP istekleri gibi paketlenir. Bir ağ analizcisi (Wireshark) trafiğe baktığında şunları görür:
    *   `Windows Update` isteği
    *   `Microsoft Weather API` sorgusu
    *   `Instagram` resim yüklemesi
    *   *Gerçek şifreli veri, bu masum paketlerin "Body" kısmına gizlenmiştir.*
*   **Noise Generator (Gürültü Üreteci):** Siz mesaj yazmasanız bile, sistem rastgele zamanlarda rastgele boyutta "sahte paketler" gönderir. Bu, trafik analizi (Traffic Analysis) yapanların ne zaman gerçekten konuştuğunuzu anlamasını imkansız kılar.

---

## 🛡️ 4. DONANIM VE ORTAM GÜVENLİĞİ (ANTI-FORENSICS)

### 🕒 Timestomping (Zaman Manipülasyonu)
Bir dosya silindiğinde, sistem önce içeriğini yok eder, ardından **dosyanın "Değiştirilme Tarihi"ni 1 Ocak 2000'e çeker** ve öyle siler. Adli bilişim araçları dosyanın ne zaman oluşturulduğunu veya silindiğini tespit edemez.

### 🗑️ DoD 5220.22-M İmha Protokolü
Dosyalar silinirken standart `delete` komutu kullanılmaz. Amerikan Savunma Bakanlığı standardı uygulanır:
1.  **Pass 1:** Tüm bitler `0` ile yazılır.
2.  **Pass 2:** Tüm bitler `1` ile yazılır.
3.  **Pass 3:** Kriptografik rastgele veri (`os.urandom`) ile yazılır.
4.  **Sonuç:** Manyetik mikroskopla bile veri kurtarılamaz.

### 🕵️ Stylometry Guard (Yazım Stili Gizleme)
Yapay zeka, yazım tarzınızdan (kullandığınız emojiler, noktalama alışkanlıkları) kimliğinizi tespit edebilir.
*   Sistem, mesajlarınızı göndermeden önce **anonimleştirir**.
*   Büyük/küçük harf alışkanlıklarını, gereksiz noktalama işaretlerini ve emojileri temizler.

### 📺 Screen Shield (Ekran Koruması)
*   **Windows:** `SetWindowDisplayAffinity` API'si kullanılarak pencere, ekran kaydedicilere (OBS, Discord, RAT, Ekran Alıntısı Aracı) karşı **simsiyah** görünür.

### 💀 Dead Man's Switch
*   Klavye başında 5 dakika hareketsiz kalırsanız, sistem otomatik olarak **PANIC MODE**'a geçer ve her şeyi imha eder.

---

## 🚀 KURULUM VE KULLANIM (UNIVERSAL)

Sistem; Windows, Linux, Android (Termux) ve iOS (iSH) üzerinde **tek kod** ile çalışır.

### Başlatma
1.  **Sunucu (Server):**
    ```bash
    python server/server.py
    ```
    *(Tor motorunu otomatik indirir, kurar ve size bir .onion adresi verir.)*

2.  **İstemci (Client):**
    ```bash
    python client/client.py
    ```
    *(Size verilen .onion adresini girin ve güvenli tüneli başlatın.)*

### Komutlar
*   `/nuke`: **KIRMIZI BUTON.** Tüm kanıtları yok eder, RAM'i yakar, dosyaları siler ve kapanır.
*   `/clear`: Ekranı ve terminal geçmişini temizler.

---
**Kod Sahibi:** Ghost Link Dev Team
**Lisans:** Zero-Trace Public License
