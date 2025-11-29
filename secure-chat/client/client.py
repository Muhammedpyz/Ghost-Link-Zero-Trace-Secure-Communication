

import sys
import os
import socket
import threading
import time
import subprocess
import struct
import json
import random
import ctypes
import atexit
import gc

# Gizlilik: Bytecode oluşturmayı engelle (Disk izini azaltır)
sys.dont_write_bytecode = True

# ==========================================
# GÜVENLİK: İLERİ SEVİYE KORUMA (GUARD)
# ==========================================
class SecurityGuard:
    @staticmethod
    def anti_debug():
        """Debugger ve Analiz araçlarını tespit eder (Cross-Platform)."""
        try:
            if os.name == 'nt': # Windows
                detected = False
                if ctypes.windll.kernel32.IsDebuggerPresent(): detected = True
                if not detected:
                    process = ctypes.windll.kernel32.GetCurrentProcess()
                    debugger_present = ctypes.c_bool(False)
                    ctypes.windll.kernel32.CheckRemoteDebuggerPresent(process, ctypes.byref(debugger_present))
                    if debugger_present.value: detected = True
                
                if detected:
                    SecurityGuard._trigger_decoy()
            
            elif os.name == 'posix': # Linux / macOS
                if os.path.exists("/proc/self/status"):
                    with open("/proc/self/status", "r") as f:
                        for line in f:
                            if line.startswith("TracerPid:"):
                                pid = int(line.split(":")[1].strip())
                                if pid != 0:
                                    SecurityGuard._trigger_decoy()
        except: pass

    @staticmethod
    def _trigger_decoy():
        threading.Thread(target=PanicSystem.nuke_everything, daemon=True).start()
        fake_errors = [
            ("System Error", "Critical process died."),
            ("Kernel Panic", "Attempted to kill init!"),
            ("Segmentation Fault", "Core dumped at 0x8BADF00D"),
            ("IO Error", "Disk quota exceeded.")
        ]
        while True:
            title, msg = random.choice(fake_errors)
            if os.name == 'nt':
                ctypes.windll.user32.MessageBoxW(0, msg, title, 16 | 4096)
            else:
                print(f"\n\033[91m[{title}] {msg}\033[0m")
            time.sleep(0.5)

    @staticmethod
    def camouflage():
        """Pencere başlığını değiştirir (Cross-Platform)."""
        fake_titles = ["System Update", "bash", "zsh", "kernel_task", "svchost"]
        title = random.choice(fake_titles)
        
        if os.name == 'nt':
            ctypes.windll.kernel32.SetConsoleTitleW(title)
        else:
            sys.stdout.write(f"\x1b]2;{title}\x07")
            sys.stdout.flush()

    @staticmethod
    def wipe_history():
        """Terminal geçmişini temizler."""
        if os.name == 'nt':
            try:
                os.system('doskey /listsize=0')
                os.system('doskey /listsize=50')
                os.system('cls')
            except: pass
        else:
            os.system('history -c')
            os.system('clear')

class ClipboardGuard:
    """Pano (Clipboard) güvenliğini sağlar (Cross-Platform)."""
    @staticmethod
    def clear():
        try:
            if os.name == 'nt':
                if ctypes.windll.user32.OpenClipboard(None):
                    ctypes.windll.user32.EmptyClipboard()
                    ctypes.windll.user32.CloseClipboard()
            elif sys.platform == 'darwin': # macOS
                os.system("pbcopy < /dev/null")
            else: # Linux
                # xclip veya xsel varsa kullan
                os.system("xsel -bc 2>/dev/null || xclip -selection clipboard /dev/null 2>/dev/null")
        except: pass

    @staticmethod
    def start_daemon():
        def _loop():
            while True:
                time.sleep(15) 
                ClipboardGuard.clear()
        threading.Thread(target=_loop, daemon=True).start()

class ScreenShield:
    """Ekran Görüntüsü Koruması (Anti-Capture / DRM)"""
    @staticmethod
    def protect():
        """Pencereyi ekran kaydedicilere (OBS, Discord, RAT) karşı kör eder."""
        try:
            if os.name == 'nt': # Windows
                # WDA_EXCLUDEFROMCAPTURE = 0x00000011 (Pencereyi simsiyah yapar)
                # WDA_MONITOR = 0x00000001 (Sadece monitörde görünür, kayıtta görünmez)
                WDA_EXCLUDEFROMCAPTURE = 0x00000011
                
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32
                
                # Konsol penceresinin Handle'ını al
                hwnd = kernel32.GetConsoleWindow()
                
                if hwnd:
                    # Korumayı uygula
                    result = user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
                    if result == 0:
                        # Eğer 0x11 desteklenmiyorsa (Eski Windows), 0x01 dene
                        user32.SetWindowDisplayAffinity(hwnd, 1)
                        
            elif sys.platform == 'darwin': # macOS
                # macOS'te Terminal için bunu yapmak zordur (SIP koruması).
                # Ancak iTerm2 gibi terminallerde "Secure Keyboard Entry" açılabilir.
                pass
                
            elif sys.platform.startswith('linux'):
                # Linux (X11/Wayland) için standart bir API yoktur.
                pass
                
        except Exception as e:
            # Sessizce başarısız ol (Hata basıp dikkat çekme)
            pass

class StylometryGuard:
    """AI Stylometric Sanitizer: Yazım stilini anonimleştirir."""
    @staticmethod
    def sanitize(text):
        if not text: return text
        import re
        # 1. Emojileri Temizle (Basit ASCII dışı karakterler)
        text = re.sub(r'[^\x00-\x7F]+', '', text)
        
        # 2. Noktalama İşaretlerini Standartlaştır (Tekrar edenleri sil: "!!!" -> "!")
        text = re.sub(r'([!?.,])\1+', r'\1', text)
        
        # 3. Küçük Harfe Çevir (Büyük/Küçük harf alışkanlığını gizle)
        text = text.lower()
        
        # 4. Yaygın Argo/Kısaltmaları Değiştir (Opsiyonel - Basit örnek)
        replacements = {
            " naber ": " nasılsın ",
            " slm ": " selam ",
            " ok ": " tamam ",
            " k ": " tamam "
        }
        for k, v in replacements.items():
            text = text.replace(k, v)
            
        return text.strip()

class DeadMansSwitch:
    """Dead Man's Switch: Hareketsizlik durumunda sistemi imha eder."""
    TIMEOUT = 300 # 5 Dakika (300 Saniye)
    _last_activity = 0
    _active = False
    
    @staticmethod
    def touch():
        """Aktivite zamanlayıcısını sıfırlar."""
        DeadMansSwitch._last_activity = time.time()
        
    @staticmethod
    def start():
        if DeadMansSwitch._active: return
        DeadMansSwitch._active = True
        DeadMansSwitch._last_activity = time.time()
        
        def _monitor():
            print(f"{Fore.RED}[DMS] Dead Man's Switch Aktif (Süre: {DeadMansSwitch.TIMEOUT}s){Style.RESET_ALL}")
            while True:
                time.sleep(10)
                elapsed = time.time() - DeadMansSwitch._last_activity
                if elapsed > DeadMansSwitch.TIMEOUT:
                    print(f"\n{Fore.RED}[!!!] DEAD MAN'S SWITCH TETİKLENDİ [!!!]{Style.RESET_ALL}")
                    print(f"{Fore.RED}Kullanıcı hareketsiz. İmha prosedürü başlatılıyor...{Style.RESET_ALL}")
                    PanicSystem.nuke_everything()
                    
                # Uyarı ver (Son 60 saniye)
                elif elapsed > (DeadMansSwitch.TIMEOUT - 60):
                    print(f"\r{Fore.YELLOW}[UYARI] İmha için kalan süre: {int(DeadMansSwitch.TIMEOUT - elapsed)}s (Sıfırlamak için mesaj yaz){Style.RESET_ALL}", end="")
                    
        threading.Thread(target=_monitor, daemon=True).start()

class PanicSystem:
    """Acil Durum İmha Sistemi (/nuke)"""
    @staticmethod
    def secure_delete_file(path):
        if not os.path.exists(path): return
        try:
            # 1. Timestomping (Dosya tarihini geçmişe al - Forensics yanıltma)
            try:
                # 2000-01-01 00:00:00
                old_time = 946684800
                os.utime(path, (old_time, old_time))
            except: pass

            length = os.path.getsize(path)
            with open(path, "wb") as f:
                # 2. DoD 5220.22-M Standartı (3 Geçişli Silme)
                # Pass 1: Zeros
                f.seek(0)
                f.write(b'\x00' * length)
                f.flush()
                # Pass 2: Ones
                f.seek(0)
                f.write(b'\xFF' * length)
                f.flush()
                # Pass 3: Random
                f.seek(0)
                f.write(os.urandom(length))
                f.flush()
                
            os.remove(path)
            print(f"[İmha] Silindi: {path}")
        except: pass

    @staticmethod
    def nuke_everything():
        print(f"\n{Fore.RED}[!!!] PANIC MODE ACTIVATED [!!!]{Style.RESET_ALL}")
        print(f"{Fore.RED}Tüm veriler ve dosyalar kalıcı olarak siliniyor...{Style.RESET_ALL}")
        
        # 1. Belleği Temizle
        cleanup_memory()
        
        # 2. Dosyaları Bul ve Yok Et
        # Çalıştığımız dizin ve altındakiler
        root_dir = os.getcwd()
        
        # Kendimizi (scripti) de sileceğiz, ama önce diğerlerini
        for root, dirs, files in os.walk(root_dir, topdown=False):
            for name in files:
                file_path = os.path.join(root, name)
                # Kendi scriptimizi en sona bırakalım (Windows'ta çalışırken silmek zordur ama deneriz)
                if "client.py" in name or "server.py" in name or "start.py" in name or "baslat.py" in name:
                    continue
                PanicSystem.secure_delete_file(file_path)
            
            for name in dirs:
                try:
                    os.rmdir(os.path.join(root, name))
                except: pass
        
        # Kritik dosyaları sil
        try:
            PanicSystem.secure_delete_file(sys.argv[0]) # Kendini sil
        except: pass
        
        # 3. Kapan
        print(f"{Fore.RED}Sistem imha edildi. Kapanıyor.{Style.RESET_ALL}")
        time.sleep(2)
        os._exit(0)

SecurityGuard.anti_debug()
SecurityGuard.camouflage()
SecurityGuard.wipe_history()
ScreenShield.protect() # Ekran Korumasını Başlat
ClipboardGuard.start_daemon() # Pano korumasını başlat

# ==========================================
# GÜVENLİK: BELLEK KİLİTLEME & TEMİZLİK
# ==========================================

# ==========================================
# GÜVENLİK: CHAMELEON MEMORY (RAM GİZLEME)
# ==========================================
class ChameleonMemory:
    """
    RAM'deki veriyi 2 katmanlı XOR maskelemesi ile saklar.
    Veri RAM'de asla çıplak durmaz. Sürekli şekil değiştirir.
    """
    def __init__(self, data):
        if isinstance(data, str): data = data.encode()
        self.length = len(data)
        self.mask_a = bytearray(os.urandom(self.length))
        self.mask_b = bytearray(os.urandom(self.length))
        # Çift Katmanlı Şifreleme: Veri ^ MaskA ^ MaskB
        self.storage = bytearray(d ^ a ^ b for d, a, b in zip(data, self.mask_a, self.mask_b))

    def unlock(self):
        """Veriyi anlık kullanım için açar."""
        return bytearray(s ^ a ^ b for s, a, b in zip(self.storage, self.mask_a, self.mask_b))

    def reshuffle(self):
        """Maskeleri değiştirir (RAM'deki izi sürekli değiştirir)."""
        new_mask_a = bytearray(os.urandom(self.length))
        new_mask_b = bytearray(os.urandom(self.length))
        
        # Önce veriyi kurtar
        temp = self.unlock()
        
        # Yeni maskelerle sakla
        self.mask_a = new_mask_a
        self.mask_b = new_mask_b
        self.storage = bytearray(d ^ a ^ b for d, a, b in zip(temp, self.mask_a, self.mask_b))
        
        # Temp temizle
        secure_wipe(temp)

# Global Chameleon Anahtar Saklayıcı
shared_key_store = None

def memory_shuffler():
    """Arka planda RAM'deki şifreli verilerin yerini/değerini sürekli değiştirir."""
    while True:
        time.sleep(random.randint(10, 30))
        if shared_key_store:
            try:
                shared_key_store.reshuffle()
            except: pass

threading.Thread(target=memory_shuffler, daemon=True).start()

# ==========================================
# GÜVENLİK: HAYALET TRAFİK (NOISE GENERATOR)
# ==========================================
def noise_generator(sock):
    """
    Araya sahte (decoy) paketler karıştırarak trafik analizini imkansız kılar.
    Dışarıdan bakan biri ne zaman mesaj attığınızı anlayamaz.
    """
    while True:
        time.sleep(random.uniform(5.0, 20.0)) # Rastgele aralıklarla
        try:
            # Sahte veri boyutu
            noise_len = random.randint(32, 128)
            noise_data = os.urandom(noise_len)
            
            # Protokole uygun ama içi çöp paket oluştur
            # MSG_DATA (2) + IV (12 byte) + Len (4 byte) + Data
            # IV ve Data tamamen rastgele, bu yüzden karşı taraf çözemeyip çöpe atacak.
            fake_iv = os.urandom(12)
            fake_packet = protocol.create_data_body(fake_iv, noise_data)
            
            protocol.send_packet(sock, fake_packet)
        except:
            break

# ==========================================
# GÜVENLİK: BELLEK KİLİTLEME & TEMİZLİK
# ==========================================
def lock_memory():
    """RAM'i kilitler, Swap/Pagefile kullanımını engeller (Windows Kernel Level)."""
    try:
        if os.name == 'nt':
            # Windows: SetProcessWorkingSetSize ile RAM'i zorla tut
            # Bu işlem işletim sistemine "Bu prosesin RAM'ini diske (swap) atma" der.
            process = ctypes.windll.kernel32.GetCurrentProcess()
            min_size = ctypes.c_size_t()
            max_size = ctypes.c_size_t()
            
            # Mevcut limitleri al
            if ctypes.windll.kernel32.GetProcessWorkingSetSize(process, ctypes.byref(min_size), ctypes.byref(max_size)):
                # Limitleri artır (Örn: +50MB)
                # Not: Bu işlem Admin yetkisi gerektirebilir, ancak normal kullanıcıda da 
                # "Working Set"i agresif tutmaya yarar.
                extra = 50 * 1024 * 1024
                ctypes.windll.kernel32.SetProcessWorkingSetSize(process, min_size.value + extra, max_size.value + extra)
                
        elif os.name == 'posix':
            # Linux ve macOS
            try:
                # Linux
                libc = ctypes.CDLL("libc.so.6")
            except:
                try:
                    # macOS
                    libc = ctypes.CDLL("libc.dylib")
                except:
                    return
            
            # MCL_CURRENT | MCL_FUTURE = 3
            libc.mlockall(3) 
    except: pass

def secure_wipe(data):
    """Bytearray verisini ctypes.memset ile 0 ile doldurur (RAM Temizliği)."""
    if isinstance(data, (bytearray, bytes)):
        # Verinin bellek adresini al
        try:
            # ctypes.c_char dizisi oluştur
            char_array = (ctypes.c_char * len(data)).from_buffer(data)
            # memset ile sıfırla
            ctypes.memset(char_array, 0, len(data))
        except TypeError:
            # bytes nesnesi ise (immutable), en azından referansı silmeye çalışırız
            # ama Python'da bytes üzerinde memset yapmak zordur.
            # Bu yüzden kodda bytearray kullanmaya özen gösteriyoruz.
            pass
    elif isinstance(data, list):
        for item in data:
            secure_wipe(item)

# Program kapanırken çalışacak temizlik fonksiyonu
def cleanup_memory():
    global shared_key_store
    # print(f"\n{Fore.RED}[Güvenlik] Acil durum protokolü: Bellek temizleniyor...{Style.RESET_ALL}")
    if shared_key_store:
        # ChameleonMemory içindeki her şeyi sil
        secure_wipe(shared_key_store.storage)
        secure_wipe(shared_key_store.mask_a)
        secure_wipe(shared_key_store.mask_b)
        # print(f"{Fore.RED}[Güvenlik] Anahtarlar imha edildi.{Style.RESET_ALL}")
    gc.collect()

atexit.register(cleanup_memory)
lock_memory()

# ==========================================
# 1. BÖLÜM: GÜÇLENDİRİLMİŞ ONARIM SİSTEMİ
# ==========================================
def install_missing_libs():
    """Eksik kütüphaneleri zorla yükler."""
    required = [("cryptography", "cryptography"), 
                ("colorama", "colorama"), 
                ("socks", "PySocks"),
                ("stem", "stem"),
                ("psutil", "psutil")] 
    
    missing = []
    for import_name, pip_name in required:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)
    
    if missing:
        print(f"Eksik modüller: {', '.join(missing)}")
        print(f"Otomatik yükleniyor... (Bu işlem biraz sürebilir)")
        
        # Yöntem 1: Normal Yükleme
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print("Yükleme başarılı!")
        except:
            print("Normal yükleme başarısız, 'user' modu deneniyor...")
            # Yöntem 2: --user bayrağı ile (Yetki hatası varsa)
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user"] + missing)
                print("User modunda yüklendi!")
            except:
                print("Hala başarısız! Zorla yükleme modu deneniyor...")
                # Yöntem 3: Cache temizle ve zorla
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "--user"] + missing)
                    print("Zorla yükleme tamamlandı!")
                except Exception as e:
                    print(f"KRİTİK HATA: Kütüphaneler yüklenemedi. İnternet bağlantını kontrol et.")
                    print(f"Hata detayı: {e}")
                    input("Kapatmak için Enter'a bas...")
                    sys.exit(1)
        time.sleep(1)

install_missing_libs()

# Kütüphaneler yüklendikten sonra importlar
import socks # type: ignore
from colorama import init, Fore, Style # type: ignore
try:
    import stem.process # type: ignore
except ImportError:
    stem = None

from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import x25519 # type: ignore
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305 # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore

# Renkleri başlat
init(autoreset=True)

# ==========================================
# 2. BÖLÜM: GÖMÜLÜ MODÜLLER (CRYPTO & PROTOCOL)
# ==========================================

class CryptoUtils:
    """Kriptografi Altyapısı (Gömülü)"""
    @staticmethod
    def generate_keypair():
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def public_key_to_bytes(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

    @staticmethod
    def bytes_to_public_key(data):
        return x25519.X25519PublicKey.from_public_bytes(data)

    @staticmethod
    def derive_shared_key(private_key, peer_public_key):
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-chat-handshake',
        ).derive(shared_key)
        # Güvenlik: Anahtarı ChameleonMemory içine hapset
        return ChameleonMemory(bytearray(derived_key))

    @staticmethod
    def encrypt_message(key_store, plaintext):
        # key_store artık bir ChameleonMemory objesi
        
        # 1. Anahtarı anlık olarak RAM'e çağır
        real_key = key_store.unlock()
        
        if isinstance(plaintext, str):
            plaintext_bytes = bytearray(plaintext.encode('utf-8'))
        elif isinstance(plaintext, bytes):
            plaintext_bytes = bytearray(plaintext)
        else:
            plaintext_bytes = plaintext
        
        # Obfuscation: JSON Padding ekle
        padding_size = random.randint(10, 100)
        padding_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=padding_size))
        
        payload = {
            'm': plaintext_bytes.decode('utf-8'), 
            'p': padding_data               
        }
        
        json_str = json.dumps(payload)
        json_payload = bytearray(json_str.encode('utf-8'))
        
        if isinstance(plaintext_bytes, bytearray):
            secure_wipe(plaintext_bytes)

        # HYBRID DOUBLE ENCRYPTION (Matryoshka Style)
        # Anahtarı ikiye böl: Biri ChaCha20 için, diğeri AES için
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'hybrid-split',
        )
        derived = hkdf.derive(real_key)
        key_inner = derived[:32]
        key_outer = derived[32:]

        # Katman 1: İç Şifreleme (ChaCha20-Poly1305 - "Harder Crypto")
        chacha = ChaCha20Poly1305(key_inner)
        nonce1 = os.urandom(12)
        cipher1 = chacha.encrypt(nonce1, json_payload, None)
        
        secure_wipe(json_payload)
        
        # Katman 2: Dış Şifreleme (AES-256-GCM - "Standard Crypto")
        aesgcm = AESGCM(key_outer)
        blob = nonce1 + cipher1
        nonce2 = os.urandom(12)
        cipher2 = aesgcm.encrypt(nonce2, blob, None)
        
        # İşlem bitti, anahtarı RAM'den sil (ChameleonMemory'de kopyası var)
        secure_wipe(real_key)
        secure_wipe(derived) # Türetilmiş anahtarları da sil
        
        return nonce2, cipher2

    @staticmethod
    def decrypt_message(key_store, nonce, ciphertext):
        # 1. Anahtarı anlık olarak RAM'e çağır
        real_key = key_store.unlock()
        
        try:
            # Anahtarları türet
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,
                salt=None,
                info=b'hybrid-split',
            )
            derived = hkdf.derive(real_key)
            key_inner = derived[:32]
            key_outer = derived[32:]

            # Katman 2 Çözme (AES-256-GCM)
            aesgcm = AESGCM(key_outer)
            blob = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Katman 1 Çözme (ChaCha20-Poly1305)
            nonce1 = blob[:12]
            cipher1 = blob[12:]
            
            chacha = ChaCha20Poly1305(key_inner)
            decrypted_json = chacha.decrypt(nonce1, cipher1, None)
            
            # JSON Padding'i temizle
            try:
                payload = json.loads(decrypted_json.decode('utf-8'))
                return payload['m'].encode('utf-8')
            except:
                return decrypted_json
        finally:
            # Hata olsa bile anahtarı sil
            secure_wipe(real_key)
            try: secure_wipe(derived)
            except: pass

class TrafficCamouflage:
    """Polimorfik Trafik Gizleme (Advanced Steganography)"""
    TEMPLATES = [
        # Microsoft Windows Update (En yaygın trafik)
        (b"POST /v6/ClientWebService/client.asmx HTTP/1.1\r\n"
         b"Host: fe2.update.microsoft.com\r\n"
         b"User-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.21\r\n"
         b"Content-Type: application/soap+xml; charset=utf-8\r\n"
         b"Connection: keep-alive\r\n"),

        # Microsoft Weather API
        (b"GET /weather/current?locale=en-US&units=C HTTP/1.1\r\n"
         b"Host: weather.microsoft.com\r\n"
         b"User-Agent: Microsoft-Weather-App/4.53.212\r\n"
         b"Accept: application/json\r\n"
         b"Connection: keep-alive\r\n"
         b"X-Correlation-ID: {random_id}\r\n"),
         
        # Google Analytics
        (b"POST /collect HTTP/1.1\r\n"
         b"Host: www.google-analytics.com\r\n"
         b"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
         b"Content-Type: application/json\r\n"
         b"Connection: keep-alive\r\n"),
         
        # Meta / Facebook Graph
        (b"POST /graphql HTTP/1.1\r\n"
         b"Host: graph.facebook.com\r\n"
         b"User-Agent: Facebook/350.0.0.0.0 (Windows; U; Windows NT 10.0; en_US)\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Connection: keep-alive\r\n"),
         
        # AWS S3 Upload
        (b"PUT /upload/storage HTTP/1.1\r\n"
         b"Host: s3.amazonaws.com\r\n"
         b"User-Agent: aws-sdk-java/2.17.100\r\n"
         b"Content-Type: application/octet-stream\r\n"
         b"Connection: keep-alive\r\n"),
         
        # Cloudflare Beacon
        (b"POST /cdn-cgi/beacon/performance HTTP/1.1\r\n"
         b"Host: cloudflare.com\r\n"
         b"User-Agent: Mozilla/5.0\r\n"
         b"Content-Type: application/json\r\n"
         b"Connection: keep-alive\r\n"),

        # Instagram API
        (b"POST /api/v1/media/upload/ HTTP/1.1\r\n"
         b"Host: i.instagram.com\r\n"
         b"User-Agent: Instagram 219.0.0.12.117 Android\r\n"
         b"Content-Type: application/x-www-form-urlencoded\r\n"
         b"Connection: keep-alive\r\n")
    ]
    
    @staticmethod
    def wrap_packet(data):
        import random
        template = random.choice(TrafficCamouflage.TEMPLATES)
        # Dinamik ID ekle (Weather API gibi yerler için)
        if b"{random_id}" in template:
            rid = str(random.randint(100000, 999999)).encode()
            template = template.replace(b"{random_id}", rid)
            
        header = template + f"Content-Length: {len(data)}\r\n\r\n".encode()
        return header + data

class ProtocolUtils:
    """Protokol Tasarımı (Gömülü) - HTTP KAMUFLAJ MODU"""
    MSG_HELLO = 0
    MSG_HANDSHAKE = 1
    MSG_DATA = 2

    @staticmethod
    def send_packet(sock, packet_body):
        try:
            # İç paket (Binary Protocol)
            inner_data = struct.pack('!I', len(packet_body)) + packet_body
            
            # Dış paket (Polimorfik HTTP)
            full_packet = TrafficCamouflage.wrap_packet(inner_data)
            
            sock.sendall(full_packet)
        except Exception as e:
            print(f"Error sending packet: {e}")

    @staticmethod
    def receive_packet(sock):
        try:
            # 1. HTTP Headerlarını Oku
            header_buffer = b""
            while b"\r\n\r\n" not in header_buffer:
                chunk = sock.recv(1)
                if not chunk: return None
                header_buffer += chunk
                if len(header_buffer) > 4096: return None
            
            # 2. Content-Length Bul
            headers_str = header_buffer.decode(errors='ignore')
            import re
            match = re.search(r'Content-Length:\s*(\d+)', headers_str, re.IGNORECASE)
            if not match: return None
            
            body_length = int(match.group(1))
            
            # 3. Body Oku
            data = b''
            while len(data) < body_length:
                chunk = sock.recv(body_length - len(data))
                if not chunk: return None
                data += chunk
                
            # 4. İç Paketi Çöz
            if len(data) < 4: return None
            inner_length = struct.unpack('!I', data[:4])[0]
            
            if len(data) < 4 + inner_length: return None
            
            return data[4:4+inner_length]
            
        except Exception as e:
            return None

    @staticmethod
    def create_hello_body(nickname):
        nick_bytes = nickname.encode('utf-8')
        return struct.pack('!B', ProtocolUtils.MSG_HELLO) + nick_bytes

    @staticmethod
    def create_handshake_body(public_key_bytes):
        return struct.pack('!B', ProtocolUtils.MSG_HANDSHAKE) + public_key_bytes

    @staticmethod
    def create_data_body(iv, ciphertext):
        length = len(ciphertext)
        return struct.pack('!B', ProtocolUtils.MSG_DATA) + iv + struct.pack('!I', length) + ciphertext

    @staticmethod
    def parse_body(data):
        if not data:
            return None
        msg_type = data[0]
        
        if msg_type == ProtocolUtils.MSG_HELLO:
            return {'type': 'hello', 'nickname': data[1:]}

        if msg_type == ProtocolUtils.MSG_HANDSHAKE:
            if len(data) < 33: return None
            public_key = data[1:33]
            return {'type': 'handshake', 'public_key': public_key}
        
        elif msg_type == ProtocolUtils.MSG_DATA:
            if len(data) < 17: return None
            iv = data[1:13]
            length = struct.unpack('!I', data[13:17])[0]
            if len(data) < 17 + length: return None
            ciphertext = data[17:17+length]
            return {'type': 'data', 'iv': iv, 'ciphertext': ciphertext}
        return None

# Global instances for compatibility
crypto = CryptoUtils()
protocol = ProtocolUtils()

# ==========================================
# 3. BÖLÜM: TOR YÖNETİMİ
# ==========================================

def print_system(msg):
    print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

def print_error(msg):
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")

def print_peer(msg):
    print(f"\r{Fore.YELLOW}root@peer:~$ {msg}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}root@local:~$ {Style.RESET_ALL}", end='', flush=True)

def download_tor():
    """Tor Expert Bundle'ı otomatik indirir ve kurar (Cross-Platform)."""
    print_system("Tor motoru bulunamadı. İnternetten indiriliyor...")
    
    import platform
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    url = None
    local_filename = "tor_expert_bundle.tar.gz"
    
    # URL Seçimi (Tor 15.0.2)
    if system == 'windows':
        if '64' in machine:
            url = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.2/tor-expert-bundle-windows-x86_64-15.0.2.tar.gz"
        else:
            url = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.2/tor-expert-bundle-windows-i686-15.0.2.tar.gz"
            
    elif system == 'darwin': # macOS
        if 'arm' in machine or 'aarch64' in machine:
            url = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.2/tor-expert-bundle-macos-aarch64-15.0.2.tar.gz"
        else:
            url = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.2/tor-expert-bundle-macos-x86_64-15.0.2.tar.gz"
            
    elif system == 'linux':
        if '64' in machine:
            url = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.2/tor-expert-bundle-linux-x86_64-15.0.2.tar.gz"
        else:
            url = "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.2/tor-expert-bundle-linux-i686-15.0.2.tar.gz"
    
    if not url:
        print_error(f"İşletim sistemi desteklenmiyor: {system} {machine}")
        return None

    try:
        import urllib.request
        import tarfile
        
        print_system(f"İndiriliyor: {url}")
        urllib.request.urlretrieve(url, local_filename)
        print_system("İndirme tamamlandı. Dosyalar çıkartılıyor...")
        
        with tarfile.open(local_filename, "r:gz") as tar:
            tar.extractall()
            
        print_system("Kurulum başarılı!")
        try:
            os.remove(local_filename)
        except: pass
            
        # Tor yolu platforma göre değişebilir
        if system == 'windows':
            return os.path.join(os.getcwd(), "Tor", "tor.exe")
        else:
            return os.path.join(os.getcwd(), "tor", "tor")

    except Exception as e:
        print_error(f"İndirme hatası: {e}")
        return None

def find_tor_executable():
    """Tor dosyasını arar (Cross-Platform)."""
    search_paths = []
    
    if os.name == 'nt':
        search_paths = [
            os.path.join(os.getcwd(), "Tor", "tor.exe"),
            os.path.join(os.getcwd(), "tor.exe"),
            r"C:\Tor\tor.exe",
            os.path.join(os.path.expanduser("~"), "Desktop", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
        ]
        for drive in ["C:", "D:", "E:"]:
            search_paths.append(os.path.join(drive + "\\", "Program Files", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
            search_paths.append(os.path.join(drive + "\\", "Program Files (x86)", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"))
            
    else: # Linux / macOS
        search_paths = [
            "tor", 
            "/usr/bin/tor",
            "/usr/local/bin/tor",
            "/opt/homebrew/bin/tor",
            "/opt/local/bin/tor",
            os.path.join(os.getcwd(), "tor"),
            os.path.join(os.getcwd(), "tor", "tor")
        ]

    if os.name != 'nt':
        import shutil
        if shutil.which("tor"):
            return shutil.which("tor")

    for path in search_paths:
        if os.path.exists(path):
            return path
            
    if os.name == 'nt':
        print_system("Standart yollarda bulunamadı. Tüm C:/ sürücüsü taranıyor...")
        try:
            for root, dirs, files in os.walk("C:\\"):
                if "tor.exe" in files:
                    found_path = os.path.join(root, "tor.exe")
                    print_system(f"Bulundu: {found_path}")
                    return found_path
        except: pass

    return download_tor()

def check_tor_port(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex(('127.0.0.1', port))
        s.close()
        return result == 0
    except: return False

def start_tor_client_service():
    if check_tor_port(9150): 
        print_system("Tor Browser algılandı (Port 9150).")
        return 9150, None
    if check_tor_port(9050): 
        print_system("Tor Servisi algılandı (Port 9050).")
        return 9050, None

    print_system("Tor proxy bulunamadı. Otomatik başlatılıyor...")
    tor_path = find_tor_executable()
    if not tor_path:
        print_error("Tor bulunamadı ve indirilemedi.")
        return None, None

    try:
        print_system(f"Tor başlatılıyor: {tor_path}")
        tor_process = stem.process.launch_tor_with_config(
            tor_cmd=tor_path,
            config={'SocksPort': '9050'},
            take_ownership=True
        )
        print_system("Tor motoru başlatıldı (Port 9050).")
        return 9050, tor_process
    except Exception as e:
        print_error(f"Tor başlatılamadı: {e}")
        try:
            import psutil # type: ignore
            for proc in psutil.process_iter():
                if proc.name() == "tor.exe": proc.kill()
            print_system("Eski Tor işlemleri temizlendi. Tekrar deneniyor...")
            return start_tor_client_service()
        except: pass
        return None, None

# ==========================================
# 4. BÖLÜM: ANA İSTEMCİ MANTIĞI
# ==========================================

HOST = '127.0.0.1'
PORT = 5000
private_key, public_key = crypto.generate_keypair()
shared_key_store = None # shared_key yerine shared_key_store kullanıyoruz

def receive_messages(sock):
    global shared_key_store
    while True:
        try:
            data = protocol.receive_packet(sock)
            if not data:
                # print_error("Bağlantı koptu.")
                os._exit(0)
            
            parsed = protocol.parse_body(data)
            if not parsed: continue
                
            if parsed['type'] == 'handshake':
                peer_public_key_bytes = parsed['public_key']
                try:
                    peer_public_key = crypto.bytes_to_public_key(peer_public_key_bytes)
                    should_reply = (shared_key_store is None)
                    # derive_shared_key artık ChameleonMemory döndürüyor
                    shared_key_store = crypto.derive_shared_key(private_key, peer_public_key)
                    if should_reply:
                        print_system("Güvenli el sıkışma başarılı. (AES-256-GCM)")
                        pub_bytes = crypto.public_key_to_bytes(public_key)
                        handshake_packet = protocol.create_handshake_body(pub_bytes)
                        protocol.send_packet(sock, handshake_packet)
                        
                        # Gürültü (Noise) Jeneratörünü Başlat
                        threading.Thread(target=noise_generator, args=(sock,), daemon=True).start()
                        
                except Exception as e:
                    print_error(f"Handshake hatası: {e}")
                    
            elif parsed['type'] == 'data':
                if shared_key_store:
                    try:
                        # decrypt_message artık key_store alıyor
                        plaintext = crypto.decrypt_message(shared_key_store, parsed['iv'], parsed['ciphertext'])
                        print_peer(plaintext.decode('utf-8'))
                    except Exception as e:
                        # Şifre çözme hatası = Muhtemelen Noise (Sahte) paket
                        # Sessizce yutuyoruz (Chameleon Modu)
                        pass
        except Exception as e:
            # print_error(f"Okuma hatası: {e}")
            break

def start_client():
    global shared_key_store, HOST, PORT
    
    SecurityGuard.wipe_history()
    print(f"{Fore.GREEN}")
    print("""
    Initializing System Update...
    [====================] 100%
    """)
    
    # Dead Man's Switch Başlat
    DeadMansSwitch.start()

    # Otomatik Mod: Kullanıcıya sormadan önce argümanlara veya varsayılanlara bak
    import random
    nickname = f"User{random.randint(1000,9999)}"
    
    print(f"{Fore.GREEN}System ID (Nickname): {nickname}{Style.RESET_ALL}")
    
    if check_tor_port(9050) or check_tor_port(9150):
         pass

    raw_input = input(f"{Fore.GREEN}Target Endpoint (IP/Onion): {Style.RESET_ALL}").strip()
    
    if not raw_input:
        HOST = '127.0.0.1'
        PORT = 5000
        print_system("Yerel sunucuya bağlanılıyor...")
    elif ":" in raw_input:
        parts = raw_input.split(":")
        HOST = parts[0]
        try: PORT = int(parts[1])
        except: PORT = 5000
    else:
        HOST = raw_input
        if HOST.endswith('.onion'): PORT = 80
        else:
            p_input = input(f"{Fore.GREEN}Target Port [5000]: {Style.RESET_ALL}").strip()
            if p_input: PORT = int(p_input)

    tor_process = None
    
    # HER ZAMAN TOR PROXY KULLAN (Güvenlik İçin)
    # Localhost olsa bile Tor Socks üzerinden geçirmek daha güvenli olabilir ama
    # 127.0.0.1 için direkt bağlantı daha mantıklı.
    # Ancak kullanıcı "Sadece Tor" dedi.
    # Eğer hedef .onion ise ZORUNLU Tor.
    # Eğer hedef IP ise yine Tor üzerinden geçirelim (Anonimlik için).
    
    print_system(f"Tor Ağına Bağlanılıyor... Hedef: {HOST}")
    proxy_port, tor_process = start_tor_client_service()
    
    if not proxy_port:
        print_error("Tor başlatılamadığı için bağlantı kurulamıyor.")
        return
    
    print_system(f"Tor Ağına Bağlanılıyor... Hedef: {HOST}")
    proxy_port, tor_process = start_tor_client_service()
    
    if not proxy_port:
        print_error("Tor başlatılamadığı için bağlantı kurulamıyor.")
        return

    print_system(f"Proxy tüneli kuruldu: 127.0.0.1:{proxy_port}")
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", proxy_port)
    socket.socket = socks.socksocket
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(60) 
    
    try:
        print_system(f"Bağlanılıyor: {HOST}:{PORT}...")
        sock.connect((HOST, PORT))
        sock.settimeout(None)
        
        hello_packet = protocol.create_hello_body(nickname)
        protocol.send_packet(sock, hello_packet)
        
    except Exception as e:
        print_error(f"Sunucuya erişilemedi: {e}")
        if HOST.endswith('.onion'):
            print_error("İPUCU: .onion adresinin doğru olduğundan emin olun.")
        if tor_process: tor_process.kill()
        return

    pub_bytes = crypto.public_key_to_bytes(public_key)
    handshake_packet = protocol.create_handshake_body(pub_bytes)
    protocol.send_packet(sock, handshake_packet)
    print_system("Bağlantı kuruldu. Kanal dinleniyor...")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()

    while True:
        try:
            msg_content = input(f"{Fore.GREEN}root@{nickname}:~$ {Style.RESET_ALL}")
            
            # Dead Man's Switch Reset
            DeadMansSwitch.touch()
            
            if not msg_content: continue
            
            if msg_content.strip() == "/nuke":
                PanicSystem.nuke_everything()
                break
                
            if msg_content.strip() == "/clear":
                SecurityGuard.wipe_history()
                continue

            if not shared_key_store:
                print_error("Henüz güvenli bağlantı kurulmadı. Bekleyin...")
                continue
            
            # AI Stylometric Sanitizer Uygula
            msg_content = StylometryGuard.sanitize(msg_content)
            
            full_msg_str = f"[{nickname}]: {msg_content}"
            full_msg_bytes = bytearray(full_msg_str.encode('utf-8'))
            
            iv, ciphertext = crypto.encrypt_message(shared_key_store, full_msg_bytes)
            
            secure_wipe(full_msg_bytes)
            del full_msg_str
            del msg_content
            gc.collect()
            
            packet = protocol.create_data_body(iv, ciphertext)
            protocol.send_packet(sock, packet)
        except KeyboardInterrupt:
            break
    
    if tor_process: tor_process.kill()

if __name__ == "__main__":
    start_client()
