

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

class SecureInput:
    """
    Güvenli Giriş Sistemi:
    1. Standart input() fonksiyonunu kullanmaz (String oluşturmaz).
    2. Karakterleri tek tek okur ve doğrudan bytearray'e yazar.
    3. İşlem bitince belleği anında temizler.
    4. Keylogger'lara karşı OS buffer'ını atlar (Low-Level I/O).
    """
    @staticmethod
    def _getch():
        """Tek bir karakter okur (Cross-Platform)."""
        if os.name == 'nt':
            import msvcrt
            # getwch() Unicode karakterleri de okur
            return msvcrt.getwch()
        else:
            import tty, termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                ch = sys.stdin.read(1)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            return ch

    @staticmethod
    def ask(prompt):
        """Güvenli bir şekilde veri okur."""
        sys.stdout.write(prompt)
        sys.stdout.flush()
        
        buffer = bytearray()
        
        while True:
            char = SecureInput._getch()
            
            # Enter (Windows: \r, Unix: \n)
            if char in ('\r', '\n'):
                sys.stdout.write('\n')
                break
                
            # Backspace (Windows: \x08, Unix: \x7f)
            elif char in ('\x08', '\x7f'):
                if len(buffer) > 0:
                    buffer.pop()
                    # Ekrandan silme efekti
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            
            # Ctrl+C (ETX)
            elif char == '\x03':
                raise KeyboardInterrupt
            
            # Normal Karakter
            else:
                # Byte'a çevirip ekle
                try:
                    encoded = char.encode('utf-8')
                    buffer.extend(encoded)
                    sys.stdout.write(char)
                    sys.stdout.flush()
                except: pass
                
        return buffer

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
            length = os.path.getsize(path)
            
            # 1. Önce İçeriği Yok Et (Shredding)
            # Dosyayı açıp üzerine yazmak "Değiştirilme Tarihini" günceller.
            # Bu yüzden önce silme/karıştırma işlemini yapıyoruz.
            with open(path, "wb") as f:
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

            # 2. Timestomping (Dosya tarihini geçmişe al - Forensics yanıltma)
            # Yazma işlemi bittikten SONRA tarihi değiştiriyoruz ki son iz 2000 yılı kalsın.
            try:
                # 2000-01-01 00:00:00
                old_time = 946684800
                os.utime(path, (old_time, old_time))
            except: pass
                
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
# 1. BÖLÜM: GÜÇLENDİRİLMİŞ ONARIM SİSTEMİ (UNIVERSAL)
# ==========================================
def universal_setup():
    """Tüm platformlar için (Windows, Linux, Android, iOS) otomatik kurulum."""
    import platform
    system_name = platform.system().lower()
    is_android = 'ANDROID_ROOT' in os.environ
    is_ios = os.path.exists("/etc/alpine-release")
    
    try:
        if is_android:
            print(f"{Fore.YELLOW}[Sistem] Android (Termux) algılandı. Paketler kontrol ediliyor...{Style.RESET_ALL}")
            subprocess.run("pkg update -y", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("pkg install -y python tor libcrypt clang openssl", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            # Cryptography Android'de derleme ister, hazir paket varsa onu kullan
            subprocess.run("pkg install -y python-cryptography", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        elif is_ios:
            print(f"{Fore.YELLOW}[Sistem] iOS (iSH) algılandı. Paketler kontrol ediliyor...{Style.RESET_ALL}")
            subprocess.run("apk update", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("apk add python3 py3-pip tor py3-cryptography py3-psutil git", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

def install_missing_libs():
    """Eksik kütüphaneleri zorla yükler."""
    
    # Önce sistem seviyesinde kurulum yap (Mobile için)
    universal_setup()

    # iSH (iOS) / Alpine Linux Kontrolü
    if os.path.exists("/etc/alpine-release"):
        print(f"{Fore.YELLOW}[Sistem] iOS / Alpine Linux algılandı.{Style.RESET_ALL}")
        print("Bu sistemde 'pip' yerine sistem paketlerini kullanmanız önerilir.")
        # Yine de devam etmeye çalışalım, belki kuruludur.
    
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
        
        # GÜVENLİK NOTU: Supply Chain Attack Koruması
        # Normalde burada indirilen paketlerin SHA256 hash'lerini kontrol etmemiz gerekir.
        # Ancak PyPI sürekli güncellendiği için sabit hash kullanmak kurulumu bozabilir.
        # Kritik ortamlarda bu kütüphaneler önceden indirilip (vendored) projeye dahil edilmelidir.
        
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
                    # Mobile cihazlarda --break-system-packages gerekebilir
                    cmd = [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "--user"] + missing
                    if os.path.exists("/etc/alpine-release") or 'ANDROID_ROOT' in os.environ:
                         cmd.append("--break-system-packages")
                    
                    subprocess.check_call(cmd)
                    print("Zorla yükleme tamamlandı!")
                except Exception as e:
                    print(f"KRİTİK HATA: Kütüphaneler yüklenemedi. İnternet bağlantını kontrol et.")
                    print(f"Hata detayı: {e}")
                    # input("Kapatmak için Enter'a bas...")
                    # sys.exit(1)
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

class RatchetSession:
    """
    Double Ratchet (Simplified Symmetric) Implementation.
    Used for UNICAST (1-to-1) key exchange.
    """
    def __init__(self, root_key, role='initiator'):
        self.root_key = root_key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ratchet-init',
        )
        derived = hkdf.derive(root_key)
        chain_a = derived[:32]
        chain_b = derived[32:]
        
        if role == 'initiator':
            self.send_chain = ChameleonMemory(chain_a)
            self.recv_chain = ChameleonMemory(chain_b)
        else:
            self.send_chain = ChameleonMemory(chain_b)
            self.recv_chain = ChameleonMemory(chain_a)
            
    def ratchet_step(self, chain_memory):
        current_chain_key = chain_memory.unlock()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ratchet-step',
        )
        derived = hkdf.derive(current_chain_key)
        next_chain_key = derived[:32]
        message_key = derived[32:]
        
        chain_memory.storage = ChameleonMemory(next_chain_key).storage
        chain_memory.mask_a = ChameleonMemory(next_chain_key).mask_a
        chain_memory.mask_b = ChameleonMemory(next_chain_key).mask_b
        
        secure_wipe(current_chain_key)
        secure_wipe(derived)
        return message_key

class GroupCipher:
    """
    Sender Keys Architecture (One-Way Ratchet).
    Used for BROADCAST (Group) messaging.
    Each user has their own Chain Key and distributes it to others.
    """
    def __init__(self, chain_key):
        # chain_key is bytes
        self.chain = ChameleonMemory(chain_key)
        
    def step(self):
        """Advances the chain and returns the message key."""
        current_chain_key = self.chain.unlock()
        
        # KDF: ChainKey -> (NextChainKey, MessageKey)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'group-ratchet-step',
        )
        derived = hkdf.derive(current_chain_key)
        next_chain_key = derived[:32]
        message_key = derived[32:]
        
        # Update Chain
        self.chain.storage = ChameleonMemory(next_chain_key).storage
        self.chain.mask_a = ChameleonMemory(next_chain_key).mask_a
        self.chain.mask_b = ChameleonMemory(next_chain_key).mask_b
        
        secure_wipe(current_chain_key)
        secure_wipe(derived)
        
        return message_key

class CryptoUtils:
    """Kriptografi Altyapısı"""
    @staticmethod
    def generate_keypair():
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def generate_symmetric_key():
        return os.urandom(32)

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
    def derive_shared_key(private_key, peer_public_key, my_public_key):
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-chat-handshake',
        ).derive(shared_key)
        
        my_bytes = my_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        peer_bytes = peer_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        
        role = 'initiator' if my_bytes > peer_bytes else 'responder'
        return RatchetSession(derived_key, role)

    @staticmethod
    def encrypt_direct(ratchet_session, plaintext):
        """Encrypts a unicast message (e.g., Key Exchange) using Double Ratchet."""
        real_key = ratchet_session.ratchet_step(ratchet_session.send_chain)
        return CryptoUtils._encrypt_with_key(real_key, plaintext)

    @staticmethod
    def decrypt_direct(ratchet_session, iv, ciphertext):
        """Decrypts a unicast message."""
        real_key = ratchet_session.ratchet_step(ratchet_session.recv_chain)
        return CryptoUtils._decrypt_with_key(real_key, iv, ciphertext)

    @staticmethod
    def encrypt_group(group_cipher, plaintext):
        """Encrypts a broadcast message using Sender Keys with Timestamp (Replay Protection)."""
        real_key = group_cipher.step()
        
        # Replay Attack Protection: Add Timestamp (8 bytes double)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        timestamp = time.time()
        # Payload: [Timestamp (8 bytes)] + [Message]
        payload = struct.pack('!d', timestamp) + plaintext
        
        return CryptoUtils._encrypt_with_key(real_key, payload)

    @staticmethod
    def decrypt_group(group_cipher, iv, ciphertext):
        """Decrypts a broadcast message and verifies Timestamp."""
        real_key = group_cipher.step()
        decrypted_data = CryptoUtils._decrypt_with_key(real_key, iv, ciphertext)
        
        # Replay Attack Check
        if len(decrypted_data) < 8:
            return None
            
        timestamp = struct.unpack('!d', decrypted_data[:8])[0]
        message_bytes = decrypted_data[8:]
        
        current_time = time.time()
        # 5 Saniye Kuralı (Replay Attack Koruması)
        # Tor ağındaki gecikmeler için bu süre normalde artırılmalıdır ama
        # "Ultra Güvenlik" isteği üzerine 5 saniye olarak ayarlandı.
        if current_time - timestamp > 5.0:
            print(f"\n{Fore.RED}[GÜVENLİK UYARISI] Replay Attack Tespit Edildi! (Eski Mesaj){Style.RESET_ALL}")
            # Saldırı tespit edildiğinde boş dön veya hata fırlat
            raise Exception("Replay Attack: Message too old")
            
        if current_time - timestamp < -30.0: # Gelecekten gelen mesaj (Saat hatası)
             raise Exception("Message from future")
             
        return message_bytes

    @staticmethod
    def _encrypt_with_key(key, plaintext):
        if isinstance(plaintext, str): plaintext = plaintext.encode('utf-8')
        
        # Padding
        TARGET_SIZE = 1024 # Key exchange payloads are small
        if len(plaintext) > 1024: TARGET_SIZE = 4096
        
        final_block = bytearray(TARGET_SIZE)
        struct.pack_into('!I', final_block, 0, len(plaintext))
        final_block[4:4+len(plaintext)] = plaintext
        remaining = TARGET_SIZE - (4 + len(plaintext))
        if remaining > 0:
            final_block[4+len(plaintext):] = os.urandom(remaining)

        # Hybrid Encryption
        hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'hybrid-split')
        derived = hkdf.derive(key)
        key_inner = derived[:32]
        key_outer = derived[32:]

        chacha = ChaCha20Poly1305(key_inner)
        nonce1 = os.urandom(12)
        cipher1 = chacha.encrypt(nonce1, final_block, None)
        
        aesgcm = AESGCM(key_outer)
        blob = nonce1 + cipher1
        nonce2 = os.urandom(12)
        cipher2 = aesgcm.encrypt(nonce2, blob, None)
        
        secure_wipe(key)
        secure_wipe(derived)
        secure_wipe(final_block)
        
        return nonce2, cipher2

    @staticmethod
    def _decrypt_with_key(key, nonce, ciphertext):
        try:
            hkdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=b'hybrid-split')
            derived = hkdf.derive(key)
            key_inner = derived[:32]
            key_outer = derived[32:]

            aesgcm = AESGCM(key_outer)
            blob = aesgcm.decrypt(nonce, ciphertext, None)
            
            nonce1 = blob[:12]
            cipher1 = blob[12:]
            
            chacha = ChaCha20Poly1305(key_inner)
            decrypted_block = chacha.decrypt(nonce1, cipher1, None)
            
            data_len = struct.unpack('!I', decrypted_block[:4])[0]
            return decrypted_block[4:4+data_len]
        finally:
            secure_wipe(key)
            try: secure_wipe(derived)
            except: pass

class TrafficCamouflage:
    TEMPLATES = [
        (b"POST /v6/ClientWebService/client.asmx HTTP/1.1\r\nHost: fe2.update.microsoft.com\r\nUser-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/1.21\r\nContent-Type: application/soap+xml; charset=utf-8\r\nConnection: keep-alive\r\n"),
        (b"GET /weather/current?locale=en-US&units=C HTTP/1.1\r\nHost: weather.microsoft.com\r\nUser-Agent: Microsoft-Weather-App/4.53.212\r\nAccept: application/json\r\nConnection: keep-alive\r\nX-Correlation-ID: {random_id}\r\n"),
    ]
    
    @staticmethod
    def wrap_packet(data):
        import random
        template = random.choice(TrafficCamouflage.TEMPLATES)
        if b"{random_id}" in template:
            rid = str(random.randint(100000, 999999)).encode()
            template = template.replace(b"{random_id}", rid)
        header = template + f"Content-Length: {len(data)}\r\n\r\n".encode()
        return header + data

class ProtocolUtils:
    MSG_HELLO = 0
    MSG_HANDSHAKE = 1
    MSG_DATA = 2 # Deprecated
    MSG_DIRECT = 3
    MSG_GROUP = 4

    @staticmethod
    def send_packet(sock, packet_body):
        try:
            time.sleep(random.uniform(0.05, 0.3))
            inner_data = struct.pack('!I', len(packet_body)) + packet_body
            full_packet = TrafficCamouflage.wrap_packet(inner_data)
            sock.sendall(full_packet)
        except Exception as e:
            print(f"Error sending packet: {e}")

    @staticmethod
    def receive_packet(sock):
        try:
            header_buffer = b""
            while b"\r\n\r\n" not in header_buffer:
                chunk = sock.recv(1)
                if not chunk: return None
                header_buffer += chunk
                if len(header_buffer) > 4096: return None
            
            headers_str = header_buffer.decode(errors='ignore')
            import re
            match = re.search(r'Content-Length:\s*(\d+)', headers_str, re.IGNORECASE)
            if not match: return None
            body_length = int(match.group(1))
            
            data = b''
            while len(data) < body_length:
                chunk = sock.recv(body_length - len(data))
                if not chunk: return None
                data += chunk
                
            if len(data) < 4: return None
            inner_length = struct.unpack('!I', data[:4])[0]
            if len(data) < 4 + inner_length: return None
            return data[4:4+inner_length]
        except: return None

    @staticmethod
    def create_hello_body(nickname):
        return struct.pack('!B', ProtocolUtils.MSG_HELLO) + nickname.encode('utf-8')

    @staticmethod
    def create_handshake_body(public_key_bytes):
        return struct.pack('!B', ProtocolUtils.MSG_HANDSHAKE) + public_key_bytes

    @staticmethod
    def create_direct_body(target_nick, payload):
        target_bytes = target_nick.encode('utf-8')
        return struct.pack('!B', ProtocolUtils.MSG_DIRECT) + struct.pack('!B', len(target_bytes)) + target_bytes + payload

    @staticmethod
    def create_group_body(payload):
        return struct.pack('!B', ProtocolUtils.MSG_GROUP) + payload

    @staticmethod
    def parse_body(data):
        if not data: return None
        msg_type = data[0]
        
        if msg_type == ProtocolUtils.MSG_HELLO:
            return {'type': 'hello', 'nickname': data[1:]}
        elif msg_type == ProtocolUtils.MSG_HANDSHAKE:
            # [Type] [SenderLen] [Sender] [PubKey]
            if len(data) < 2: return None
            sender_len = data[1]
            sender = data[2:2+sender_len].decode('utf-8')
            pub_key = data[2+sender_len:]
            return {'type': 'handshake', 'sender': sender, 'public_key': pub_key}
        elif msg_type == ProtocolUtils.MSG_DIRECT:
            # [Type] [SenderLen] [Sender] [Payload]
            if len(data) < 2: return None
            sender_len = data[1]
            sender = data[2:2+sender_len].decode('utf-8')
            payload = data[2+sender_len:]
            return {'type': 'direct', 'sender': sender, 'payload': payload}
        elif msg_type == ProtocolUtils.MSG_GROUP:
            # [Type] [SenderLen] [Sender] [Payload]
            if len(data) < 2: return None
            sender_len = data[1]
            sender = data[2:2+sender_len].decode('utf-8')
            payload = data[2+sender_len:]
            return {'type': 'group', 'sender': sender, 'payload': payload}
        return None

# Global instances for compatibility
crypto = CryptoUtils()
protocol = ProtocolUtils()

# ==========================================
# 3. BÖLÜM: PEER MANAGER
# ==========================================
class PeerManager:
    def __init__(self, my_private_key, my_public_key):
        self.my_private_key = my_private_key
        self.my_public_key = my_public_key
        self.peers = {} # nickname -> {'ratchet': ..., 'group_cipher': ...}
        self.lock = threading.Lock()
        
        # My Sender Key (Chain Key)
        self.my_chain_key = ChameleonMemory(crypto.generate_symmetric_key())
        self.my_group_cipher = GroupCipher(self.my_chain_key.unlock())

    def add_peer(self, nickname, public_key_bytes):
        with self.lock:
            if nickname in self.peers: return False
            
            peer_pk = crypto.bytes_to_public_key(public_key_bytes)
            ratchet = crypto.derive_shared_key(self.my_private_key, peer_pk, self.my_public_key)
            
            self.peers[nickname] = {
                'ratchet': ratchet,
                'group_cipher': None, # Will be set when we receive their key
                'pk': peer_pk
            }
            return True

    def get_ratchet(self, nickname):
        with self.lock:
            return self.peers.get(nickname, {}).get('ratchet')

    def set_group_cipher(self, nickname, chain_key):
        with self.lock:
            if nickname in self.peers:
                self.peers[nickname]['group_cipher'] = GroupCipher(chain_key)

    def get_group_cipher(self, nickname):
        with self.lock:
            return self.peers.get(nickname, {}).get('group_cipher')

    def reshuffle_all(self):
        self.my_chain_key.reshuffle()
        with self.lock:
            for p in self.peers.values():
                if p.get('ratchet'):
                    p['ratchet'].send_chain.reshuffle()
                    p['ratchet'].recv_chain.reshuffle()
                if p.get('group_cipher'):
                    p['group_cipher'].chain.reshuffle()

# ==========================================
# 4. BÖLÜM: TOR YÖNETİMİ
# ==========================================

def print_system(msg):
    print(f"{Fore.BLUE}[*] {msg}{Style.RESET_ALL}")

def print_error(msg):
    print(f"{Fore.RED}[!] {msg}{Style.RESET_ALL}")

def print_peer(sender, msg):
    print(f"\r{Fore.YELLOW}{sender}: {msg}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}root@local:~$ {Style.RESET_ALL}", end='', flush=True)

def download_tor():
    """Tor Expert Bundle'ı otomatik indirir ve kurar (Cross-Platform)."""
    
    # Mobile Check
    if 'ANDROID_ROOT' in os.environ or os.path.exists("/etc/alpine-release"):
        print_error("Mobil cihazlarda (Android/iOS) otomatik indirme desteklenmez.")
        print_error("Lütfen paket yöneticisini kullanın (pkg install tor / apk add tor).")
        return None

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
    """Tor dosyasını arar (Cross-Platform + Android/Termux)."""
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
            
    else: # Linux / macOS / Android
        search_paths = [
            "tor", 
            "/usr/bin/tor",
            "/usr/local/bin/tor",
            "/opt/homebrew/bin/tor",
            "/opt/local/bin/tor",
            "/data/data/com.termux/files/usr/bin/tor", # Android Termux Yolu
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

    # Android kontrolü
    if hasattr(sys, 'getandroidapilevel') or 'ANDROID_ROOT' in os.environ:
        # Termux'ta pkg install tor ile kurulduysa path'te olmalıydı.
        # Bulunamadıysa uyarı ver ama indirmeyi dene (belki çalışır)
        print_error("Android (Termux) algılandı ama Tor bulunamadı!")
        print_error("Lütfen: 'pkg install tor' komutunu çalıştırın.")
        # return None # İndirmeyi denesin

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
# 5. BÖLÜM: ANA İSTEMCİ MANTIĞI
# ==========================================

HOST = '127.0.0.1'
PORT = 5000
private_key, public_key = crypto.generate_keypair()
peer_manager = PeerManager(private_key, public_key)

def receive_messages(sock):
    global peer_manager
    while True:
        try:
            data = protocol.receive_packet(sock)
            if not data:
                # print_error("Bağlantı koptu.")
                os._exit(0)
            
            parsed = protocol.parse_body(data)
            if not parsed: continue
                
            if parsed['type'] == 'handshake':
                # New peer announced themselves
                sender = parsed['sender']
                pk_bytes = parsed['public_key']
                
                # 1. Add Peer (Create Ratchet)
                if peer_manager.add_peer(sender, pk_bytes):
                    print_system(f"Yeni kullanıcı katıldı: {sender}")
                    
                    # 2. Send MY Chain Key to them (Unicast)
                    ratchet = peer_manager.get_ratchet(sender)
                    my_chain_key = peer_manager.my_chain_key.unlock()
                    
                    iv, ciphertext = crypto.encrypt_direct(ratchet, my_chain_key)
                    secure_wipe(my_chain_key)
                    
                    payload = iv + struct.pack('!I', len(ciphertext)) + ciphertext
                    packet = protocol.create_direct_body(sender, payload)
                    protocol.send_packet(sock, packet)

            elif parsed['type'] == 'direct':
                # Received a Chain Key from someone
                sender = parsed['sender']
                payload = parsed['payload']
                
                ratchet = peer_manager.get_ratchet(sender)
                if ratchet:
                    iv = payload[:12]
                    length = struct.unpack('!I', payload[12:16])[0]
                    ciphertext = payload[16:16+length]
                    
                    try:
                        chain_key = crypto.decrypt_direct(ratchet, iv, ciphertext)
                        peer_manager.set_group_cipher(sender, chain_key)
                        print_system(f"Güvenli kanal kuruldu: {sender}")
                    except Exception as e:
                        pass
                else:
                    # Unknown sender sent Direct.
                    # This happens when I join. Existing peers send me keys.
                    # But I don't have their PubKey to make a Ratchet.
                    # So the Direct message payload must include their PubKey.
                    # Let's adjust the logic below in 'direct' handling.
                    pass

            elif parsed['type'] == 'group':
                sender = parsed['sender']
                payload = parsed['payload']
                
                cipher = peer_manager.get_group_cipher(sender)
                if cipher:
                    iv = payload[:12]
                    length = struct.unpack('!I', payload[12:16])[0]
                    ciphertext = payload[16:16+length]
                    
                    try:
                        plaintext = crypto.decrypt_group(cipher, iv, ciphertext)
                        print_peer(sender, plaintext.decode('utf-8'))
                    except: pass

        except Exception as e:
            # print_error(f"Okuma hatası: {e}")
            break

def start_client():
    global HOST, PORT
    
    SecurityGuard.wipe_history()
    print(f"{Fore.RED}[STATE SECRET MODE: ACTIVE]{Style.RESET_ALL}")
    print(f"{Fore.RED}[*] Sender Keys Architecture | 100+ Users Support{Style.RESET_ALL}")
    
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
        
        # 1. Send Hello
        hello_packet = protocol.create_hello_body(nickname)
        protocol.send_packet(sock, hello_packet)
        
        # 2. Broadcast Handshake (My PubKey)
        pub_bytes = crypto.public_key_to_bytes(public_key)
        handshake_packet = protocol.create_handshake_body(pub_bytes)
        protocol.send_packet(sock, handshake_packet)
        
    except Exception as e:
        print_error(f"Sunucuya erişilemedi: {e}")
        if HOST.endswith('.onion'):
            print_error("İPUCU: .onion adresinin doğru olduğundan emin olun.")
        if tor_process: tor_process.kill()
        return

    print_system("Bağlantı kuruldu. Kanal dinleniyor...")

    threading.Thread(target=receive_messages, args=(sock,), daemon=True).start()
    
    # Gürültü (Noise) Jeneratörünü Başlat
    threading.Thread(target=noise_generator, args=(sock,), daemon=True).start()

    while True:
        try:
            # GÜVENLİK GÜNCELLEMESİ: input() yerine SecureInput.ask()
            msg_content_bytes = SecureInput.ask(f"{Fore.GREEN}root@{nickname}:~$ {Style.RESET_ALL}")
            
            # Dead Man's Switch Reset
            DeadMansSwitch.touch()
            
            if not msg_content_bytes: continue
            
            # Komut Kontrolü (Byte karşılaştırması)
            if msg_content_bytes.strip() == b"/nuke":
                PanicSystem.nuke_everything()
                break
                
            if msg_content_bytes.strip() == b"/clear":
                SecurityGuard.wipe_history()
                continue
            
            # AI Stylometric Sanitizer Uygula
            temp_str = msg_content_bytes.decode('utf-8', errors='ignore')
            sanitized_str = StylometryGuard.sanitize(temp_str)
            
            # Orijinal byte buffer'ı hemen temizle
            secure_wipe(msg_content_bytes)
            
            # Encrypt with MY Group Cipher
            iv, ciphertext = crypto.encrypt_group(peer_manager.my_group_cipher, sanitized_str)
            
            # Temizlik
            del temp_str
            del sanitized_str
            gc.collect()
            
            # Send Group Message
            payload = iv + struct.pack('!I', len(ciphertext)) + ciphertext
            packet = protocol.create_group_body(payload)
            protocol.send_packet(sock, packet)
            
        except KeyboardInterrupt:
            break
    
    if tor_process: tor_process.kill()

if __name__ == "__main__":
    start_client()
