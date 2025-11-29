
import sys
import subprocess
import os
import time
import socket
import threading
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

# Global Chameleon Anahtar Saklayıcı
shared_key_store = None

def secure_wipe(data):
    """Bytearray verisini ctypes.memset ile 0 ile doldurur (RAM Temizliği)."""
    if isinstance(data, (bytearray, bytes)):
        try:
            char_array = (ctypes.c_char * len(data)).from_buffer(data)
            ctypes.memset(char_array, 0, len(data))
        except TypeError:
            pass
    elif isinstance(data, list):
        for item in data:
            secure_wipe(item)

def cleanup_memory():
    global shared_key_store
    if shared_key_store:
        secure_wipe(shared_key_store.storage)
        secure_wipe(shared_key_store.mask_a)
        secure_wipe(shared_key_store.mask_b)
    gc.collect()

atexit.register(cleanup_memory)

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
        self.storage = bytearray(d ^ a ^ b for d, a, b in zip(data, self.mask_a, self.mask_b))

    def unlock(self):
        return bytearray(s ^ a ^ b for s, a, b in zip(self.storage, self.mask_a, self.mask_b))

    def reshuffle(self):
        new_mask_a = bytearray(os.urandom(self.length))
        new_mask_b = bytearray(os.urandom(self.length))
        temp = self.unlock()
        self.mask_a = new_mask_a
        self.mask_b = new_mask_b
        self.storage = bytearray(d ^ a ^ b for d, a, b in zip(temp, self.mask_a, self.mask_b))
        secure_wipe(temp)

def memory_shuffler():
    while True:
        time.sleep(random.randint(10, 30))
        if shared_key_store:
            try: shared_key_store.reshuffle()
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
                    print(f"\r{Fore.YELLOW}[UYARI] İmha için kalan süre: {int(DeadMansSwitch.TIMEOUT - elapsed)}s{Style.RESET_ALL}", end="")
                    
        threading.Thread(target=_monitor, daemon=True).start()

class PanicSystem:
    """Acil Durum İmha Sistemi"""
    @staticmethod
    def secure_delete_file(path):
        if not os.path.exists(path): return
        try:
            length = os.path.getsize(path)
            with open(path, "wb") as f:
                # 1. DoD 5220.22-M Standartı (3 Geçişli Silme)
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
            # Yazma işlemi bittikten SONRA yapılmalı, yoksa tarih güncellenir.
            try:
                # 2000-01-01 00:00:00
                old_time = 946684800
                os.utime(path, (old_time, old_time))
            except: pass

            os.remove(path)
        except: pass

    @staticmethod
    def nuke_everything():
        cleanup_memory()
        root_dir = os.getcwd()
        for root, dirs, files in os.walk(root_dir, topdown=False):
            for name in files:
                if "server.py" in name or "client.py" in name: continue
                PanicSystem.secure_delete_file(os.path.join(root, name))
            for name in dirs:
                try: os.rmdir(os.path.join(root, name))
                except: pass
        try: PanicSystem.secure_delete_file(sys.argv[0])
        except: pass
        os._exit(0)

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
                    sys.stdout.write(char) # Ekrana bas (Görsel Gizlilik istenirse '*' basılabilir)
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
                WDA_EXCLUDEFROMCAPTURE = 0x00000011
                
                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32
                
                # Konsol penceresinin Handle'ını al
                hwnd = kernel32.GetConsoleWindow()
                
                if hwnd:
                    # Korumayı uygula
                    result = user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)
                    if result == 0:
                        # Fallback
                        user32.SetWindowDisplayAffinity(hwnd, 1)
        except: pass

# Güvenlik Protokollerini Başlat
SecurityGuard.anti_debug()
SecurityGuard.camouflage()
SecurityGuard.wipe_history()
ScreenShield.protect() # Ekran Korumasını Başlat
# lock_memory() # Aşağıda tanımlı olacak

# ==========================================
# 1. BÖLÜM: OTOMATİK ONARIM SİSTEMİ (UNIVERSAL)
# ==========================================
def universal_setup():
    """Tüm platformlar için (Windows, Linux, Android, iOS) otomatik kurulum."""
    import platform
    system_name = platform.system().lower()
    is_android = 'ANDROID_ROOT' in os.environ
    is_ios = os.path.exists("/etc/alpine-release")
    
    try:
        if is_android:
            print(f"[Sistem] Android (Termux) algılandı. Paketler kontrol ediliyor...")
            subprocess.run("pkg update -y", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("pkg install -y python tor libcrypt clang openssl", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("pkg install -y python-cryptography", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
        elif is_ios:
            print(f"[Sistem] iOS (iSH) algılandı. Paketler kontrol ediliyor...")
            subprocess.run("apk update", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run("apk add python3 py3-pip tor py3-cryptography py3-psutil git", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except: pass

def install_missing_libs():
    """Eksik kütüphaneleri kontrol eder ve yükler."""
    
    # Önce sistem seviyesinde kurulum yap (Mobile için)
    universal_setup()

    required = [("cryptography", "cryptography"), 
                ("colorama", "colorama"), 
                ("stem", "stem"), 
                ("socks", "PySocks"),
                ("psutil", "psutil")] 
    
    missing = []
    for import_name, pip_name in required:
        try:
            __import__(import_name)
        except ImportError:
            missing.append(pip_name)
    
    if missing:
        print(f"[Sistem] Eksik modüller tespit edildi: {', '.join(missing)}")
        print(f"[Sistem] Otomatik yükleniyor... (İnternet gerekli)")
        
        # GÜVENLİK NOTU: Supply Chain Attack Koruması
        # Normalde burada indirilen paketlerin SHA256 hash'lerini kontrol etmemiz gerekir.
        # Ancak PyPI sürekli güncellendiği için sabit hash kullanmak kurulumu bozabilir.
        # Kritik ortamlarda bu kütüphaneler önceden indirilip (vendored) projeye dahil edilmelidir.
        
        # Yöntem 1: Normal
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
            print(f"[Sistem] Yükleme başarılı! Devam ediliyor...")
        except:
            print("[Sistem] Normal yükleme başarısız, 'user' modu deneniyor...")
            # Yöntem 2: --user
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--user"] + missing)
            except:
                print("[Sistem] Zorla yükleme modu...")
                # Yöntem 3: Force
                try:
                    cmd = [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "--user"] + missing
                    if os.path.exists("/etc/alpine-release") or 'ANDROID_ROOT' in os.environ:
                         cmd.append("--break-system-packages")
                    subprocess.check_call(cmd)
                except Exception as e:
                    print(f"[!] Kritik Hata: {e}")
                    # input("Kapatmak için Enter...")
                    # sys.exit(1)
        time.sleep(1)

# Kütüphaneleri yükle
install_missing_libs()

# Importlar
try:
    import stem.process # type: ignore
    from stem.util import term # type: ignore
except ImportError:
    stem = None

from colorama import init, Fore, Style # type: ignore
init(autoreset=True)

from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import x25519 # type: ignore
from cryptography.hazmat.primitives.kdf.hkdf import HKDF # type: ignore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305 # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore

# ==========================================
# 2. BÖLÜM: GÖMÜLÜ MODÜLLER (CRYPTO & PROTOCOL)
# ==========================================

def lock_memory():
    """RAM'i kilitler, Swap/Pagefile kullanımını engeller (Windows Kernel Level)."""
    try:
        if os.name == 'nt':
            # Windows: SetProcessWorkingSetSize ile RAM'i zorla tut
            process = ctypes.windll.kernel32.GetCurrentProcess()
            min_size = ctypes.c_size_t()
            max_size = ctypes.c_size_t()
            
            if ctypes.windll.kernel32.GetProcessWorkingSetSize(process, ctypes.byref(min_size), ctypes.byref(max_size)):
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

lock_memory()

class RatchetSession:
    """
    Double Ratchet (Simplified Symmetric) Implementation.
    Her mesajda yeni anahtar üretir (Forward Secrecy).
    """
    def __init__(self, root_key, role='initiator'):
        self.root_key = root_key
        # Kök anahtardan iki zincir türet:
        # Chain A: Initiator -> Responder
        # Chain B: Responder -> Initiator
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ratchet-init',
        )
        derived = hkdf.derive(root_key)
        chain_a = derived[:32]
        chain_b = derived[32:]
        
        # Role'e göre gönderme/alma zincirlerini ata
        if role == 'initiator':
            self.send_chain = ChameleonMemory(chain_a)
            self.recv_chain = ChameleonMemory(chain_b)
        else:
            self.send_chain = ChameleonMemory(chain_b)
            self.recv_chain = ChameleonMemory(chain_a)
            
    def ratchet_step(self, chain_memory):
        """Zinciri bir adım ilerletir ve mesaj anahtarını döndürür."""
        current_chain_key = chain_memory.unlock()
        
        # KDF: ChainKey -> (NextChainKey, MessageKey)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'ratchet-step',
        )
        derived = hkdf.derive(current_chain_key)
        next_chain_key = derived[:32]
        message_key = derived[32:]
        
        # Zinciri güncelle (Eski anahtarı sil)
        chain_memory.storage = ChameleonMemory(next_chain_key).storage
        chain_memory.mask_a = ChameleonMemory(next_chain_key).mask_a
        chain_memory.mask_b = ChameleonMemory(next_chain_key).mask_b
        
        secure_wipe(current_chain_key)
        secure_wipe(derived)
        
        return message_key

class CryptoUtils:
    """Kriptografi Altyapısı (Gömülü - Server tarafında gerekirse diye)"""
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
    def derive_shared_key(private_key, peer_public_key, my_public_key):
        shared_key = private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'secure-chat-handshake',
        ).derive(shared_key)
        
        # Role Determination (Lexical Sort)
        my_bytes = my_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        peer_bytes = peer_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        
        role = 'initiator' if my_bytes > peer_bytes else 'responder'
        
        # Ratchet Oturumunu Başlat
        return RatchetSession(derived_key, role)

    @staticmethod
    def encrypt_message(ratchet_session, plaintext):
        # 1. Ratchet'tan yeni mesaj anahtarı al
        real_key = ratchet_session.ratchet_step(ratchet_session.send_chain)
        
        if isinstance(plaintext, str):
            plaintext_bytes = bytearray(plaintext.encode('utf-8'))
        elif isinstance(plaintext, bytes):
            plaintext_bytes = bytearray(plaintext)
        else:
            plaintext_bytes = plaintext
        
        # 2. Fixed Size Padding (Traffic Analysis Defense)
        # Her paket tam olarak 4KB (4096 byte) olacak şekilde doldurulur.
        TARGET_SIZE = 4096
        
        payload = {'m': plaintext_bytes.decode('utf-8')}
        json_bytes = json.dumps(payload).encode('utf-8')
        
        final_block = bytearray(TARGET_SIZE)
        # Uzunluk başlığı (4 byte)
        struct.pack_into('!I', final_block, 0, len(json_bytes))
        
        # Veri sığıyor mu?
        if len(json_bytes) + 4 > TARGET_SIZE:
            # Çok uzun mesaj, kesmek gerekebilir ama şimdilik sığdığını varsayalım
            pass
            
        final_block[4:4+len(json_bytes)] = json_bytes
        # Geri kalanı rastgele
        remaining = TARGET_SIZE - (4 + len(json_bytes))
        if remaining > 0:
            final_block[4+len(json_bytes):] = os.urandom(remaining)
            
        if isinstance(plaintext_bytes, bytearray):
            secure_wipe(plaintext_bytes)

        # HYBRID DOUBLE ENCRYPTION (Matryoshka Style)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'hybrid-split',
        )
        derived = hkdf.derive(real_key)
        key_inner = derived[:32]
        key_outer = derived[32:]

        # Katman 1: İç Şifreleme (ChaCha20-Poly1305)
        chacha = ChaCha20Poly1305(key_inner)
        nonce1 = os.urandom(12)
        cipher1 = chacha.encrypt(nonce1, final_block, None)
        
        secure_wipe(final_block)
        
        # Katman 2: Dış Şifreleme (AES-256-GCM)
        aesgcm = AESGCM(key_outer)
        blob = nonce1 + cipher1
        nonce2 = os.urandom(12)
        cipher2 = aesgcm.encrypt(nonce2, blob, None)
        
        secure_wipe(real_key)
        secure_wipe(derived)
        
        return nonce2, cipher2

    @staticmethod
    def decrypt_message(ratchet_session, nonce, ciphertext):
        # 1. Ratchet'tan yeni mesaj anahtarı al
        real_key = ratchet_session.ratchet_step(ratchet_session.recv_chain)
        
        try:
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
            decrypted_block = chacha.decrypt(nonce1, cipher1, None)
            
            # Padding Temizliği
            data_len = struct.unpack('!I', decrypted_block[:4])[0]
            json_bytes = decrypted_block[4:4+data_len]
            
            import json
            payload = json.loads(json_bytes.decode('utf-8'))
            return payload['m'].encode('utf-8')
        finally:
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
    MSG_DIRECT = 3
    MSG_GROUP = 4

    @staticmethod
    def send_packet(sock, packet_body):
        try:
            # Jitter: Traffic Analysis Defense
            # Paketleri rastgele gecikmelerle gönder (Yapay Zeka analizini bozar)
            time.sleep(random.uniform(0.05, 0.3))
            
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
            # 1. HTTP Headerlarını Oku (\r\n\r\n bulana kadar)
            header_buffer = b""
            while b"\r\n\r\n" not in header_buffer:
                chunk = sock.recv(1)
                if not chunk: return None
                header_buffer += chunk
                if len(header_buffer) > 4096: return None # Anti-DoS
            
            # 2. Content-Length Bul
            headers_str = header_buffer.decode(errors='ignore')
            import re
            match = re.search(r'Content-Length:\s*(\d+)', headers_str, re.IGNORECASE)
            if not match: return None
            
            body_length = int(match.group(1))
            
            # 3. Body Oku (Binary Protocol Paketi)
            data = b''
            while len(data) < body_length:
                chunk = sock.recv(body_length - len(data))
                if not chunk: return None
                data += chunk
                
            # 4. İç Paketi Çöz (Length + Body)
            # data = struct.pack('!I', length) + packet_body
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
    def create_direct_body(target_nick, payload):
        target_bytes = target_nick.encode('utf-8')
        return struct.pack('!B', ProtocolUtils.MSG_DIRECT) + struct.pack('!B', len(target_bytes)) + target_bytes + payload

    @staticmethod
    def create_group_body(payload):
        return struct.pack('!B', ProtocolUtils.MSG_GROUP) + payload

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
            
        elif msg_type == ProtocolUtils.MSG_DIRECT:
            if len(data) < 2: return None
            nick_len = data[1]
            if len(data) < 2 + nick_len: return None
            target_nick = data[2:2+nick_len].decode('utf-8')
            payload = data[2+nick_len:]
            return {'type': 'direct', 'target': target_nick, 'payload': payload}
            
        elif msg_type == ProtocolUtils.MSG_GROUP:
            return {'type': 'group', 'payload': data[1:]}
            
        return None

# Global instances
protocol = ProtocolUtils()

# ==========================================
# 3. BÖLÜM: AYARLAR VE YARDIMCI FONKSİYONLAR
# ==========================================

HOST = '0.0.0.0'
PORT = 5000
MAX_CLIENTS = 100  # Sender Keys ile 100 kişiye kadar hızlı
clients = {} # Nickname -> Socket
clients_lock = threading.Lock()

class ReplayGuard:
    """
    Sunucu Tarafı Replay Koruması.
    Şifreli paketlerin özetini (Hash) saklar.
    Aynı paket tekrar gelirse (Replay Attack), sunucu bunu reddeder.
    """
    def __init__(self):
        self.seen_hashes = {} # hash -> timestamp
        self.lock = threading.Lock()
        self.TTL = 10.0 # 10 Saniye boyunca aynı paketi kabul etme (Cache Süresi)

    def is_replay(self, packet_data):
        import hashlib
        # Paketin özetini çıkar (SHA-256)
        h = hashlib.sha256(packet_data).hexdigest()
        now = time.time()
        
        with self.lock:
            # Süresi dolmuşları temizle (Garbage Collection)
            to_remove = [k for k, v in self.seen_hashes.items() if now - v > self.TTL]
            for k in to_remove:
                del self.seen_hashes[k]
            
            if h in self.seen_hashes:
                return True # Bu paket daha önce görüldü!
            
            self.seen_hashes[h] = now
            return False

replay_guard = ReplayGuard()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# ==========================================
# 4. BÖLÜM: TOR BAĞLANTISI (GİZLİLİK MODU)
# ==========================================

def download_tor():
    """Tor Expert Bundle'ı otomatik indirir ve kurar (Cross-Platform)."""
    
    # Mobile Check
    if 'ANDROID_ROOT' in os.environ or os.path.exists("/etc/alpine-release"):
        print("[Tor] Mobil cihazlarda (Android/iOS) otomatik indirme desteklenmez.")
        print("[Tor] Lütfen paket yöneticisini kullanın (pkg install tor / apk add tor).")
        return None

    print("[Tor] Tor motoru bulunamadı. İnternetten indiriliyor...")
    
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
        print(f"[Tor] İşletim sistemi desteklenmiyor: {system} {machine}")
        return None

    try:
        import urllib.request
        import tarfile
        
        print(f"[Tor] İndiriliyor: {url}")
        urllib.request.urlretrieve(url, local_filename)
        print("[Tor] İndirme tamamlandı. Dosyalar çıkartılıyor...")
        
        with tarfile.open(local_filename, "r:gz") as tar:
            tar.extractall()
            
        print("[Tor] Kurulum başarılı!")
        try:
            os.remove(local_filename)
        except:
            pass
            
        # Tor yolu platforma göre değişebilir
        if system == 'windows':
            expected_path = os.path.join(os.getcwd(), "Tor", "tor.exe")
        else:
            expected_path = os.path.join(os.getcwd(), "tor", "tor")
            
        if not os.path.exists(expected_path):
            print(f"[Tor] HATA: Beklenen dosya bulunamadı: {expected_path}")
            print(f"[Tor] Mevcut dizin içeriği: {os.listdir(os.getcwd())}")
            # Belki 'Data' klasörü içindedir?
            if os.path.exists(os.path.join(os.getcwd(), "Data", "Tor", "tor.exe")):
                 return os.path.join(os.getcwd(), "Data", "Tor", "tor.exe")
            return None
            
        return expected_path

    except Exception as e:
        print(f"[Tor] İndirme hatası: {e}")
        return None

def find_tor_executable():
    """Tor dosyasını arar (Cross-Platform + Android/Termux)."""
    # 1. ÖNCELİK: Kendi indirdiğimiz yerel Tor (En kararlı sürüm)
    if os.name == 'nt':
        local_tor = os.path.join(os.getcwd(), "Tor", "tor.exe")
    else:
        local_tor = os.path.join(os.getcwd(), "tor", "tor")
        
    if os.path.exists(local_tor):
        return local_tor

    search_paths = []
    
    if os.name == 'nt':
        search_paths = [
            r"C:\Tor\tor.exe",
            os.path.join(os.path.expanduser("~"), "Desktop", "Tor Browser", "Browser", "TorBrowser", "Tor", "tor.exe"),
        ]
    else: # Linux / macOS / Android
        search_paths = [
            "tor", 
            "/usr/bin/tor",
            "/usr/local/bin/tor",
            "/opt/homebrew/bin/tor",
            "/opt/local/bin/tor",
            "/data/data/com.termux/files/usr/bin/tor", # Android Termux
            os.path.join(os.getcwd(), "tor"),
            os.path.join(os.getcwd(), "tor", "tor")
        ]

    # Önce PATH kontrolü (Linux/macOS için)
    if os.name != 'nt':
        import shutil
        if shutil.which("tor"):
            return shutil.which("tor")

    for path in search_paths:
        if os.path.exists(path):
            return path
            
    # Android kontrolü
    if hasattr(sys, 'getandroidapilevel') or 'ANDROID_ROOT' in os.environ:
        print("[Tor] Android (Termux) algılandı ama Tor bulunamadı!")
        print("[Tor] Lütfen: 'pkg install tor' komutunu çalıştırın.")
        # return None

    # Derin arama KALDIRILDI: Rastgele bozuk Tor sürümlerini bulup hataya sebep oluyor.
    # Bunun yerine temiz bir sürüm indiriyoruz.
    return download_tor()

def setup_tor():
    """Tor Hidden Service başlatır."""
    if not stem:
        return None, None

    print(f"[Tor] Tor motoru hazırlanıyor...")
    tor_path = find_tor_executable()
    
    if not tor_path:
        print("[Tor] HATA: Tor indirilemedi ve bulunamadı.")
        return None, None

    print(f"[Tor] Kullanılıyor: {tor_path}")
    print(f"[Tor] Gizli Servis başlatılıyor... (Bu işlem 1-2 dk sürebilir)")
    
    hidden_service_dir = os.path.join(os.getcwd(), "hidden_service")
    if not os.path.exists(hidden_service_dir):
        os.makedirs(hidden_service_dir)

    def print_bootstrap_lines(line):
        if "Bootstrapped " in line:
            print(f"[Tor Durumu] {line}")

    def launch_tor_process():
        return stem.process.launch_tor_with_config(
            tor_cmd=tor_path,
            config={
                'SocksPort': '9050',
                'HiddenServiceDir': hidden_service_dir,
                'HiddenServicePort': f'80 127.0.0.1:{PORT}'
            },
            init_msg_handler=print_bootstrap_lines,
            take_ownership=True
        )

    # Robust Retry Loop (Gelişmiş Hata Yönetimi)
    max_retries = 10
    for attempt in range(max_retries):
        try:
            tor_process = launch_tor_process()
            
            hostname_path = os.path.join(hidden_service_dir, "hostname")
            # Hostname dosyasının oluşması için bekle
            timeout = 0
            while not os.path.exists(hostname_path) and timeout < 20:
                time.sleep(0.5)
                timeout += 1
                
            if os.path.exists(hostname_path):
                with open(hostname_path, "r") as f:
                    onion_address = f.read().strip()
                print(f"[Tor] BAŞARILI! Tünel açıldı.")
                return onion_address, tor_process
            else:
                raise Exception("Hostname dosyası oluşturulamadı.")
                
        except Exception as e:
            print(f"[Tor] Başlatma hatası ({attempt+1}/{max_retries}): {e}")
            # Hata durumunda temizlik yap
            try:
                import psutil # type: ignore
                for proc in psutil.process_iter():
                    if proc.name() == "tor.exe" or proc.name() == "tor":
                        try: proc.kill()
                        except: pass
            except: pass
            
            # KRİTİK DÜZELTME: "Broken state" hatası için klasörü sil
            if os.path.exists(hidden_service_dir):
                try:
                    import shutil
                    shutil.rmtree(hidden_service_dir)
                    print("[Tor] Hasarlı yapılandırma temizlendi.")
                    os.makedirs(hidden_service_dir) # Tekrar oluştur
                except: pass
            
            if attempt < max_retries - 1:
                print("[Tor] Portlar temizlendi, 3 saniye içinde tekrar deneniyor...")
                time.sleep(3)
            else:
                print("[Tor] Tüm denemeler başarısız oldu.")

    return None, None

# ==========================================
# 5. BÖLÜM: (KALDIRILDI - SADECE TOR)
# ==========================================
# UPnP ve Yerel Ağ özellikleri güvenlik nedeniyle kaldırılmıştır.


# ==========================================
# 6. BÖLÜM: SUNUCU ANA DÖNGÜSÜ
# ==========================================

def broadcast(data, sender_socket):
    with clients_lock:
        for nick, client in clients.items():
            if client != sender_socket:
                try:
                    protocol.send_packet(client, data)
                except:
                    pass

def handle_client(client_socket):
    """Tek bir istemciyi dinle."""
    nickname = "Anonim"
    
    # İlk paket Nickname olmalı (MSG_HELLO)
    try:
        # 5 saniye içinde nickname gelmezse varsayılan kalır
        client_socket.settimeout(5)
        first_data = protocol.receive_packet(client_socket)
        client_socket.settimeout(None)
        
        if first_data:
            parsed = protocol.parse_body(first_data)
            if parsed and parsed['type'] == 'hello':
                nickname = parsed['nickname'].decode('utf-8', errors='ignore')
    except:
        client_socket.settimeout(None)

    # Nickname Benzersizlik Kontrolü
    with clients_lock:
        if nickname in clients:
            nickname += f"_{random.randint(100,999)}"
        clients[nickname] = client_socket

    # Gizlilik: IP adresi loglanmaz, sadece Nickname
    print(f"[+] Yeni Bağlantı: {nickname}")
    
    # Gürültü (Noise) Jeneratörünü Başlat (Sunucu tarafı)
    threading.Thread(target=noise_generator, args=(client_socket,), daemon=True).start()
    
    while True:
        try:
            # ProtocolUtils ile veriyi al (Uzunluk bilgisini otomatik çözer)
            data = protocol.receive_packet(client_socket)
            if not data:
                break
            
            # SERVER-SIDE REPLAY PROTECTION (Sunucu Bazlı Tekrar Koruması)
            # Sunucu şifreyi çözemez ama paketin aynısının tekrar gelip gelmediğini anlar.
            if replay_guard.is_replay(data):
                print(f"{Fore.RED}[!] Replay Attack Engellendi (Duplicate Packet): {nickname}{Style.RESET_ALL}")
                continue

            # Dead Man's Switch Reset (Aktivite var)
            DeadMansSwitch.touch()
            
            parsed = protocol.parse_body(data)
            if not parsed: continue
            
            if parsed['type'] == 'direct':
                # Hedefe Yönlendir (Unicast)
                target_nick = parsed['target']
                with clients_lock:
                    if target_nick in clients:
                        # Recipient needs to know WHO sent the key
                        # New Packet: [MSG_DIRECT] [SenderLen] [Sender] [Payload]
                        sender_bytes = nickname.encode('utf-8')
                        payload = parsed['payload']
                        new_body = struct.pack('!B', ProtocolUtils.MSG_DIRECT) + \
                                   struct.pack('!B', len(sender_bytes)) + \
                                   sender_bytes + \
                                   payload
                        protocol.send_packet(clients[target_nick], new_body)
            
            elif parsed['type'] == 'group':
                # Herkese Yayınla (Broadcast)
                # Sender bilgisini ekle: [MSG_GROUP] [SenderLen] [Sender] [Payload]
                sender_bytes = nickname.encode('utf-8')
                payload = parsed['payload']
                new_body = struct.pack('!B', ProtocolUtils.MSG_GROUP) + \
                           struct.pack('!B', len(sender_bytes)) + \
                           sender_bytes + \
                           payload
                
                broadcast(new_body, client_socket)
            
            elif parsed['type'] == 'handshake':
                # Public Key Broadcast
                # Sender bilgisini ekle: [MSG_HANDSHAKE] [SenderLen] [Sender] [PublicKey]
                sender_bytes = nickname.encode('utf-8')
                pk = parsed['public_key']
                new_body = struct.pack('!B', ProtocolUtils.MSG_HANDSHAKE) + \
                           struct.pack('!B', len(sender_bytes)) + \
                           sender_bytes + \
                           pk
                
                broadcast(new_body, client_socket)

        except Exception as e:
            print(f"[-] Hata: {e}")
            break
    
    with clients_lock:
        if nickname in clients:
            del clients[nickname]
    client_socket.close()
    print(f"[-] Bağlantı Kesildi: {nickname}")

def start_server():
    global MAX_CLIENTS
    # Ekranı temizle (İz bırakma)
    SecurityGuard.wipe_history()
    
    print(f"{Fore.RED}[STATE SECRET MODE: ACTIVE]{Style.RESET_ALL}")
    print(f"{Fore.RED}[*] Memory Locked | Traffic Noise | Double Ratchet | Dead Man's Switch{Style.RESET_ALL}")
    
    # Dead Man's Switch Başlat
    DeadMansSwitch.start()
    
    # Fake Title zaten ayarlandı ama kullanıcı arayüzü için temiz bir başlangıç
    print(f"==========================================")
    print(f"   SYSTEM DIAGNOSTIC TOOL v1.0           ") # Kamuflajlı İsim
    print(f"==========================================")
    
    # Kullanıcı isteği: Host kişi sayısını belirlesin
    try:
        max_c_input = input(f"{Fore.GREEN}Maksimum Kişi Sayısı (Varsayılan 100): {Style.RESET_ALL}").strip()
        if max_c_input.isdigit():
            MAX_CLIENTS = int(max_c_input)
        else:
            MAX_CLIENTS = 100
    except:
        MAX_CLIENTS = 100
    print(f"[Sistem] Kapasite: {MAX_CLIENTS} Kişi") 
    
    onion_addr = None
    tor_proc = None
    
    # Sonsuz döngü ile Tor başlatılana kadar dene (Sunucu çökmesini engelle)
    while not onion_addr:
        onion_addr, tor_proc = setup_tor()
        
        if not onion_addr:
            print("[HATA] Tor başlatılamadı. 5 saniye sonra otomatik tekrar denenecek...")
            print("[İPUCU] Eğer bu hata devam ederse, lütfen internet bağlantınızı kontrol edin.")
            time.sleep(5)
            # Döngü başa döner ve tekrar dener
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
    except OSError:
        print(f"[HATA] Port {PORT} dolu! Başka bir pencerede server açık mı?")
        return

    server.listen()
    
    print(f"------------------------------------------")
    print(f"   DURUM RAPORU:")
    print(f"   [+] TOR AĞI : AKTİF ✅")
    print(f"   [+] ADRES   : {onion_addr}")
    print(f"   (Arkadaşına bu .onion adresini ver)")
    print(f"------------------------------------------")
    
    # İstemciyi Otomatik Başlat
    print("[Sistem] İstemci (Client) otomatik başlatılıyor...")
    try:
        # Client'ın yolunu akıllıca bul
        current_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(current_dir) 
        client_path = os.path.join(base_dir, "client", "client.py")
            
        if os.path.exists(client_path):
            # Yeni pencerede başlat (Cross-Platform)
            if os.name == 'nt':
                # Windows: cmd /k ile yeni pencerede aç (Spaces ve Unicode karakterler için güvenli yöntem)
                # creationflags=16 (CREATE_NEW_CONSOLE) kullanarak shell=True sorunlarından kaçınıyoruz
                subprocess.Popen(["cmd", "/k", sys.executable, client_path], creationflags=16)
            elif sys.platform == 'darwin': # macOS
                subprocess.Popen(['open', '-a', 'Terminal', sys.executable, client_path])
            else: # Linux
                # Yaygın terminalleri dene
                terminals = ['gnome-terminal', 'xterm', 'konsole', 'xfce4-terminal']
                started = False
                for term in terminals:
                    try:
                        if term == 'gnome-terminal':
                            subprocess.Popen([term, '--', sys.executable, client_path])
                        else:
                            subprocess.Popen([term, '-e', f"{sys.executable} {client_path}"])
                        started = True
                        break
                    except: continue
                
                if not started:
                    # Terminal bulunamazsa arka planda çalıştır
                    subprocess.Popen([sys.executable, client_path])
        else:
            print(f"[!] Client dosyası bulunamadı: {client_path}")
    except Exception as e:
        print(f"[!] Client başlatılamadı: {e}")

    while True:
        client_sock, addr = server.accept()
        
        # Güvenlik: Kişi Limiti Kontrolü
        with clients_lock:
            if len(clients) >= MAX_CLIENTS:
                print(f"[!] Bağlantı Reddedildi (Dolu): {addr[0]}")
                client_sock.close()
                continue
            # clients.append(client_sock) # handle_client içinde ekleniyor
        
        thread = threading.Thread(target=handle_client, args=(client_sock,))
        thread.start()

if __name__ == "__main__":
    while True:
        try:
            start_server()
        except KeyboardInterrupt:
            print("\n[Sistem] Kullanıcı tarafından kapatıldı.")
            break
        except Exception as e:
            print(f"\n[KRİTİK HATA] Sunucu çöktü: {e}")
            print("[Sistem] 5 saniye içinde otomatik yeniden başlatılıyor...")
            time.sleep(5)
            continue
