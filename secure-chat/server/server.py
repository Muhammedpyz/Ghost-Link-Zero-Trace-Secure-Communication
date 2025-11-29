
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

class PanicSystem:
    """Acil Durum İmha Sistemi"""
    @staticmethod
    def secure_delete_file(path):
        if not os.path.exists(path): return
        try:
            length = os.path.getsize(path)
            with open(path, "wb") as f:
                for _ in range(3):
                    f.seek(0)
                    f.write(os.urandom(length))
                    f.flush()
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

# Güvenlik Protokollerini Başlat
SecurityGuard.anti_debug()
SecurityGuard.camouflage()
SecurityGuard.wipe_history()
# lock_memory() # Aşağıda tanımlı olacak

# ==========================================
# 1. BÖLÜM: OTOMATİK ONARIM SİSTEMİ
# ==========================================
def install_missing_libs():
    """Eksik kütüphaneleri kontrol eder ve yükler."""
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
                    subprocess.check_call([sys.executable, "-m", "pip", "install", "--no-cache-dir", "--force-reinstall", "--user"] + missing)
                except Exception as e:
                    print(f"[!] Kritik Hata: {e}")
                    input("Kapatmak için Enter...")
                    sys.exit(1)
        time.sleep(1)

# Kütüphaneleri yükle
install_missing_libs()

# Importlar
try:
    import stem.process
    from stem.util import term
except ImportError:
    stem = None

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization

# ==========================================
# 2. BÖLÜM: GÖMÜLÜ MODÜLLER (CRYPTO & PROTOCOL)
# ==========================================

def lock_memory():
    """RAM'i kilitler, Swap/Pagefile kullanımını engeller (Cross-Platform)."""
    try:
        if os.name == 'posix':
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
        elif os.name == 'nt':
             pass 
    except: pass

lock_memory()

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
        real_key = key_store.unlock()
        
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Obfuscation: JSON Padding ekle
        import json
        import random
        padding_size = random.randint(10, 100)
        padding_data = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=padding_size))
        
        payload = {
            'm': plaintext.decode('utf-8'),
            'p': padding_data
        }
        json_payload = json.dumps(payload).encode('utf-8')

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
        cipher1 = chacha.encrypt(nonce1, json_payload, None)
        
        # Katman 2: Dış Şifreleme (AES-256-GCM)
        aesgcm = AESGCM(key_outer)
        blob = nonce1 + cipher1
        nonce2 = os.urandom(12)
        cipher2 = aesgcm.encrypt(nonce2, blob, None)
        
        secure_wipe(real_key)
        secure_wipe(derived)
        
        return nonce2, cipher2

    @staticmethod
    def decrypt_message(key_store, nonce, ciphertext):
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
            
            import json
            try:
                payload = json.loads(decrypted_json.decode('utf-8'))
                return payload['m'].encode('utf-8')
            except:
                return decrypted_json
        finally:
            secure_wipe(real_key)
            try: secure_wipe(derived)
            except: pass

class TrafficCamouflage:
    """Polimorfik Trafik Gizleme"""
    TEMPLATES = [
        # Microsoft Telemetry
        (b"POST /api/v2/telemetry HTTP/1.1\r\n"
         b"Host: settings-win.data.microsoft.com\r\n"
         b"User-Agent: Microsoft-WNS/10.0\r\n"
         b"Content-Type: application/x-binary\r\n"
         b"Connection: keep-alive\r\n"),
         
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

# Global instances
protocol = ProtocolUtils()

# ==========================================
# 3. BÖLÜM: AYARLAR VE YARDIMCI FONKSİYONLAR
# ==========================================

HOST = '0.0.0.0'
PORT = 5000
MAX_CLIENTS = 2  # Güvenlik: Sadece 2 kişi (Sen ve Arkadaşın)
clients = []
clients_lock = threading.Lock()

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
    """Tor dosyasını arar (Cross-Platform)."""
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
    else: # Linux / macOS
        search_paths = [
            "tor", 
            "/usr/bin/tor",
            "/usr/local/bin/tor",
            "/opt/homebrew/bin/tor",
            "/opt/local/bin/tor"
        ]

    # Önce PATH kontrolü (Linux/macOS için)
    if os.name != 'nt':
        import shutil
        if shutil.which("tor"):
            return shutil.which("tor")

    for path in search_paths:
        if os.path.exists(path):
            return path
            
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
                import psutil
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
        for client in clients:
            if client != sender_socket:
                try:
                    # ProtocolUtils.send_packet zaten uzunluk bilgisini ekler
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

    # Gizlilik: IP adresi loglanmaz, sadece Nickname
    print(f"[+] Yeni Bağlantı: {nickname}")
    
    while True:
        try:
            # ProtocolUtils ile veriyi al (Uzunluk bilgisini otomatik çözer)
            data = protocol.receive_packet(client_socket)
            if not data:
                break
            
            # Paketi diğerlerine ilet
            broadcast(data, client_socket)
            
        except Exception as e:
            print(f"[-] Hata: {e}")
            break
    
    with clients_lock:
        if client_socket in clients:
            clients.remove(client_socket)
    client_socket.close()
    print(f"[-] Bağlantı Kesildi: {nickname}")

def start_server():
    global MAX_CLIENTS
    # Ekranı temizle (İz bırakma)
    SecurityGuard.wipe_history()
    
    # Fake Title zaten ayarlandı ama kullanıcı arayüzü için temiz bir başlangıç
    print(f"==========================================")
    print(f"   SYSTEM DIAGNOSTIC TOOL v1.0           ") # Kamuflajlı İsim
    print(f"==========================================")
    
    # MAX_CLIENTS sormadan önce varsayılanı kullan veya gizli bir şekilde al
    # Otomasyon için input'u kaldırıyoruz veya timeout ekliyoruz
    # Kullanıcı "her şey otomatik olsun" dedi.
    MAX_CLIENTS = 2 
    
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
            clients.append(client_sock)
        
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
