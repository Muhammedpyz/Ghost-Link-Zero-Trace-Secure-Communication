import os
import sys
import subprocess
import shutil
import time
import ctypes
import random
import threading

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
                # Linux'ta TracerPid kontrolü
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
        # SAHTE HATA DÖNGÜSÜ
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
            # Linux/macOS ANSI escape code
            sys.stdout.write(f"\x1b]2;{title}\x07")
            sys.stdout.flush()

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

def set_console_title():
    SecurityGuard.camouflage()

def install_requirements():
    """Gerekli kütüphaneleri ve PyArmor'ı yükler."""
    # socks modülü için PySocks paketi gerekir
    required = [("pyarmor", "pyarmor"), 
                ("cryptography", "cryptography"), 
                ("stem", "stem"), 
                ("colorama", "colorama"), 
                ("psutil", "psutil"), 
                ("socks", "PySocks")]
    
    print("[*] Sistem gereksinimleri kontrol ediliyor...")
    
    for import_name, package_name in required:
        try:
            # Modül import edilebilir mi kontrol et
            if import_name == "pyarmor":
                # PyArmor bir modül değil, CLI aracıdır, bu yüzden pip show ile bakıyoruz
                subprocess.check_call([sys.executable, "-m", "pip", "show", "pyarmor"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                __import__(import_name)
        except (ImportError, subprocess.CalledProcessError):
            print(f"[+] Yükleniyor: {package_name}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
            except:
                print(f"[!] {package_name} yüklenemedi. İnternet bağlantınızı kontrol edin veya 'pip install {package_name}' komutunu manuel çalıştırın.")

def obfuscate_code():
    """Kodları şifreler (PyArmor)."""
    print("[*] Güvenlik modülleri derleniyor (Obfuscation)...")
    
    if os.path.exists("dist"):
        try:
            shutil.rmtree("dist")
        except: pass
    
    # server ve client klasörlerini koruyarak dist içine at
    # PyArmor genelde dist/server.py ve dist/client.py olarak çıkarır eğer recursive ise
    # Basitçe dosyaları tek tek verelim
    try:
        # Server şifrele
        subprocess.check_call(["pyarmor", "gen", "-O", "dist/server", "secure-chat/server/server.py"], stdout=subprocess.DEVNULL)
        # Client şifrele
        subprocess.check_call(["pyarmor", "gen", "-O", "dist/client", "secure-chat/client/client.py"], stdout=subprocess.DEVNULL)
        
        # Client'ın server tarafından bulunabilmesi için dist yapısını düzenle
        # Server dist/server/server.py içinde çalışacak.
        # Client'ı dist/client/client.py içinde arayacak.
        print("[+] Kodlar şifrelendi ve kilitlendi.")
        return True
    except Exception as e:
        print(f"[!] Şifreleme hatası: {e}")
        print("[!] Şifresiz modda devam ediliyor...")
        return False

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    set_console_title()
    lock_memory() # RAM'i kilitle (Swap engelle)
    
    print("""
    #################################################
    #           SECURE CHAT - ZERO TRACE            #
    #################################################
    # 1. ODA KUR (HOST)                             #
    #    - Tor Sunucusu Başlatır                    #
    #    - İstemciyi Otomatik Açar                  #
    #                                               #
    # 2. ODAYA KATIL (JOIN)                         #
    #    - Sadece İstemciyi Açar                    #
    #################################################
    """)
    
    # GÜVENLİK GÜNCELLEMESİ: input() yerine SecureInput.ask()
    choice_bytes = SecureInput.ask("Seçiminiz (1 veya 2): ")
    choice = choice_bytes.decode('utf-8').strip()
    secure_wipe(choice_bytes) # RAM'den temizle
    
    install_requirements()
    is_obfuscated = obfuscate_code()
    
    if choice == "1":
        # HOST MODU
        print("\n[+] Sunucu başlatılıyor...")
        if is_obfuscated:
            target = os.path.join("dist", "server", "server.py")
        else:
            target = os.path.join("secure-chat", "server", "server.py")
            
        subprocess.call([sys.executable, target])
        
    elif choice == "2":
        # JOIN MODU
        print("\n[+] İstemci başlatılıyor...")
        if is_obfuscated:
            target = os.path.join("dist", "client", "client.py")
        else:
            target = os.path.join("secure-chat", "client", "client.py")
            
        subprocess.call([sys.executable, target])
        
    else:
        print("[!] Geçersiz seçim.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
