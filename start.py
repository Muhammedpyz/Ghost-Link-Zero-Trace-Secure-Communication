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
    
    choice = input("Seçiminiz (1 veya 2): ").strip()
    
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
