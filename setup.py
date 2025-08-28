import subprocess
import sys

def install_svttk():
    try:
        subprocess.check_call([
            sys.executable, "-m", "pip", "install", "sv-ttk", "--break-system-packages"
        ])
        print("\n✅ مكتبة sv-ttk تم تثبيتها بنجاح.")
    except subprocess.CalledProcessError as e:
        print("\n❌ فشل التثبيت. تأكد أنك تملك صلاحيات كافية أو أنك على Kali Linux.")
        print(f"الخطأ: {e}")

if __name__ == "__main__":
    install_svttk()

