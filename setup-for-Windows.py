import subprocess
import sys

def install_svttk():
    try:
        print("🔄 جاري تثبيت مكتبة sv-ttk...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "sv-ttk"])
        print("\n✅ تم تثبيت sv-ttk بنجاح!")
    except subprocess.CalledProcessError as e:
        print("\n❌ فشل في تثبيت sv-ttk.")
        print(f"الخطأ: {e}")

if __name__ == "__main__":
    install_svttk()
