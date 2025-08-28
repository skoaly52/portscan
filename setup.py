import subprocess
import sys
import platform

def install_svttk_windows():
    print("🔍 اكتشف النظام: Windows")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "sv-ttk"])
        print("✅ تم تثبيت sv-ttk بنجاح على Windows.")
    except subprocess.CalledProcessError as e:
        print("❌ فشل التثبيت على Windows.")
        print(e)

def install_svttk_linux():
    print("🔍 اكتشف النظام: Linux")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "sv-ttk", "--break-system-packages"])
        print("✅ تم تثبيت sv-ttk بنجاح على Kali/Linux.")
    except subprocess.CalledProcessError as e:
        print("❌ فشل التثبيت على Linux.")
        print(e)

def main():
    os_type = platform.system()
    if os_type == "Windows":
        install_svttk_windows()
    elif os_type == "Linux":
        install_svttk_linux()
    else:
        print(f"❗ النظام غير مدعوم: {os_type}")

if __name__ == "__main__":
    main()

