import subprocess
import sys
import platform

def install_svttk_windows():
    print("🔍 Detected OS: Windows")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "sv-ttk"])
        print("✅ sv-ttk installed successfully on Windows.")
    except subprocess.CalledProcessError as e:
        print("❌ Failed to install sv-ttk on Windows.")
        print(e)

def install_svttk_linux():
    print("🔍 Detected OS: Linux")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "sv-ttk", "--break-system-packages"])
        print("✅ sv-ttk installed successfully on Linux (Kali).")
    except subprocess.CalledProcessError as e:
        print("❌ Failed to install sv-ttk on Linux.")
        print(e)

def main():
    os_type = platform.system()
    if os_type == "Windows":
        install_svttk_windows()
    elif os_type == "Linux":
        install_svttk_linux()
    else:
        print(f"❗ Unsupported OS: {os_type}")

if __name__ == "__main__":
    main()

