#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import subprocess
import time

def run_command(command):
    """تنفيذ أمر في CMD"""
    try:
        result = subprocess.run(command, shell=True, check=True, 
                              capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"خطأ: {e}")
        return None

def main():
    print("=" * 50)
    print("PortScan Installer")
    print("=" * 50)
    
    # تثبيت المتطلبات
    print("📦 جاري تثبيت الحزم المطلوبة...")
    
    packages = ["sv-ttk", "tkinter"]
    
    for package in packages:
        print(f"🔧 تثبيت {package}...")
        result = run_command(f"pip install {package}")
        if result:
            print(f"✅ تم تثبيت {package} بنجاح")
        else:
            print(f"❌ فشل تثبيت {package}")
        print("-" * 30)
    
    # تشغيل الأداة
    print("🚀 تشغيل PortScan...")
    time.sleep(2)
    
    try:
        # تشغيل البرنامج الرئيسي
        import portscan
        print("✅ تم تشغيل الأداة بنجاح!")
    except ImportError as e:
        print(f"❌ خطأ في التشغيل: {e}")
        print("تأكد من وجود ملف portscan.py في نفس المجلد")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
