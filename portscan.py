#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import time
import random
import csv
import json
import ipaddress
import subprocess
import sys
import os
import platform
from collections import OrderedDict

# محاولة استيراد المكتبات الاختيارية
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from scapy.all import ARP, Ether, srp, ICMP, IP, TCP, conf
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# تحديد نظام التشغيل
IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"

# محاولة استيراد سمة التصميم الحديثة (إن وجدت)
try:
    import sv_ttk
    THEME_AVAILABLE = True
except ImportError:
    THEME_AVAILABLE = False

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner Pro - Ultimate Edition")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)
        
        # تعيين سمة التصميم إذا كانت متاحة
        if THEME_AVAILABLE:
            sv_ttk.set_theme("dark")
        
        # تكوين الأنماط
        self.style = ttk.Style()
        self.style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'))
        self.style.configure('Subtitle.TLabel', font=('Segoe UI', 11))
        self.style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))
        self.style.configure('Critical.TLabel', foreground='#ff4444')
        self.style.configure('Warning.TLabel', foreground='#ffbb33')
        self.style.configure('Success.TLabel', foreground='#00C851')
        
        # المتغيرات
        self.scanning = False
        self.stop_scan = False
        self.open_ports = []
        self.scan_history = []
        self.host_info = {}
        self.vulnerability_db = self.load_vulnerability_db()
        self.common_ports_list = self.load_common_ports()
        
        # معلومات الشبكة
        self.local_ip = self.get_local_ip()
        self.public_ip = self.get_public_ip()
        
        self.setup_ui()
        
    def setup_ui(self):
        # إنشاء دفتر (تبويبات)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # تبويب المسح الرئيسي
        self.scan_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.scan_frame, text='Port Scanner')
        
        # تبويب أدوات الشبكة
        self.tools_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.tools_frame, text='Network Tools')
        
        # تبويب سجل النتائج
        self.history_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.history_frame, text='Scan History')
        
        # تبويب الإعدادات
        self.settings_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.settings_frame, text='Settings')
        
        # إعداد كل تبويب
        self.setup_scan_tab()
        self.setup_tools_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
        
    def setup_scan_tab(self):
        # الحاوية الرئيسية
        main_container = ttk.Frame(self.scan_frame)
        main_container.pack(fill='both', expand=True)
        
        # رأس الصفحة
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(header_frame, text="🚀 Port Scanner Pro - Ultimate Edition", style='Header.TLabel').pack(side='left')
        
        # لوحة المعلومات السريعة
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side='right')
        
        ttk.Label(info_frame, text=f"Local IP: {self.local_ip}", 
                 style='Subtitle.TLabel').pack(side='top', anchor='e')
        ttk.Label(info_frame, text=f"Public IP: {self.public_ip}", 
                 style='Subtitle.TLabel').pack(side='top', anchor='e')
        ttk.Label(info_frame, text=f"Hostname: {socket.gethostname()}", 
                 style='Subtitle.TLabel').pack(side='top', anchor='e')
        ttk.Label(info_frame, text=f"OS: {platform.system()} {platform.release()}", 
                 style='Subtitle.TLabel').pack(side='top', anchor='e')
        
        # منطقة المحتوى
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill='both', expand=True)
        
        # اللوحة اليسرى - عناصر التحكم
        control_frame = ttk.LabelFrame(content_frame, text="Scan Configuration", padding=15)
        control_frame.pack(side='left', fill='y', padx=(0, 10))
        
        # إدخال الهدف مع خيارات متقدمة
        ttk.Label(control_frame, text="Target", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        target_input_frame = ttk.Frame(control_frame)
        target_input_frame.grid(row=1, column=0, sticky='we', pady=(0, 15))
        
        self.target_var = tk.StringVar(value="127.0.0.1")
        target_entry = ttk.Entry(target_input_frame, textvariable=self.target_var, width=25, font=('Segoe UI', 10))
        target_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Button(target_input_frame, text="Discover", command=self.discover_hosts, width=8).pack(side='right', padx=(5, 0))
        
        # نوع المسح
        ttk.Label(control_frame, text="Scan Type", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky='w', pady=(0, 5))
        
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        scan_types = ["TCP Connect", "SYN Stealth", "UDP", "FIN", "XMAS", "NULL", "ACK", "Window", "Maimon"]
        scan_type_combo = ttk.Combobox(control_frame, textvariable=self.scan_type_var, values=scan_types, state="readonly")
        scan_type_combo.grid(row=3, column=0, sticky='we', pady=(0, 15))
        
        # اختيار المنافذ
        port_selection_frame = ttk.LabelFrame(control_frame, text="Port Selection", padding=10)
        port_selection_frame.grid(row=4, column=0, sticky='we', pady=(0, 15))
        
        self.port_selection_var = tk.StringVar(value="Range")
        ttk.Radiobutton(port_selection_frame, text="Range", variable=self.port_selection_var, value="Range").grid(row=0, column=0, sticky='w')
        ttk.Radiobutton(port_selection_frame, text="Common Ports", variable=self.port_selection_var, value="Common").grid(row=0, column=1, sticky='w')
        ttk.Radiobutton(port_selection_frame, text="Custom List", variable=self.port_selection_var, value="Custom").grid(row=0, column=2, sticky='w')
        
        # نطاق المنافذ
        port_range_frame = ttk.Frame(port_selection_frame)
        port_range_frame.grid(row=1, column=0, columnspan=3, sticky='we', pady=(5, 0))
        
        self.start_port_var = tk.StringVar(value="1")
        start_port_entry = ttk.Entry(port_range_frame, textvariable=self.start_port_var, width=8, font=('Segoe UI', 9))
        start_port_entry.pack(side='left')
        
        ttk.Label(port_range_frame, text="—").pack(side='left', padx=5)
        
        self.end_port_var = tk.StringVar(value="1024")
        end_port_entry = ttk.Entry(port_range_frame, textvariable=self.end_port_var, width=8, font=('Segoe UI', 9))
        end_port_entry.pack(side='left')
        
        # منافذ مخصصة
        self.custom_ports_var = tk.StringVar(value="80,443,22,21,23,25,53,110,135,137,139,143,445,993,995,1723,3306,3389,5900,8080")
        custom_ports_entry = ttk.Entry(port_selection_frame, textvariable=self.custom_ports_var, font=('Segoe UI', 9))
        custom_ports_entry.grid(row=2, column=0, columnspan=3, sticky='we', pady=(5, 0))
        
        # الإعدادات المتقدمة
        advanced_frame = ttk.LabelFrame(control_frame, text="Advanced Settings", padding=10)
        advanced_frame.grid(row=5, column=0, sticky='we', pady=(0, 15))
        
        ttk.Label(advanced_frame, text="Timeout (s):", font=('Segoe UI', 9)).grid(row=0, column=0, sticky='w')
        self.timeout_var = tk.StringVar(value="0.5")
        timeout_entry = ttk.Entry(advanced_frame, textvariable=self.timeout_var, width=8, font=('Segoe UI', 9))
        timeout_entry.grid(row=0, column=1, padx=(5, 15), sticky='w')
        
        ttk.Label(advanced_frame, text="Threads:", font=('Segoe UI', 9)).grid(row=0, column=2, sticky='w')
        self.threads_var = tk.StringVar(value="100")
        threads_entry = ttk.Entry(advanced_frame, textvariable=self.threads_var, width=8, font=('Segoe UI', 9))
        threads_entry.grid(row=0, column=3, sticky='w')
        
        ttk.Label(advanced_frame, text="Delay (ms):", font=('Segoe UI', 9)).grid(row=1, column=0, sticky='w', pady=(5, 0))
        self.delay_var = tk.StringVar(value="0")
        delay_entry = ttk.Entry(advanced_frame, textvariable=self.delay_var, width=8, font=('Segoe UI', 9))
        delay_entry.grid(row=1, column=1, padx=(5, 15), pady=(5, 0), sticky='w')
        
        ttk.Label(advanced_frame, text="Retries:", font=('Segoe UI', 9)).grid(row=1, column=2, sticky='w', pady=(5, 0))
        self.retries_var = tk.StringVar(value="1")
        retries_entry = ttk.Entry(advanced_frame, textvariable=self.retries_var, width=8, font=('Segoe UI', 9))
        retries_entry.grid(row=1, column=3, pady=(5, 0), sticky='w')
        
        # الخيارات
        options_frame = ttk.Frame(control_frame)
        options_frame.grid(row=6, column=0, sticky='we', pady=(0, 20))
        
        self.verbose_var = tk.BooleanVar(value=False)
        verbose_cb = ttk.Checkbutton(options_frame, text="Show closed ports", variable=self.verbose_var)
        verbose_cb.pack(side='left')
        
        self.service_detection_var = tk.BooleanVar(value=True)
        service_cb = ttk.Checkbutton(options_frame, text="Service detection", variable=self.service_detection_var)
        service_cb.pack(side='left', padx=(10, 0))
        
        self.os_detection_var = tk.BooleanVar(value=False)
        os_cb = ttk.Checkbutton(options_frame, text="OS detection", variable=self.os_detection_var)
        os_cb.pack(side='left', padx=(10, 0))
        
        # أزرار التنفيذ
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=7, column=0, sticky='we')
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.toggle_scan, style='Accent.TButton')
        self.scan_button.pack(side='left', padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side='left')
        
        ttk.Button(button_frame, text="Save Results", command=self.save_results).pack(side='right')
        
        # اللوحة اليمنى - النتائج
        results_frame = ttk.LabelFrame(content_frame, text="Scan Results", padding=10)
        results_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        # إنشاء دفتر للتبويبات داخل نتائج المسح
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill='both', expand=True)
        
        # تبويب نتائج المنافذ
        port_results_frame = ttk.Frame(results_notebook, padding=5)
        results_notebook.add(port_results_frame, text='Ports')
        
        # تبويب معلومات المضيف
        host_info_frame = ttk.Frame(results_notebook, padding=5)
        results_notebook.add(host_info_frame, text='Host Info')
        
        # تبويب الثغرات الأمنية
        vuln_frame = ttk.Frame(results_notebook, padding=5)
        results_notebook.add(vuln_frame, text='Vulnerabilities')
        
        # منطقة النتائج النصية مع تنسيق مخصص
        self.results_text = scrolledtext.ScrolledText(
            port_results_frame, 
            width=60, 
            height=20,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10),
            insertbackground='white',
            selectbackground='#3a3a3a',
            relief='flat',
            padx=10,
            pady=10
        )
        self.results_text.pack(fill='both', expand=True)
        
        # منطقة معلومات المضيف
        self.host_info_text = scrolledtext.ScrolledText(
            host_info_frame,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10),
            insertbackground='white',
            selectbackground='#3a3a3a',
            relief='flat',
            padx=10,
            pady=10
        )
        self.host_info_text.pack(fill='both', expand=True)
        
        # منطقة الثغرات الأمنية
        self.vuln_text = scrolledtext.ScrolledText(
            vuln_frame,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10),
            insertbackground='white',
            selectbackground='#3a3a3a',
            relief='flat',
            padx=10,
            pady=10
        )
        self.vuln_text.pack(fill='both', expand=True)
        
        # شريط التقدم
        self.progress = ttk.Progressbar(results_frame, mode='determinate')
        self.progress.pack(fill='x', pady=(10, 0))
        
        # إطار الإحصائيات
        stats_frame = ttk.Frame(results_frame)
        stats_frame.pack(fill='x', pady=(10, 0))
        
        ttk.Label(stats_frame, text="Open ports:").grid(row=0, column=0, sticky='w')
        self.open_ports_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.open_ports_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=1, sticky='w', padx=(5, 15))
        
        ttk.Label(stats_frame, text="Scanned:").grid(row=0, column=2, sticky='w')
        self.scanned_ports_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.scanned_ports_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=3, sticky='w', padx=(5, 15))
        
        ttk.Label(stats_frame, text="Filtered:").grid(row=0, column=4, sticky='w')
        self.filtered_ports_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.filtered_ports_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=5, sticky='w', padx=(5, 15))
        
        ttk.Label(stats_frame, text="Status:").grid(row=0, column=6, sticky='w')
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(stats_frame, textvariable=self.status_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=7, sticky='w', padx=(5, 0))
        
        # تكوين أوزان الشبكة
        control_frame.columnconfigure(0, weight=1)
        port_selection_frame.columnconfigure(2, weight=1)
        advanced_frame.columnconfigure(3, weight=1)
        button_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(7, weight=1)
        
        # التهيئة الأولية
        self.append_result("🚀 Port Scanner Pro Ultimate Edition initialized\n", "#4fc3f7")
        self.append_result("Enter target and port range to begin scanning\n\n", "#ba68c8")
        
    def setup_tools_tab(self):
        # واجهة أدوات الشبكة
        ttk.Label(self.tools_frame, text="Network Analysis Tools", style='Header.TLabel').pack(anchor='w', pady=(0, 20))
        
        # دفتر أدوات
        tools_notebook = ttk.Notebook(self.tools_frame)
        tools_notebook.pack(fill='both', expand=True)
        
        # أداة Ping
        ping_frame = ttk.Frame(tools_notebook, padding=10)
        tools_notebook.add(ping_frame, text='Ping')
        
        ping_input_frame = ttk.Frame(ping_frame)
        ping_input_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(ping_input_frame, text="Host:").pack(side='left')
        self.ping_host_var = tk.StringVar(value="google.com")
        ping_entry = ttk.Entry(ping_input_frame, textvariable=self.ping_host_var, width=30)
        ping_entry.pack(side='left', padx=(5, 10))
        
        ttk.Button(ping_input_frame, text="Ping", command=self.run_ping).pack(side='left')
        ttk.Button(ping_input_frame, text="Traceroute", command=self.run_traceroute).pack(side='left', padx=(5, 0))
        
        self.ping_result = scrolledtext.ScrolledText(
            ping_frame,
            height=15,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10)
        )
        self.ping_result.pack(fill='both', expand=True)
        
        # أداة WHOIS
        if WHOIS_AVAILABLE:
            whois_frame = ttk.Frame(tools_notebook, padding=10)
            tools_notebook.add(whois_frame, text='WHOIS')
            
            whois_input_frame = ttk.Frame(whois_frame)
            whois_input_frame.pack(fill='x', pady=(0, 10))
            
            ttk.Label(whois_input_frame, text="Domain:").pack(side='left')
            self.whois_domain_var = tk.StringVar(value="google.com")
            whois_entry = ttk.Entry(whois_input_frame, textvariable=self.whois_domain_var, width=30)
            whois_entry.pack(side='left', padx=(5, 10))
            
            ttk.Button(whois_input_frame, text="Lookup", command=self.run_whois).pack(side='left')
            
            self.whois_result = scrolledtext.ScrolledText(
                whois_frame,
                height=15,
                bg='#1a1a1a',
                fg='#ffffff',
                font=('Consolas', 10)
            )
            self.whois_result.pack(fill='both', expand=True)
        
        # أداة DNS
        if DNS_AVAILABLE:
            dns_frame = ttk.Frame(tools_notebook, padding=10)
            tools_notebook.add(dns_frame, text='DNS Lookup')
            
            dns_input_frame = ttk.Frame(dns_frame)
            dns_input_frame.pack(fill='x', pady=(0, 10))
            
            ttk.Label(dns_input_frame, text="Domain:").pack(side='left')
            self.dns_domain_var = tk.StringVar(value="google.com")
            dns_entry = ttk.Entry(dns_input_frame, textvariable=self.dns_domain_var, width=20)
            dns_entry.pack(side='left', padx=(5, 5))
            
            ttk.Label(dns_input_frame, text="Record Type:").pack(side='left', padx=(10, 5))
            self.dns_type_var = tk.StringVar(value="A")
            dns_type_combo = ttk.Combobox(dns_input_frame, textvariable=self.dns_type_var, 
                                         values=["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"], width=8)
            dns_type_combo.pack(side='left')
            
            ttk.Button(dns_input_frame, text="Lookup", command=self.run_dns_lookup).pack(side='left', padx=(10, 0))
            
            self.dns_result = scrolledtext.ScrolledText(
                dns_frame,
                height=15,
                bg='#1a1a1a',
                fg='#ffffff',
                font=('Consolas', 10)
            )
            self.dns_result.pack(fill='both', expand=True)
        
        # أداة Subnet Calculator
        subnet_frame = ttk.Frame(tools_notebook, padding=10)
        tools_notebook.add(subnet_frame, text='Subnet Calculator')
        
        subnet_input_frame = ttk.Frame(subnet_frame)
        subnet_input_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(subnet_input_frame, text="IP/CIDR:").pack(side='left')
        self.subnet_ip_var = tk.StringVar(value="192.168.1.0/24")
        subnet_entry = ttk.Entry(subnet_input_frame, textvariable=self.subnet_ip_var, width=20)
        subnet_entry.pack(side='left', padx=(5, 10))
        
        ttk.Button(subnet_input_frame, text="Calculate", command=self.calculate_subnet).pack(side='left')
        
        self.subnet_result = scrolledtext.ScrolledText(
            subnet_frame,
            height=15,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10)
            )
        self.subnet_result.pack(fill='both', expand=True)
        
        # إضافة تبويب لأدوات النظام
        system_frame = ttk.Frame(tools_notebook, padding=10)
        tools_notebook.add(system_frame, text='System Info')
        
        system_info = self.get_system_info()
        system_text = scrolledtext.ScrolledText(
            system_frame,
            height=15,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10)
        )
        system_text.pack(fill='both', expand=True)
        system_text.insert(tk.END, system_info)
        system_text.config(state=tk.DISABLED)
    
    def setup_history_tab(self):
        # واجهة سجل المسح
        ttk.Label(self.history_frame, text="Scan History", style='Header.TLabel').pack(anchor='w', pady=(0, 20))
        
        # عناصر تحكم السجل
        history_controls = ttk.Frame(self.history_frame)
        history_controls.pack(fill='x', pady=(0, 10))
        
        ttk.Button(history_controls, text="Load History", command=self.load_history).pack(side='left')
        ttk.Button(history_controls, text="Clear History", command=self.clear_history).pack(side='left', padx=(5, 0))
        ttk.Button(history_controls, text="Export All", command=self.export_history).pack(side='right')
        
        # جدول السجل
        columns = ("Date", "Target", "Ports", "Open", "Time")
        self.history_tree = ttk.Treeview(self.history_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=100)
        
        self.history_tree.column("Date", width=150)
        self.history_tree.column("Target", width=150)
        
        # شريط التمرير للجدول
        scrollbar = ttk.Scrollbar(self.history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        self.history_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # تحميل السجل
        self.load_history()
    
    def setup_settings_tab(self):
        # واجهة الإعدادات
        ttk.Label(self.settings_frame, text="Application Settings", style='Header.TLabel').pack(anchor='w', pady=(0, 20))
        
        # اختيار السمة
        theme_frame = ttk.LabelFrame(self.settings_frame, text="Theme", padding=10)
        theme_frame.pack(fill='x', pady=(0, 15))
        
        self.theme_var = tk.StringVar(value="dark")
        ttk.Radiobutton(theme_frame, text="Dark", variable=self.theme_var, value="dark", 
                       command=self.change_theme).pack(side='left')
        ttk.Radiobutton(theme_frame, text="Light", variable=self.theme_var, value="light", 
                       command=self.change_theme).pack(side='left', padx=(20, 0))
        
        # إعدادات المسح الافتراضية
        defaults_frame = ttk.LabelFrame(self.settings_frame, text="Default Scan Settings", padding=10)
        defaults_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Label(defaults_frame, text="Default timeout (s):").grid(row=0, column=0, sticky='w')
        self.default_timeout_var = tk.StringVar(value="0.5")
        ttk.Entry(defaults_frame, textvariable=self.default_timeout_var, width=10).grid(row=0, column=1, sticky='w', padx=(5, 0))
        
        ttk.Label(defaults_frame, text="Default threads:").grid(row=0, column=2, sticky='w', padx=(20, 0))
        self.default_threads_var = tk.StringVar(value="100")
        ttk.Entry(defaults_frame, textvariable=self.default_threads_var, width=10).grid(row=0, column=3, sticky='w', padx=(5, 0))
        
        ttk.Label(defaults_frame, text="Default ports:").grid(row=1, column=0, sticky='w', pady=(10, 0))
        self.default_ports_var = tk.StringVar(value="1-1024")
        ttk.Entry(defaults_frame, textvariable=self.default_ports_var, width=10).grid(row=1, column=1, sticky='w', padx=(5, 0), pady=(10, 0))
        
        # قاعدة بيانات الثغرات
        vuln_db_frame = ttk.LabelFrame(self.settings_frame, text="Vulnerability Database", padding=10)
        vuln_db_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Button(vuln_db_frame, text="Update Vulnerability DB", command=self.update_vulnerability_db).pack(side='left')
        ttk.Button(vuln_db_frame, text="View Vulnerability DB", command=self.view_vulnerability_db).pack(side='left', padx=(10, 0))
        
        # معلومات التطبيق
        info_frame = ttk.LabelFrame(self.settings_frame, text="Application Information", padding=10)
        info_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Label(info_frame, text="Version: 2.0.0").pack(anchor='w')
        ttk.Label(info_frame, text="Author: Port Scanner Pro Team").pack(anchor='w')
        ttk.Label(info_frame, text="License: MIT").pack(anchor='w')
        ttk.Label(info_frame, text=f"Platform: {platform.system()} {platform.release()}").pack(anchor='w')
        
        # زر الإعادة إلى الإعدادات الافتراضية
        ttk.Button(self.settings_frame, text="Reset to Defaults", command=self.reset_settings).pack(anchor='w')
    
    def change_theme(self):
        if THEME_AVAILABLE:
            sv_ttk.set_theme(self.theme_var.get())
        else:
            messagebox.showinfo("Theme", "Theme library not available. Using system theme.")
    
    def reset_settings(self):
        self.default_timeout_var.set("0.5")
        self.default_threads_var.set("100")
        self.default_ports_var.set("1-1024")
        messagebox.showinfo("Settings", "Settings have been reset to defaults.")
    
    def update_vulnerability_db(self):
        self.append_result("Updating vulnerability database...\n", "#4fc3f7")
        # في التطبيق الحقيقي، هذا سيقوم بالجلب من مصدر عبر الإنترنت
        self.vulnerability_db = self.load_vulnerability_db()
        self.append_result("Vulnerability database updated.\n", "#4caf50")
    
    def view_vulnerability_db(self):
        # إنشاء نافذة جديدة لعرض قاعدة بيانات الثغرات
        vuln_window = tk.Toplevel(self.root)
        vuln_window.title("Vulnerability Database")
        vuln_window.geometry("800x600")
        
        text_area = scrolledtext.ScrolledText(
            vuln_window,
            bg='#1a1a1a',
            fg='#ffffff',
            font=('Consolas', 10)
        )
        text_area.pack(fill='both', expand=True, padx=10, pady=10)
        
        # عرض قاعدة بيانات الثغرات
        text_area.insert(tk.END, json.dumps(self.vulnerability_db, indent=2))
        text_area.config(state=tk.DISABLED)
    
    def load_vulnerability_db(self):
        # هذه قاعدة بيانات مبسطة للثغرات
        # في التطبيق الحقيقي، سيتم تحميل هذا من ملف أو قاعدة بيانات عبر الإنترنت
        return {
            "21": {"service": "FTP", "vulnerabilities": ["Anonymous login", "Brute force"]},
            "22": {"service": "SSH", "vulnerabilities": ["Weak passwords", "SSH version 1"]},
            "23": {"service": "Telnet", "vulnerabilities": ["Clear text communication", "No encryption"]},
            "25": {"service": "SMTP", "vulnerabilities": ["Open relay", "User enumeration"]},
            "53": {"service": "DNS", "vulnerabilities": ["DNS cache poisoning", "Zone transfer"]},
            "80": {"service": "HTTP", "vulnerabilities": ["SQL injection", "XSS", "CSRF"]},
            "110": {"service": "POP3", "vulnerabilities": ["Clear text authentication"]},
            "135": {"service": "RPC", "vulnerabilities": ["Remote code execution"]},
            "139": {"service": "NetBIOS", "vulnerabilities": ["Information disclosure"]},
            "143": {"service": "IMAP", "vulnerabilities": ["Clear text authentication"]},
            "443": {"service": "HTTPS", "vulnerabilities": ["SSL vulnerabilities", "Heartbleed"]},
            "445": {"service": "SMB", "vulnerabilities": ["EternalBlue", "SMB relay"]},
            "993": {"service": "IMAPS", "vulnerabilities": ["SSL vulnerabilities"]},
            "995": {"service": "POP3S", "vulnerabilities": ["SSL vulnerabilities"]},
            "1433": {"service": "MSSQL", "vulnerabilities": ["Weak authentication", "SQL injection"]},
            "3306": {"service": "MySQL", "vulnerabilities": ["Weak authentication", "SQL injection"]},
            "3389": {"service": "RDP", "vulnerabilities": ["BlueKeep", "Weak passwords"]},
            "5900": {"service": "VNC", "vulnerabilities": ["Weak authentication", "No encryption"]},
            "27017": {"service": "MongoDB", "vulnerabilities": ["No authentication", "Data exposure"]}
        }
    
    def load_common_ports(self):
        # قائمة بالمنافذ الشائعة وخدماتها
        return OrderedDict([
            (21, "FTP"),
            (22, "SSH"),
            (23, "Telnet"),
            (25, "SMTP"),
            (53, "DNS"),
            (80, "HTTP"),
            (110, "POP3"),
            (115, "SFTP"),
            (135, "RPC"),
            (139, "NetBIOS"),
            (143, "IMAP"),
            (194, "IRC"),
            (443, "HTTPS"),
            (445, "SMB"),
            (993, "IMAPS"),
            (995, "POP3S"),
            (1433, "MSSQL"),
            (1723, "PPTP"),
            (3306, "MySQL"),
            (3389, "RDP"),
            (5900, "VNC"),
            (8080, "HTTP-Alt")
        ])
    
    def get_local_ip(self):
        try:
            # الحصول على IP المحلي عن طريق إنشاء اتصال تجريبي
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def get_public_ip(self):
        try:
            if not REQUESTS_AVAILABLE:
                return "Requests library required"
            
            response = requests.get("https://api.ipify.org", timeout=10)
            response = requests.get('https://api.ipify.org', timeout=10)
            return response.text
        except:
            return "Unable to determine"
    
    def get_system_info(self):
        # جمع معلومات النظام
        info = "=== System Information ===\n\n"
        info += f"Hostname: {socket.gethostname()}\n"
        info += f"OS: {platform.system()} {platform.release()}\n"
        info += f"Version: {platform.version()}\n"
        info += f"Architecture: {platform.machine()}\n"
        info += f"Processor: {platform.processor()}\n\n"
        
        info += "=== Network Information ===\n\n"
        info += f"Local IP: {self.local_ip}\n"
        info += f"Public IP: {self.public_ip}\n\n"
        
        info += "=== Python Information ===\n\n"
        info += f"Python Version: {platform.python_version()}\n"
        info += f"Python Implementation: {platform.python_implementation()}\n"
        
        return info
    
    def append_result(self, text, color="#ffffff"):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text, color)
        self.results_text.tag_config(color, foreground=color)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)
    
    def toggle_scan(self):
        if self.scanning:
            self.stop_scan = True
            self.scan_button.config(text="Stopping...")
            self.status_var.set("Stopping...")
        else:
            self.start_scan()
    
    def start_scan(self):
        # التحقق من صحة المدخلات
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target to scan")
            return
        
        try:
            # الحصول على قائمة المنافذ للمسح
            if self.port_selection_var.get() == "Range":
                start_port = int(self.start_port_var.get())
                end_port = int(self.end_port_var.get())
                if start_port > end_port:
                    messagebox.showerror("Error", "Start port cannot be greater than end port")
                    return
                ports_to_scan = list(range(start_port, end_port + 1))
            elif self.port_selection_var.get() == "Common":
                ports_to_scan = list(self.common_ports_list.keys())
            else:  # Custom
                custom_ports = self.custom_ports_var.get().split(',')
                ports_to_scan = []
                for port_str in custom_ports:
                    port_str = port_str.strip()
                    if '-' in port_str:
                        start, end = map(int, port_str.split('-'))
                        ports_to_scan.extend(range(start, end + 1))
                    else:
                        ports_to_scan.append(int(port_str))
            
            # الحصول على إعدادات المسح
            timeout = float(self.timeout_var.get())
            max_threads = int(self.threads_var.get())
            delay = float(self.delay_var.get()) / 1000  # تحويل إلى ثواني
            retries = int(self.retries_var.get())
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {str(e)}")
            return
        
        # إعداد حالة المسح
        self.scanning = True
        self.stop_scan = False
        self.open_ports = []
        self.scan_button.config(text="Stop Scan")
        self.status_var.set("Scanning...")
        self.progress.config(maximum=len(ports_to_scan), value=0)
        
        # مسح النتائج السابقة
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        # بدء المسح في thread منفصل
        scan_thread = threading.Thread(
            target=self.scan_ports,
            args=(target, ports_to_scan, timeout, max_threads, delay, retries)
        )
        scan_thread.daemon = True
        scan_thread.start()
    
    def scan_ports(self, target, ports, timeout, max_threads, delay, retries):
        try:
            # حل اسم المضيف إذا كان اسم نطاق
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                self.status_var.set("Invalid target")
                self.scanning = False
                self.scan_button.config(text="Start Scan")
                return
            
            # تحديث معلومات المضيف
            self.host_info = {
                'target': target,
                'ip': target_ip,
                'start_time': datetime.now(),
                'total_ports': len(ports)
            }
            
            # مسح المنافذ باستخدام ThreadPool
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            scanned_count = 0
            filtered_count = 0
            
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                # إنشاء مهمة لكل منفذ
                future_to_port = {
                    executor.submit(self.scan_port, target_ip, port, timeout, retries): port 
                    for port in ports
                }
                
                for future in as_completed(future_to_port):
                    if self.stop_scan:
                        break
                        
                    port = future_to_port[future]
                    try:
                        result = future.result()
                        scanned_count += 1
                        
                        if result['status'] == 'open':
                            self.open_ports.append(port)
                            self.display_port_result(port, result)
                        elif result['status'] == 'filtered':
                            filtered_count += 1
                            if self.verbose_var.get():
                                self.display_port_result(port, result)
                        
                        # تحديث الإحصائيات
                        self.scanned_ports_var.set(str(scanned_count))
                        self.open_ports_var.set(str(len(self.open_ports)))
                        self.filtered_ports_var.set(str(filtered_count))
                        self.progress.config(value=scanned_count)
                        
                        # تأخير إذا تم تحديده
                        if delay > 0:
                            time.sleep(delay)
                            
                    except Exception as e:
                        print(f"Error scanning port {port}: {e}")
            
            # انتهاء المسح
            self.finish_scan()
            
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            self.scanning = False
            self.scan_button.config(text="Start Scan")
    
    def scan_port(self, target, port, timeout, retries):
        result = {
            'port': port,
            'status': 'closed',
            'service': 'unknown',
            'banner': ''
        }
        
        for attempt in range(retries):
            if self.stop_scan:
                break
                
            try:
                # إنشاء socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                # محاولة الاتصال
                connection_result = sock.connect_ex((target, port))
                
                if connection_result == 0:
                    result['status'] = 'open'
                    
                    # محاولة الحصول على banner
                    try:
                        sock.send(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = sock.recv(1024).decode('utf-8', errors='ignore')
                        if banner:
                            result['banner'] = banner.strip()[:100] + "..." if len(banner) > 100 else banner.strip()
                    except:
                        pass
                    
                    # تحديد الخدمة
                    try:
                        result['service'] = socket.getservbyport(port, 'tcp')
                    except:
                        result['service'] = 'unknown'
                    
                    break
                else:
                    # قد يكون المنفذ filtered
                    result['status'] = 'filtered' if connection_result in [111, 113] else 'closed'
                    
            except socket.timeout:
                result['status'] = 'filtered'
            except Exception as e:
                result['status'] = 'error'
                result['error'] = str(e)
            finally:
                try:
                    sock.close()
                except:
                    pass
        
        return result
    
    def display_port_result(self, port, result):
        color = "#4caf50" if result['status'] == 'open' else "#ff9800" if result['status'] == 'filtered' else "#f44336"
        status_text = result['status'].upper()
        
        self.append_result(f"Port {port:5d} : {status_text:8s}", color)
        
        if result['status'] == 'open':
            service_info = f" - {result['service']}"
            self.append_result(service_info, "#bb86fc")
            
            if result['banner']:
                self.append_result(f" - {result['banner']}\n", "#03dac6")
            else:
                self.append_result("\n", color)
        else:
            self.append_result("\n", color)
    
    def finish_scan(self):
        end_time = datetime.now()
        scan_duration = end_time - self.host_info['start_time']
        
        # تحديث معلومات المضيف
        self.update_host_info(scan_duration)
        
        # التحقق من الثغرات الأمنية
        self.check_vulnerabilities()
        
        # حفظ في السجل
        self.save_to_history(scan_duration)
        
        # تحديث الواجهة
        self.status_var.set("Scan completed")
        self.scanning = False
        self.scan_button.config(text="Start Scan")
        
        # عرض ملخص
        self.append_result(f"\nScan completed in {scan_duration.total_seconds():.2f} seconds\n", "#4fc3f7")
        self.append_result(f"Scanned {self.host_info['total_ports']} ports, ", "#4fc3f7")
        self.append_result(f"{len(self.open_ports)} open, ", "#4caf50")
        self.append_result(f"{int(self.filtered_ports_var.get())} filtered\n", "#ff9800")
    
    def update_host_info(self, duration):
        self.host_info_text.config(state=tk.NORMAL)
        self.host_info_text.delete(1.0, tk.END)
        
        info = f"Target: {self.host_info['target']}\n"
        info += f"IP Address: {self.host_info['ip']}\n"
        info += f"Scan started: {self.host_info['start_time'].strftime('%Y-%m-%d %H:%M:%S')}\n"
        info += f"Scan duration: {duration.total_seconds():.2f} seconds\n"
        info += f"Total ports scanned: {self.host_info['total_ports']}\n"
        info += f"Open ports: {len(self.open_ports)}\n"
        info += f"Filtered ports: {self.filtered_ports_var.get()}\n\n"
        
        # معلومات إضافية إذا كان المضيف محلياً
        if self.host_info['ip'] == self.local_ip or self.host_info['ip'].startswith('127.'):
            info += "Note: Scanning localhost\n"
        
        self.host_info_text.insert(tk.END, info)
        self.host_info_text.config(state=tk.DISABLED)
    
    def check_vulnerabilities(self):
        self.vuln_text.config(state=tk.NORMAL)
        self.vuln_text.delete(1.0, tk.END)
        
        if not self.open_ports:
            self.vuln_text.insert(tk.END, "No open ports found for vulnerability analysis.\n")
            self.vuln_text.config(state=tk.DISABLED)
            return
        
        vulnerabilities_found = 0
        
        self.vuln_text.insert(tk.END, "Vulnerability Analysis:\n\n")
        
        for port in self.open_ports:
            port_str = str(port)
            if port_str in self.vulnerability_db:
                vuln_info = self.vulnerability_db[port_str]
                self.vuln_text.insert(tk.END, f"Port {port} ({vuln_info['service']}):\n", "#ff4444")
                
                for vuln in vuln_info['vulnerabilities']:
                    self.vuln_text.insert(tk.END, f"  - {vuln}\n", "#ffbb33")
                    vulnerabilities_found += 1
                
                self.vuln_text.insert(tk.END, "\n")
        
        if vulnerabilities_found == 0:
            self.vuln_text.insert(tk.END, "No known vulnerabilities detected in open ports.\n", "#00C851")
        else:
            self.vuln_text.insert(tk.END, f"Total potential vulnerabilities found: {vulnerabilities_found}\n", "#ff4444")
        
        self.vuln_text.config(state=tk.DISABLED)
    
    def save_to_history(self, duration):
        scan_entry = {
            'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'target': self.host_info['target'],
            'ip': self.host_info['ip'],
            'ports_scanned': self.host_info['total_ports'],
            'open_ports': len(self.open_ports),
            'filtered_ports': int(self.filtered_ports_var.get()),
            'duration': f"{duration.total_seconds():.2f}s",
            'open_ports_list': self.open_ports.copy()
        }
        
        self.scan_history.append(scan_entry)
        
        # حفظ إلى ملف
        try:
            history_file = "scan_history.json"
            with open(history_file, 'w') as f:
                json.dump(self.scan_history, f, indent=2)
        except Exception as e:
            print(f"Error saving history: {e}")
    
    def clear_results(self):
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        
        self.host_info_text.config(state=tk.NORMAL)
        self.host_info_text.delete(1.0, tk.END)
        self.host_info_text.config(state=tk.DISABLED)
        
        self.vuln_text.config(state=tk.NORMAL)
        self.vuln_text.delete(1.0, tk.END)
        self.vuln_text.config(state=tk.DISABLED)
        
        self.open_ports_var.set("0")
        self.scanned_ports_var.set("0")
        self.filtered_ports_var.set("0")
        self.status_var.set("Ready")
        self.progress.config(value=0)
        
        self.append_result("Results cleared. Ready for new scan.\n", "#4fc3f7")
    
    def save_results(self):
        if not self.open_ports and not self.scan_history:
            messagebox.showinfo("Save Results", "No scan results to save.")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.csv'):
                self.save_results_csv(file_path)
            elif file_path.endswith('.json'):
                self.save_results_json(file_path)
            else:
                self.save_results_txt(file_path)
                
            messagebox.showinfo("Save Results", f"Results saved successfully to {file_path}")
        except Exception as e:
            messagebox.showerror("Save Error", f"Error saving results: {str(e)}")
    
    def save_results_txt(self, file_path):
        with open(file_path, 'w') as f:
            f.write(f"Port Scanner Pro - Scan Results\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {self.host_info.get('target', 'N/A')}\n")
            f.write(f"IP: {self.host_info.get('ip', 'N/A')}\n")
            f.write(f"Scan duration: {self.host_info.get('duration', 'N/A')}\n\n")
            
            f.write("OPEN PORTS:\n")
            f.write("----------\n")
            for port in self.open_ports:
                f.write(f"Port {port}\n")
            
            f.write(f"\nTotal open ports: {len(self.open_ports)}\n")
            f.write(f"Total ports scanned: {self.host_info.get('total_ports', 0)}\n")
    
    def save_results_csv(self, file_path):
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status', 'Service'])
            for port in self.open_ports:
                writer.writerow([port, 'Open', 'Unknown'])  # يمكن تحسين هذا
    
    def save_results_json(self, file_path):
        results = {
            'scan_date': datetime.now().isoformat(),
            'target': self.host_info.get('target', ''),
            'ip_address': self.host_info.get('ip', ''),
            'open_ports': self.open_ports,
            'scan_duration': self.host_info.get('duration', ''),
            'total_ports_scanned': self.host_info.get('total_ports', 0)
        }
        
        with open(file_path, 'w') as f:
            json.dump(results, f, indent=2)
    
    def discover_hosts(self):
        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target network")
            return
        
        try:
            # تحقق إذا كان المدخل هو نطاق شبكة
            network = ipaddress.ip_network(target, strict=False)
            network_str = str(network)
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid network (e.g., 192.168.1.0/24)")
            return
        
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Error", "Scapy library required for host discovery")
            return
        
        # تنفيذ مسح ARP لاكتشاف الأجهزة
        self.append_result(f"\nDiscovering hosts in {network_str}...\n", "#4fc3f7")
        
        try:
            # إنشاء طلب ARP
            arp = ARP(pdst=str(network))
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # إرسال واستقبال الحزم
            result = srp(packet, timeout=2, verbose=0)[0]
            
            hosts = []
            for sent, received in result:
                hosts.append({'ip': received.psrc, 'mac': received.hwsrc})
            
            if hosts:
                self.append_result(f"Found {len(hosts)} hosts:\n", "#4caf50")
                for host in hosts:
                    self.append_result(f"IP: {host['ip']} - MAC: {host['mac']}\n", "#bb86fc")
            else:
                self.append_result("No hosts found in the network\n", "#ff9800")
                
        except Exception as e:
            self.append_result(f"Discovery error: {str(e)}\n", "#f44336")
    
    def run_ping(self):
        host = self.ping_host_var.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a host to ping")
            return
        
        self.ping_result.config(state=tk.NORMAL)
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Pinging {host}...\n\n")
        self.ping_result.config(state=tk.DISABLED)
        
        # تنفيذ ping بناءً على نظام التشغيل
        param = "-n" if IS_WINDOWS else "-c"
        command = ["ping", param, "4", host]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.ping_result.config(state=tk.NORMAL)
            self.ping_result.insert(tk.END, result.stdout)
            if result.stderr:
                self.ping_result.insert(tk.END, f"\nError: {result.stderr}")
            self.ping_result.config(state=tk.DISABLED)
        except subprocess.TimeoutExpired:
            self.ping_result.config(state=tk.NORMAL)
            self.ping_result.insert(tk.END, "Ping timed out")
            self.ping_result.config(state=tk.DISABLED)
        except Exception as e:
            self.ping_result.config(state=tk.NORMAL)
            self.ping_result.insert(tk.END, f"Error: {str(e)}")
            self.ping_result.config(state=tk.DISABLED)
    
    def run_traceroute(self):
        host = self.ping_host_var.get().strip()
        if not host:
            messagebox.showerror("Error", "Please enter a host for traceroute")
            return
        
        self.ping_result.config(state=tk.NORMAL)
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Traceroute to {host}...\n\n")
        self.ping_result.config(state=tk.DISABLED)
        
        # تنفيذ traceroute بناءً على نظام التشغيل
        command = ["tracert", "-d", host] if IS_WINDOWS else ["traceroute", host]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            self.ping_result.config(state=tk.NORMAL)
            self.ping_result.insert(tk.END, result.stdout)
            if result.stderr:
                self.ping_result.insert(tk.END, f"\nError: {result.stderr}")
            self.ping_result.config(state=tk.DISABLED)
        except FileNotFoundError:
            self.ping_result.config(state=tk.NORMAL)
            self.ping_result.insert(tk.END, "Traceroute command not available")
            self.ping_result.config(state=tk.DISABLED)
        except Exception as e:
            self.ping_result.config(state=tk.NORMAL)
            self.ping_result.insert(tk.END, f"Error: {str(e)}")
            self.ping_result.config(state=tk.DISABLED)
    
    def run_whois(self):
        if not WHOIS_AVAILABLE:
            messagebox.showerror("Error", "Whois library not available")
            return
        
        domain = self.whois_domain_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.whois_result.config(state=tk.NORMAL)
        self.whois_result.delete(1.0, tk.END)
        self.whois_result.insert(tk.END, f"WHOIS lookup for {domain}...\n\n")
        self.whois_result.config(state=tk.DISABLED)
        
        try:
            whois_info = whois.whois(domain)
            self.whois_result.config(state=tk.NORMAL)
            self.whois_result.insert(tk.END, str(whois_info))
            self.whois_result.config(state=tk.DISABLED)
        except Exception as e:
            self.whois_result.config(state=tk.NORMAL)
            self.whois_result.insert(tk.END, f"Error: {str(e)}")
            self.whois_result.config(state=tk.DISABLED)
    
    def run_dns_lookup(self):
        if not DNS_AVAILABLE:
            messagebox.showerror("Error", "DNS library not available")
            return
        
        domain = self.dns_domain_var.get().strip()
        record_type = self.dns_type_var.get().strip()
        if not domain:
            messagebox.showerror("Error", "Please enter a domain")
            return
        
        self.dns_result.config(state=tk.NORMAL)
        self.dns_result.delete(1.0, tk.END)
        self.dns_result.insert(tk.END, f"DNS {record_type} lookup for {domain}...\n\n")
        self.dns_result.config(state=tk.DISABLED)
        
        try:
            answers = dns.resolver.resolve(domain, record_type)
            self.dns_result.config(state=tk.NORMAL)
            for answer in answers:
                self.dns_result.insert(tk.END, f"{answer}\n")
            self.dns_result.config(state=tk.DISABLED)
        except dns.resolver.NoAnswer:
            self.dns_result.config(state=tk.NORMAL)
            self.dns_result.insert(tk.END, f"No {record_type} records found for {domain}")
            self.dns_result.config(state=tk.DISABLED)
        except Exception as e:
            self.dns_result.config(state=tk.NORMAL)
            self.dns_result.insert(tk.END, f"Error: {str(e)}")
            self.dns_result.config(state=tk.DISABLED)
    
    def calculate_subnet(self):
        subnet_input = self.subnet_ip_var.get().strip()
        if not subnet_input:
            messagebox.showerror("Error", "Please enter an IP/CIDR")
            return
        
        try:
            network = ipaddress.ip_network(subnet_input, strict=False)
            self.subnet_result.config(state=tk.NORMAL)
            self.subnet_result.delete(1.0, tk.END)
            
            info = f"Subnet Calculator Results:\n\n"
            info += f"Network Address: {network.network_address}\n"
            info += f"Broadcast Address: {network.broadcast_address}\n"
            info += f"Netmask: {network.netmask}\n"
            info += f"Wildcard Mask: {network.hostmask}\n"
            info += f"CIDR Notation: /{network.prefixlen}\n"
            info += f"Total Hosts: {network.num_addresses}\n"
            info += f"Usable Hosts: {network.num_addresses - 2}\n"
            info += f"First Usable: {list(network.hosts())[0] if network.num_addresses > 2 else 'N/A'}\n"
            info += f"Last Usable: {list(network.hosts())[-1] if network.num_addresses > 2 else 'N/A'}\n"
            
            self.subnet_result.insert(tk.END, info)
            self.subnet_result.config(state=tk.DISABLED)
            
        except ValueError as e:
            self.subnet_result.config(state=tk.NORMAL)
            self.subnet_result.delete(1.0, tk.END)
            self.subnet_result.insert(tk.END, f"Error: Invalid IP/CIDR format\n{e}")
            self.subnet_result.config(state=tk.DISABLED)
    
    def load_history(self):
        try:
            history_file = "scan_history.json"
            if os.path.exists(history_file):
                with open(history_file, 'r') as f:
                    self.scan_history = json.load(f)
                
                # تحديث Treeview
                for item in self.history_tree.get_children():
                    self.history_tree.delete(item)
                
                for scan in self.scan_history:
                    self.history_tree.insert("", "end", values=(
                        scan['date'],
                        scan['target'],
                        scan['ports_scanned'],
                        scan['open_ports'],
                        scan['duration']
                    ))
        except Exception as e:
            print(f"Error loading history: {e}")
    
    def clear_history(self):
        if messagebox.askyesno("Clear History", "Are you sure you want to clear all scan history?"):
            self.scan_history = []
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
            
            try:
                os.remove("scan_history.json")
            except:
                pass
    
    def export_history(self):
        if not self.scan_history:
            messagebox.showinfo("Export", "No scan history to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.csv'):
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Date', 'Target', 'IP', 'Ports Scanned', 'Open Ports', 'Duration'])
                    for scan in self.scan_history:
                        writer.writerow([
                            scan['date'],
                            scan['target'],
                            scan['ip'],
                            scan['ports_scanned'],
                            scan['open_ports'],
                            scan['duration']
                        ])
            else:
                with open(file_path, 'w') as f:
                    json.dump(self.scan_history, f, indent=2)
            
            messagebox.showinfo("Export", "History exported successfully")
        except Exception as e:
            messagebox.showerror("Export Error", f"Error exporting history: {str(e)}")

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
