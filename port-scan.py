#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import sv_ttk  # Modern theme for tkinter
import ipaddress
import csv
import json
import time
import random
from scapy.all import ARP, Ether, srp, ICMP, IP, TCP, conf
import requests
from bs4 import BeautifulSoup
import whois
import dns.resolver
import subprocess
import sys
import os
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from concurrent.futures import ThreadPoolExecutor, as_completed

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner Pro - Ultimate Edition")
        self.root.geometry("1200x850")
        self.root.minsize(1000, 700)
        
        # Set dark theme
        sv_ttk.set_theme("dark")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'))
        self.style.configure('Subtitle.TLabel', font=('Segoe UI', 11))
        self.style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))
        self.style.configure('Card.TFrame', background='#1c1c1c')
        self.style.configure('Critical.TLabel', foreground='#ff4444')
        self.style.configure('Warning.TLabel', foreground='#ffbb33')
        self.style.configure('Success.TLabel', foreground='#00C851')
        
        # Variables
        self.scanning = False
        self.stop_scan = False
        self.open_ports = []
        self.scan_history = []
        self.host_info = {}
        self.vulnerability_db = self.load_vulnerability_db()
        self.common_ports_list = self.load_common_ports()
        
        # Network information
        self.local_ip = socket.gethostbyname(socket.gethostname())
        self.public_ip = self.get_public_ip()
        
        self.setup_ui()
        
    def setup_ui(self):
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Main scan tab
        self.scan_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.scan_frame, text='Port Scanner')
        
        # Network tools tab
        self.tools_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.tools_frame, text='Network Tools')
        
        # Results history tab
        self.history_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.history_frame, text='Scan History')
        
        # Settings tab
        self.settings_frame = ttk.Frame(self.notebook, padding=15)
        self.notebook.add(self.settings_frame, text='Settings')
        
        # Setup each tab
        self.setup_scan_tab()
        self.setup_tools_tab()
        self.setup_history_tab()
        self.setup_settings_tab()
        
    def setup_scan_tab(self):
        # Main container
        main_container = ttk.Frame(self.scan_frame)
        main_container.pack(fill='both', expand=True)
        
        # Header
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(header_frame, text="🚀 Port Scanner Pro - Ultimate Edition", style='Header.TLabel').pack(side='left')
        
        # Quick info panel
        info_frame = ttk.Frame(header_frame)
        info_frame.pack(side='right')
        
        ttk.Label(info_frame, text=f"Local IP: {self.local_ip} | Public IP: {self.public_ip}", 
                 style='Subtitle.TLabel').pack(side='top', anchor='e')
        ttk.Label(info_frame, text=f"Hostname: {socket.gethostname()}", 
                 style='Subtitle.TLabel').pack(side='top', anchor='e')
        
        # Content area
        content_frame = ttk.Frame(main_container)
        content_frame.pack(fill='both', expand=True)
        
        # Left panel - Controls
        control_frame = ttk.LabelFrame(content_frame, text="Scan Configuration", padding=15)
        control_frame.pack(side='left', fill='y', padx=(0, 10))
        
        # Target input with advanced options
        ttk.Label(control_frame, text="Target", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky='w', pady=(0, 5))
        
        target_input_frame = ttk.Frame(control_frame)
        target_input_frame.grid(row=1, column=0, sticky='we', pady=(0, 15))
        
        self.target_var = tk.StringVar(value="127.0.0.1")
        target_entry = ttk.Entry(target_input_frame, textvariable=self.target_var, width=25, font=('Segoe UI', 10))
        target_entry.pack(side='left', fill='x', expand=True)
        
        ttk.Button(target_input_frame, text="Discover", command=self.discover_hosts, width=8).pack(side='right', padx=(5, 0))
        
        # Scan type
        ttk.Label(control_frame, text="Scan Type", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky='w', pady=(0, 5))
        
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        scan_types = ["TCP Connect", "SYN Stealth", "UDP", "FIN", "XMAS", "NULL", "ACK", "Window", "Maimon"]
        scan_type_combo = ttk.Combobox(control_frame, textvariable=self.scan_type_var, values=scan_types, state="readonly")
        scan_type_combo.grid(row=3, column=0, sticky='we', pady=(0, 15))
        
        # Port selection
        port_selection_frame = ttk.LabelFrame(control_frame, text="Port Selection", padding=10)
        port_selection_frame.grid(row=4, column=0, sticky='we', pady=(0, 15))
        
        self.port_selection_var = tk.StringVar(value="Range")
        ttk.Radiobutton(port_selection_frame, text="Range", variable=self.port_selection_var, value="Range").grid(row=0, column=0, sticky='w')
        ttk.Radiobutton(port_selection_frame, text="Common Ports", variable=self.port_selection_var, value="Common").grid(row=0, column=1, sticky='w')
        ttk.Radiobutton(port_selection_frame, text="Custom List", variable=self.port_selection_var, value="Custom").grid(row=0, column=2, sticky='w')
        
        # Port range
        port_range_frame = ttk.Frame(port_selection_frame)
        port_range_frame.grid(row=1, column=0, columnspan=3, sticky='we', pady=(5, 0))
        
        self.start_port_var = tk.StringVar(value="1")
        start_port_entry = ttk.Entry(port_range_frame, textvariable=self.start_port_var, width=8, font=('Segoe UI', 9))
        start_port_entry.pack(side='left')
        
        ttk.Label(port_range_frame, text="—").pack(side='left', padx=5)
        
        self.end_port_var = tk.StringVar(value="1024")
        end_port_entry = ttk.Entry(port_range_frame, textvariable=self.end_port_var, width=8, font=('Segoe UI', 9))
        end_port_entry.pack(side='left')
        
        # Custom ports
        self.custom_ports_var = tk.StringVar(value="80,443,22,21,23,25,53,110,135,137,139,143,445,993,995,1723,3306,3389,5900,8080")
        custom_ports_entry = ttk.Entry(port_selection_frame, textvariable=self.custom_ports_var, font=('Segoe UI', 9))
        custom_ports_entry.grid(row=2, column=0, columnspan=3, sticky='we', pady=(5, 0))
        
        # Advanced settings
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
        
        # Options
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
        
        # Action buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=7, column=0, sticky='we')
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.toggle_scan, style='Accent.TButton')
        self.scan_button.pack(side='left', padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side='left')
        
        ttk.Button(button_frame, text="Save Results", command=self.save_results).pack(side='right')
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(content_frame, text="Scan Results", padding=10)
        results_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        # Create notebook for results tabs
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill='both', expand=True)
        
        # Port results tab
        port_results_frame = ttk.Frame(results_notebook, padding=5)
        results_notebook.add(port_results_frame, text='Ports')
        
        # Host info tab
        host_info_frame = ttk.Frame(results_notebook, padding=5)
        results_notebook.add(host_info_frame, text='Host Info')
        
        # Vulnerability tab
        vuln_frame = ttk.Frame(results_notebook, padding=5)
        results_notebook.add(vuln_frame, text='Vulnerabilities')
        
        # Results text area with custom styling
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
        
        # Host info text area
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
        
        # Vulnerability text area
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
        
        # Progress bar
        self.progress = ttk.Progressbar(results_frame, mode='determinate')
        self.progress.pack(fill='x', pady=(10, 0))
        
        # Statistics frame
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
        
        # Configure grid weights
        control_frame.columnconfigure(0, weight=1)
        port_selection_frame.columnconfigure(2, weight=1)
        advanced_frame.columnconfigure(3, weight=1)
        button_frame.columnconfigure(1, weight=1)
        stats_frame.columnconfigure(7, weight=1)
        
        # Initialize
        self.append_result("🚀 Port Scanner Pro Ultimate Edition initialized\n", "#4fc3f7")
        self.append_result("Enter target and port range to begin scanning\n\n", "#ba68c8")
        
    def setup_tools_tab(self):
        # Network tools interface
        ttk.Label(self.tools_frame, text="Network Analysis Tools", style='Header.TLabel').pack(anchor='w', pady=(0, 20))
        
        # Tools notebook
        tools_notebook = ttk.Notebook(self.tools_frame)
        tools_notebook.pack(fill='both', expand=True)
        
        # Ping tool
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
        
        # WHOIS tool
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
        
        # DNS tool
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
        
        # Subnet calculator
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
    
    def setup_history_tab(self):
        # Scan history interface
        ttk.Label(self.history_frame, text="Scan History", style='Header.TLabel').pack(anchor='w', pady=(0, 20))
        
        # History controls
        history_controls = ttk.Frame(self.history_frame)
        history_controls.pack(fill='x', pady=(0, 10))
        
        ttk.Button(history_controls, text="Load History", command=self.load_history).pack(side='left')
        ttk.Button(history_controls, text="Clear History", command=self.clear_history).pack(side='left', padx=(5, 0))
        ttk.Button(history_controls, text="Export All", command=self.export_history).pack(side='right')
        
        # History table
        columns = ("Date", "Target", "Ports", "Open", "Time")
        self.history_tree = ttk.Treeview(self.history_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=100)
        
        self.history_tree.column("Date", width=150)
        self.history_tree.column("Target", width=150)
        
        # Scrollbar for treeview
        scrollbar = ttk.Scrollbar(self.history_frame, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        self.history_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Load history
        self.load_history()
    
    def setup_settings_tab(self):
        # Settings interface
        ttk.Label(self.settings_frame, text="Application Settings", style='Header.TLabel').pack(anchor='w', pady=(0, 20))
        
        # Theme selection
        theme_frame = ttk.LabelFrame(self.settings_frame, text="Theme", padding=10)
        theme_frame.pack(fill='x', pady=(0, 15))
        
        self.theme_var = tk.StringVar(value="dark")
        ttk.Radiobutton(theme_frame, text="Dark", variable=self.theme_var, value="dark", 
                       command=self.change_theme).pack(side='left')
        ttk.Radiobutton(theme_frame, text="Light", variable=self.theme_var, value="light", 
                       command=self.change_theme).pack(side='left', padx=(20, 0))
        
        # Default scan settings
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
        
        # Vulnerability database
        vuln_db_frame = ttk.LabelFrame(self.settings_frame, text="Vulnerability Database", padding=10)
        vuln_db_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Button(vuln_db_frame, text="Update Vulnerability DB", command=self.update_vulnerability_db).pack(side='left')
        ttk.Button(vuln_db_frame, text="View Vulnerability DB", command=self.view_vulnerability_db).pack(side='left', padx=(10, 0))
        
        # Application info
        info_frame = ttk.LabelFrame(self.settings_frame, text="Application Information", padding=10)
        info_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Label(info_frame, text="Version: 2.0.0").pack(anchor='w')
        ttk.Label(info_frame, text="Author: Port Scanner Pro Team").pack(anchor='w')
        ttk.Label(info_frame, text="License: MIT").pack(anchor='w')
        
        # Reset button
        ttk.Button(self.settings_frame, text="Reset to Defaults", command=self.reset_settings).pack(anchor='w')
    
    def change_theme(self):
        sv_ttk.set_theme(self.theme_var.get())
    
    def reset_settings(self):
        self.default_timeout_var.set("0.5")
        self.default_threads_var.set("100")
        self.default_ports_var.set("1-1024")
        messagebox.showinfo("Settings", "Settings have been reset to defaults.")
    
    def update_vulnerability_db(self):
        self.append_result("Updating vulnerability database...\n", "#4fc3f7")
        # In a real application, this would fetch from an online source
        self.vulnerability_db = self.load_vulnerability_db()
        self.append_result("Vulnerability database updated.\n", "#4caf50")
    
    def view_vulnerability_db(self):
        # Create a new window to view the vulnerability database
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
        
        # Display the vulnerability database
        text_area.insert(tk.END, json.dumps(self.vulnerability_db, indent=2))
        text_area.config(state=tk.DISABLED)
    
    def load_vulnerability_db(self):
        # This is a simplified vulnerability database
        # In a real application, this would be loaded from a file or online database
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
        # List of common ports and their services
        return {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            115: "SFTP",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            194: "IRC",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt"
        }
    
    def get_public_ip(self):
        try:
            return requests.get('https://api.ipify.org').text
        except:
            return "Unable to determine"
    
    def discover_hosts(self):
        target = self.target_var.get()
        try:
            # Check if target is a network range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
                
                # Create a new window to show discovered hosts
                discover_window = tk.Toplevel(self.root)
                discover_window.title("Discovered Hosts")
                discover_window.geometry("400x300")
                
                text_area = scrolledtext.ScrolledText(
                    discover_window,
                    bg='#1a1a1a',
                    fg='#ffffff',
                    font=('Consolas', 10)
                )
                text_area.pack(fill='both', expand=True, padx=10, pady=10)
                
                text_area.insert(tk.END, f"Hosts in {target}:\n\n")
                for host in hosts:
                    text_area.insert(tk.END, f"{host}\n")
                
                text_area.config(state=tk.DISABLED)
            else:
                messagebox.showinfo("Discovery", "Enter a network range (e.g., 192.168.1.0/24) to discover hosts.")
        except ValueError:
            messagebox.showerror("Error", "Invalid network range")
    
    def run_ping(self):
        host = self.ping_host_var.get()
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Pinging {host}...\n\n")
        
        # Run ping command based on OS
        param = "-n" if sys.platform.lower() == "win32" else "-c"
        command = ["ping", param, "4", host]
        
        try:
            output = subprocess.check_output(command, universal_newlines=True)
            self.ping_result.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.ping_result.insert(tk.END, f"Error: {e}")
    
    def run_traceroute(self):
        host = self.ping_host_var.get()
        self.ping_result.delete(1.0, tk.END)
        self.ping_result.insert(tk.END, f"Tracing route to {host}...\n\n")
        
        # Run traceroute command based on OS
        command = ["tracert", "-d", host] if sys.platform.lower() == "win32" else ["traceroute", host]
        
        try:
            output = subprocess.check_output(command, universal_newlines=True)
            self.ping_result.insert(tk.END, output)
        except subprocess.CalledProcessError as e:
            self.ping_result.insert(tk.END, f"Error: {e}")
        except FileNotFoundError:
            self.ping_result.insert(tk.END, "Traceroute utility not found")
    
    def run_whois(self):
        domain = self.whois_domain_var.get()
        self.whois_result.delete(1.0, tk.END)
        self.whois_result.insert(tk.END, f"WHOIS lookup for {domain}...\n\n")
        
        try:
            whois_info = whois.whois(domain)
            self.whois_result.insert(tk.END, str(whois_info))
        except Exception as e:
            self.whois_result.insert(tk.END, f"Error: {e}")
    
    def run_dns_lookup(self):
        domain = self.dns_domain_var.get()
        record_type = self.dns_type_var.get()
        self.dns_result.delete(1.0, tk.END)
        self.dns_result.insert(tk.END, f"DNS {record_type} lookup for {domain}...\n\n")
        
        try:
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                self.dns_result.insert(tk.END, f"{rdata}\n")
        except dns.resolver.NoAnswer:
            self.dns_result.insert(tk.END, f"No {record_type} records found for {domain}")
        except dns.resolver.NXDOMAIN:
            self.dns_result.insert(tk.END, f"Domain {domain} does not exist")
        except Exception as e:
            self.dns_result.insert(tk.END, f"Error: {e}")
    
    def calculate_subnet(self):
        subnet_str = self.subnet_ip_var.get()
        self.subnet_result.delete(1.0, tk.END)
        
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            self.subnet_result.insert(tk.END, f"Network Address: {network.network_address}\n")
            self.subnet_result.insert(tk.END, f"Broadcast Address: {network.broadcast_address}\n")
            self.subnet_result.insert(tk.END, f"Netmask: {network.netmask}\n")
            self.subnet_result.insert(tk.END, f"Hostmask: {network.hostmask}\n")
            self.subnet_result.insert(tk.END, f"Total Hosts: {network.num_addresses}\n")
            self.subnet_result.insert(tk.END, f"Usable Hosts: {network.num_addresses - 2}\n")
            self.subnet_result.insert(tk.END, f"First Usable: {list(network.hosts())[0]}\n")
            self.subnet_result.insert(tk.END, f"Last Usable: {list(network.hosts())[-1]}\n")
        except ValueError as e:
            self.subnet_result.insert(tk.END, f"Error: {e}")
    
    def load_history(self):
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Add sample history (in a real app, this would load from a file/database)
        sample_history = [
            ("2023-10-15 14:30", "192.168.1.1", "1-1024", "5", "12.5s"),
            ("2023-10-14 09:15", "scanme.nmap.org", "1-1000", "3", "8.2s"),
            ("2023-10-13 16:45", "127.0.0.1", "1-10000", "12", "45.3s")
        ]
        
        for item in sample_history:
            self.history_tree.insert("", "end", values=item)
    
    def clear_history(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
    
    def export_history(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w', newline='') as file:
                    writer = csv.writer(file)
                    writer.writerow(["Date", "Target", "Ports", "Open", "Time"])
                    
                    for item in self.history_tree.get_children():
                        writer.writerow(self.history_tree.item(item)["values"])
                
                messagebox.showinfo("Export", "History exported successfully")
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export: {e}")
    
    def toggle_scan(self):
        if self.scanning:
            self.stop_scan = True
            self.scan_button.config(text="Stopping...", state="disabled")
            self.status_var.set("Stopping...")
        else:
            self.start_scan()
    
    def start_scan(self):
        # Validate inputs
        try:
            target = self.target_var.get()
            
            # Determine port range based on selection
            if self.port_selection_var.get() == "Range":
                start_port = int(self.start_port_var.get())
                end_port = int(self.end_port_var.get())
                ports_to_scan = list(range(start_port, end_port + 1))
            elif self.port_selection_var.get() == "Common":
                ports_to_scan = list(self.common_ports_list.keys())
            else:  # Custom
                ports_str = self.custom_ports_var.get()
                ports_to_scan = []
                for part in ports_str.split(','):
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        ports_to_scan.extend(range(start, end + 1))
                    else:
                        ports_to_scan.append(int(part))
            
            timeout = float(self.timeout_var.get())
            threads = int(self.threads_var.get())
            delay = int(self.delay_var.get())
            retries = int(self.retries_var.get())
            
            if any(p < 1 or p > 65535 for p in ports_to_scan):
                messagebox.showerror("Error", "Invalid port range. Ports must be between 1 and 65535.")
                return
                
            # Resolve target
            try:
                target_ip = socket.gethostbyname(target)
            except socket.gaierror:
                messagebox.showerror("Error", "Could not resolve hostname")
                return
                
        except ValueError:
            messagebox.showerror("Error", "Please enter valid numeric values")
            return
        
        # Start scanning
        self.scanning = True
        self.stop_scan = False
        self.open_ports = []
        self.filtered_ports = 0
        self.scan_button.config(text="Stop Scan")
        self.status_var.set("Scanning...")
        self.progress.config(maximum=len(ports_to_scan), value=0)
        
        # Clear previous results
        self.results_text.delete(1.0, tk.END)
        self.host_info_text.delete(1.0, tk.END)
        self.vuln_text.delete(1.0, tk.END)
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(
            target=self.port_scanner,
            args=(target_ip, ports_to_scan, timeout, threads, delay, retries)
        )
        scan_thread.daemon = True
        scan_thread.start()
    
    def port_scanner(self, target, ports_to_scan, timeout, max_threads, delay, retries):
        start_time = datetime.now()
        total_ports = len(ports_to_scan)
        scanned_count = 0
        
        # Display start message
        self.append_result(f"🔍 Starting {self.scan_type_var.get()} scan on {target}\n", "#4fc3f7")
        self.append_result(f"📊 Scanning {total_ports} ports\n", "#4fc3f7")
        self.append_result(f"⚡ Timeout: {timeout}s | Threads: {max_threads} | Delay: {delay}ms\n", "#4fc3f7")
        self.append_result("-" * 60 + "\n", "#5d5d5d")
        
        # Gather host information
        self.gather_host_info(target)
        
        # Use ThreadPoolExecutor for better thread management
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(self.scan_port, target, port, timeout, retries): port 
                for port in ports_to_scan
            }
            
            # Process results as they complete
            for future in as_completed(future_to_port):
                if self.stop_scan:
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                
                scanned_count += 1
                self.scanned_ports_var.set(f"{scanned_count}/{total_ports}")
                self.progress.config(value=scanned_count)
                
                # Apply delay if specified
                if delay > 0:
                    time.sleep(delay / 1000)
        
        # Calculate and display scan duration
        end_time = datetime.now()
        duration = end_time - start_time
        
        self.append_result("-" * 60 + "\n", "#5d5d5d")
        if self.stop_scan:
            self.append_result("⏹️ Scan stopped by user\n", "#ff9800")
        else:
            self.append_result(f"✅ Scan completed in {duration.total_seconds():.2f} seconds\n", "#4caf50")
            self.append_result(f"🔓 Found {len(self.open_ports)} open ports\n", "#4caf50")
            self.append_result(f"🚫 Found {self.filtered_ports} filtered ports\n", "#ff9800")
            
            if self.open_ports:
                self.append_result("Open ports: " + ", ".join(map(str, sorted(self.open_ports))) + "\n", "#4caf50")
                
                # Check for vulnerabilities
                self.check_vulnerabilities(target)
        
        # Save to history
        self.save_to_history(target, ports_to_scan, duration)
        
        # Reset UI state
        self.scanning = False
        self.root.after(0, self.update_ui_after_scan)
    
    def scan_port(self, target, port, timeout, retries):
        for attempt in range(retries):
            if self.stop_scan:
                return
                
            try:
                # Create socket object
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    
                    # Attempt to connect to the port
                    result = s.connect_ex((target, port))
                    
                    if result == 0:
                        # Port is open
                        self.open_ports.append(port)
                        self.open_ports_var.set(str(len(self.open_ports)))
                        
                        # Get service name if enabled
                        service_name = "Unknown"
                        if self.service_detection_var.get():
                            try:
                                service_name = socket.getservbyport(port, 'tcp')
                            except:
                                # Check our common ports list
                                service_name = self.common_ports_list.get(port, "Unknown")
                        
                        # Get banner if possible
                        banner = self.get_banner(s, port)
                        
                        result_text = f"✅ Port {port:5} | OPEN    | {service_name}"
                        if banner:
                            result_text += f" | {banner}"
                        result_text += "\n"
                        
                        self.append_result(result_text, "#4caf50")
                        break  # Success, no need to retry
                    else:
                        # Port is closed or filtered
                        if attempt == retries - 1:  # Last attempt
                            if self.verbose_var.get():
                                result_text = f"❌ Port {port:5} | CLOSED  |\n"
                                self.append_result(result_text, "#f44336")
                        else:
                            # Might be filtered (firewall dropping packets)
                            self.filtered_ports += 1
                            self.filtered_ports_var.set(str(self.filtered_ports))
                            
            except socket.timeout:
                if attempt == retries - 1:  # Last attempt
                    if self.verbose_var.get():
                        result_text = f"⏱️  Port {port:5} | TIMEOUT |\n"
                        self.append_result(result_text, "#ff9800")
            except Exception as e:
                if attempt == retries - 1:  # Last attempt
                    if self.verbose_var.get():
                        result_text = f"⚠️  Port {port:5} | ERROR   | {str(e)}\n"
                        self.append_result(result_text, "#ff9800")
    
    def get_banner(self, sock, port):
        try:
            # Try to receive banner for common services
            if port in [21, 22, 25, 80, 110, 143, 443]:
                sock.settimeout(1.0)
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner[:100] + "..." if len(banner) > 100 else banner
        except:
            pass
        return None
    
    def gather_host_info(self, target):
        try:
            self.host_info_text.insert(tk.END, f"Host Information for {target}\n")
            self.host_info_text.insert(tk.END, "=" * 40 + "\n\n")
            
            # Get hostname if available
            try:
                hostname = socket.gethostbyaddr(target)[0]
                self.host_info_text.insert(tk.END, f"Hostname: {hostname}\n")
            except:
                self.host_info_text.insert(tk.END, "Hostname: Not available\n")
            
            # Get geographic information (simplified)
            if not target.startswith(('127.', '192.168.', '10.', '172.')):
                try:
                    response = requests.get(f"http://ip-api.com/json/{target}")
                    data = response.json()
                    if data['status'] == 'success':
                        self.host_info_text.insert(tk.END, f"Country: {data.get('country', 'Unknown')}\n")
                        self.host_info_text.insert(tk.END, f"Region: {data.get('regionName', 'Unknown')}\n")
                        self.host_info_text.insert(tk.END, f"City: {data.get('city', 'Unknown')}\n")
                        self.host_info_text.insert(tk.END, f"ISP: {data.get('isp', 'Unknown')}\n")
                except:
                    self.host_info_text.insert(tk.END, "Geolocation: Unable to determine\n")
            
            # OS detection (simplified)
            if self.os_detection_var.get():
                try:
                    # Simple OS detection based on TTL
                    ping = subprocess.Popen(
                        ["ping", "-c", "1", "-W", "1", target],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    out, err = ping.communicate()
                    
                    if "ttl=" in out.decode().lower():
                        ttl = int(out.decode().lower().split("ttl=")[1].split(" ")[0])
                        if ttl <= 64:
                            os_guess = "Linux/Unix"
                        elif ttl <= 128:
                            os_guess = "Windows"
                        else:
                            os_guess = "Other"
                        
                        self.host_info_text.insert(tk.END, f"OS Guess: {os_guess} (TTL: {ttl})\n")
                except:
                    self.host_info_text.insert(tk.END, "OS Detection: Failed\n")
            
            self.host_info_text.insert(tk.END, "\nInformation gathering completed.\n")
            
        except Exception as e:
            self.host_info_text.insert(tk.END, f"Error gathering host information: {e}\n")
    
    def check_vulnerabilities(self, target):
        self.vuln_text.insert(tk.END, f"Vulnerability Assessment for {target}\n")
        self.vuln_text.insert(tk.END, "=" * 50 + "\n\n")
        
        vulnerabilities_found = False
        
        for port in self.open_ports:
            port_str = str(port)
            if port_str in self.vulnerability_db:
                vuln_info = self.vulnerability_db[port_str]
                self.vuln_text.insert(tk.END, f"Port {port} ({vuln_info['service']}):\n", "#ff9800")
                
                for vuln in vuln_info['vulnerabilities']:
                    self.vuln_text.insert(tk.END, f"  - {vuln}\n", "#ff4444")
                    vulnerabilities_found = True
                
                self.vuln_text.insert(tk.END, "\n")
        
        if not vulnerabilities_found:
            self.vuln_text.insert(tk.END, "No known vulnerabilities detected for open ports.\n", "#00C851")
        else:
            self.vuln_text.insert(tk.END, "\nVulnerability assessment completed.\n", "#ff9800")
    
    def save_to_history(self, target, ports, duration):
        scan_info = {
            'date': datetime.now().strftime("%Y-%m-%d %H:%M"),
            'target': target,
            'ports': f"{min(ports)}-{max(ports)}" if len(ports) > 1 else str(ports[0]),
            'open': len(self.open_ports),
            'time': f"{duration.total_seconds():.1f}s"
        }
        
        self.scan_history.append(scan_info)
        
        # Add to history treeview
        self.history_tree.insert("", "end", values=(
            scan_info['date'],
            scan_info['target'],
            scan_info['ports'],
            scan_info['open'],
            scan_info['time']
        ))
    
    def append_result(self, text, color="#ffffff"):
        self.root.after(0, self._append_result, text, color)
    
    def _append_result(self, text, color):
        self.results_text.configure(fg=color)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
    
    def update_ui_after_scan(self):
        self.scan_button.config(text="Start Scan", state="normal")
        self.status_var.set("Ready" if not self.stop_scan else "Stopped")
    
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.host_info_text.delete(1.0, tk.END)
        self.vuln_text.delete(1.0, tk.END)
        self.open_ports_var.set("0")
        self.scanned_ports_var.set("0")
        self.filtered_ports_var.set("0")
        self.open_ports = []
        self.progress.config(value=0)
        self.append_result("🗑️ Results cleared\n\n", "#ba68c8")
    
    def save_results(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    # Write port results
                    file.write("PORT SCAN RESULTS\n")
                    file.write("=================\n\n")
                    file.write(self.results_text.get(1.0, tk.END))
                    file.write("\n\n")
                    
                    # Write host information
                    file.write("HOST INFORMATION\n")
                    file.write("================\n\n")
                    file.write(self.host_info_text.get(1.0, tk.END))
                    file.write("\n\n")
                    
                    # Write vulnerability assessment
                    file.write("VULNERABILITY ASSESSMENT\n")
                    file.write("=======================\n\n")
                    file.write(self.vuln_text.get(1.0, tk.END))
                
                messagebox.showinfo("Save Results", "Results saved successfully")
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save results: {e}")

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
