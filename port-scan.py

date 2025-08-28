#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from datetime import datetime
import sv_ttk  # Modern theme for tkinter

class PortScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Port Scanner Pro")
        self.root.geometry("1000x750")
        self.root.minsize(900, 650)
        
        # Set dark theme
        sv_ttk.set_theme("dark")
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'))
        self.style.configure('Subtitle.TLabel', font=('Segoe UI', 11))
        self.style.configure('Accent.TButton', font=('Segoe UI', 10, 'bold'))
        self.style.configure('Card.TFrame', background='#1c1c1c')
        
        # Variables
        self.scanning = False
        self.stop_scan = False
        self.open_ports = []
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main container
        main_container = ttk.Frame(self.root, padding=15)
        main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Header
        header_frame = ttk.Frame(main_container)
        header_frame.grid(row=0, column=0, columnspan=2, pady=(0, 20), sticky=(tk.W, tk.E))
        
        ttk.Label(header_frame, text="🚀 Port Scanner Pro", style='Header.TLabel').grid(row=0, column=0, sticky=tk.W)
        ttk.Label(header_frame, text="Advanced network scanning tool for security professionals", 
                 style='Subtitle.TLabel').grid(row=1, column=0, sticky=tk.W, pady=(5, 0))
        
        # Left panel - Controls
        control_frame = ttk.LabelFrame(main_container, text="Scan Configuration", padding=15)
        control_frame.grid(row=1, column=0, sticky=(tk.N, tk.S, tk.W), padx=(0, 10))
        
        # Target input
        ttk.Label(control_frame, text="Target Host", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        self.target_var = tk.StringVar(value="127.0.0.1")
        target_entry = ttk.Entry(control_frame, textvariable=self.target_var, width=25, font=('Segoe UI', 10))
        target_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        # Port range
        ttk.Label(control_frame, text="Port Range", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky=tk.W, pady=(0, 5))
        port_range_frame = ttk.Frame(control_frame)
        port_range_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 15))
        
        self.start_port_var = tk.StringVar(value="1")
        start_port_entry = ttk.Entry(port_range_frame, textvariable=self.start_port_var, width=8, font=('Segoe UI', 10))
        start_port_entry.grid(row=0, column=0)
        
        ttk.Label(port_range_frame, text="—").grid(row=0, column=1, padx=5)
        
        self.end_port_var = tk.StringVar(value="1024")
        end_port_entry = ttk.Entry(port_range_frame, textvariable=self.end_port_var, width=8, font=('Segoe UI', 10))
        end_port_entry.grid(row=0, column=2)
        
        # Common ports checkbox
        self.common_ports_var = tk.BooleanVar(value=False)
        common_ports_cb = ttk.Checkbutton(control_frame, text="Scan common ports only (1-1024)", 
                                         variable=self.common_ports_var,
                                         command=self.toggle_common_ports)
        common_ports_cb.grid(row=4, column=0, sticky=tk.W, pady=(0, 15))
        
        # Advanced settings
        advanced_frame = ttk.Frame(control_frame)
        advanced_frame.grid(row=5, column=0, sticky=(tk.W, tk.E), pady=(0, 20))
        
        ttk.Label(advanced_frame, text="Timeout (s):", font=('Segoe UI', 9)).grid(row=0, column=0, sticky=tk.W)
        self.timeout_var = tk.StringVar(value="0.5")
        timeout_entry = ttk.Entry(advanced_frame, textvariable=self.timeout_var, width=8, font=('Segoe UI', 9))
        timeout_entry.grid(row=0, column=1, padx=(5, 15))
        
        ttk.Label(advanced_frame, text="Threads:", font=('Segoe UI', 9)).grid(row=0, column=2, sticky=tk.W)
        self.threads_var = tk.StringVar(value="100")
        threads_entry = ttk.Entry(advanced_frame, textvariable=self.threads_var, width=8, font=('Segoe UI', 9))
        threads_entry.grid(row=0, column=3)
        
        # Options
        self.verbose_var = tk.BooleanVar(value=False)
        verbose_cb = ttk.Checkbutton(control_frame, text="Show closed ports", variable=self.verbose_var)
        verbose_cb.grid(row=6, column=0, sticky=tk.W, pady=(0, 20))
        
        # Action buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.grid(row=7, column=0, sticky=(tk.W, tk.E))
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.toggle_scan, style='Accent.TButton')
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT)
        
        # Right panel - Results
        results_frame = ttk.LabelFrame(main_container, text="Scan Results", padding=10)
        results_frame.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(10, 0))
        
        # Results text area with custom styling
        self.results_text = scrolledtext.ScrolledText(
            results_frame, 
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
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Progress bar
        self.progress = ttk.Progressbar(results_frame, mode='indeterminate')
        self.progress.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        # Statistics frame
        stats_frame = ttk.Frame(results_frame)
        stats_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        ttk.Label(stats_frame, text="Open ports:").grid(row=0, column=0, sticky=tk.W)
        self.open_ports_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.open_ports_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=1, sticky=tk.W, padx=(5, 15))
        
        ttk.Label(stats_frame, text="Scanned:").grid(row=0, column=2, sticky=tk.W)
        self.scanned_ports_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.scanned_ports_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=3, sticky=tk.W, padx=(5, 15))
        
        ttk.Label(stats_frame, text="Status:").grid(row=0, column=4, sticky=tk.W)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(stats_frame, textvariable=self.status_var, font=('Segoe UI', 9, 'bold')).grid(row=0, column=5, sticky=tk.W, padx=(5, 0))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_container.columnconfigure(1, weight=1)
        main_container.rowconfigure(1, weight=1)
        control_frame.rowconfigure(7, weight=1)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        
        # Initialize
        self.append_result("🚀 Port Scanner Pro initialized\n", "#4fc3f7")
        self.append_result("Enter target and port range to begin scanning\n\n", "#ba68c8")
        
    def toggle_common_ports(self):
        if self.common_ports_var.get():
            self.start_port_var.set("1")
            self.end_port_var.set("1024")
        
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
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            timeout = float(self.timeout_var.get())
            threads = int(self.threads_var.get())
            
            if start_port < 1 or end_port > 65535 or start_port > end_port:
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
        self.scan_button.config(text="Stop Scan")
        self.status_var.set("Scanning...")
        self.progress.start(10)
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(
            target=self.port_scanner,
            args=(target_ip, start_port, end_port, timeout, threads)
        )
        scan_thread.daemon = True
        scan_thread.start()
    
    def port_scanner(self, target, start_port, end_port, timeout, max_threads):
        start_time = datetime.now()
        total_ports = end_port - start_port + 1
        scanned_count = 0
        
        # Display start message
        self.append_result(f"🔍 Starting scan on {target}\n", "#4fc3f7")
        self.append_result(f"📊 Port range: {start_port}-{end_port} ({total_ports} ports)\n", "#4fc3f7")
        self.append_result(f"⚡ Timeout: {timeout}s | Threads: {max_threads}\n", "#4fc3f7")
        self.append_result("-" * 60 + "\n", "#5d5d5d")
        
        # Semaphore to control the number of concurrent threads
        thread_semaphore = threading.Semaphore(max_threads)
        
        def scan_port_with_semaphore(port):
            nonlocal scanned_count
            if self.stop_scan:
                return
                
            thread_semaphore.acquire()
            try:
                self.scan_port(target, port, timeout)
                scanned_count += 1
                self.scanned_ports_var.set(f"{scanned_count}/{total_ports}")
            finally:
                thread_semaphore.release()
        
        # Create and start threads
        threads = []
        for port in range(start_port, end_port + 1):
            if self.stop_scan:
                break
                
            t = threading.Thread(target=scan_port_with_semaphore, args=(port,))
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            if self.stop_scan:
                break
            t.join()
        
        # Calculate and display scan duration
        end_time = datetime.now()
        duration = end_time - start_time
        
        self.append_result("-" * 60 + "\n", "#5d5d5d")
        if self.stop_scan:
            self.append_result("⏹️ Scan stopped by user\n", "#ff9800")
        else:
            self.append_result(f"✅ Scan completed in {duration.total_seconds():.2f} seconds\n", "#4caf50")
            self.append_result(f"🔓 Found {len(self.open_ports)} open ports\n", "#4caf50")
            
            if self.open_ports:
                self.append_result("Open ports: " + ", ".join(map(str, sorted(self.open_ports))) + "\n", "#4caf50")
        
        # Reset UI state
        self.scanning = False
        self.root.after(0, self.update_ui_after_scan)
    
    def scan_port(self, target, port, timeout):
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
                    try:
                        service = socket.getservbyport(port, 'tcp')
                        result_text = f"✅ Port {port:5} | OPEN    | {service}\n"
                        self.append_result(result_text, "#4caf50")
                    except:
                        result_text = f"✅ Port {port:5} | OPEN    | Unknown service\n"
                        self.append_result(result_text, "#4caf50")
                elif self.verbose_var.get():
                    result_text = f"❌ Port {port:5} | CLOSED  |\n"
                    self.append_result(result_text, "#f44336")
                    
        except Exception as e:
            if self.verbose_var.get():
                result_text = f"⚠️  Port {port:5} | ERROR   | {str(e)}\n"
                self.append_result(result_text, "#ff9800")
    
    def append_result(self, text, color="#ffffff"):
        self.root.after(0, self._append_result, text, color)
    
    def _append_result(self, text, color):
        self.results_text.configure(fg=color)
        self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
    
    def update_ui_after_scan(self):
        self.scan_button.config(text="Start Scan", state="normal")
        self.progress.stop()
        self.status_var.set("Ready" if not self.stop_scan else "Stopped")
    
    def clear_results(self):
        self.results_text.delete(1.0, tk.END)
        self.open_ports_var.set("0")
        self.scanned_ports_var.set("0")
        self.open_ports = []
        self.append_result("🗑️ Results cleared\n\n", "#ba68c8")

def main():
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
