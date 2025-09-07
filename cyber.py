import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import queue
import subprocess
import os
import random
import sys
import re

# --- Fact Database ---
SECURITY_FACTS = [
    "Fact: ARP spoofing, also known as ARP cache poisoning, is a malicious attack in which an attacker sends falsified ARP messages over a local area network. This can allow the attacker to intercept, modify, or stop data in transit.",
    "Fact: The 'root' user on Linux and the 'Administrator' on Windows are examples of privileged accounts. An attacker's ultimate goal is often to gain control of one of these accounts, which is called 'privileged escalation'.",
    "Fact: A firewall is a network security device that monitors and filters incoming and outgoing network traffic based on an organization's previously established security policies.",
    "Fact: The 'netstat' command (network statistics) is a command-line tool that displays network connections, routing tables, interface statistics, and open ports.",
    "Fact: Common ports include HTTP (80), HTTPS (443), SSH (22), FTP (21), and DNS (53). Each port is tied to a specific service or application.",
    "Fact: A 'ping' command sends an ICMP (Internet Control Message Protocol) Echo Request to a host. It is often used to test reachability and latency of a network host.",
    "Fact: SUID (Set User ID) and SGID (Set Group ID) are special file permissions on Unix-like operating systems. They allow a user to run an executable with the permissions of the file owner (or group), which can be a security risk if not managed properly.",
    "Fact: A SYN flood is a form of denial-of-service attack in which an attacker sends a succession of SYN requests to a target's system in an attempt to consume enough server resources to make the system unresponsive to legitimate traffic.",
    "Fact: A 'kill chain' is a model used to describe the stages of a cyber attack, from initial reconnaissance to the exfiltration of data.",
    "Fact: The principle of 'least privilege' states that an individual, a process, or a program should have only the bare minimum privileges necessary to perform its function."
]

class SecurityToolkit(tk.Tk):
    """
    A basic cybersecurity toolkit with a GUI to perform simple port scanning,
    ARP table checks, and other security-related tasks.
    """
    def __init__(self):
        super().__init__()
        self.title("Security Toolkit")
        self.geometry("800x600")
        self.configure(bg="#2c3e50")
        self.create_widgets()

        # Initialize threading queue
        self.scan_queue = queue.Queue()

    def create_widgets(self):
        """Creates all the GUI widgets and layouts."""
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('TFrame', background='#34495e')
        style.configure('TButton', font=('Helvetica', 12, 'bold'), borderwidth=1, relief="flat", padding=10)
        style.map('TButton', background=[('active', '#e74c3c')])
        style.configure('TLabel', background='#34495e', foreground='#ecf0f1', font=('Helvetica', 12, 'bold'))
        style.configure('TEntry', fieldbackground='#ecf0f1', foreground='#2c3e50')
        style.configure('TScrolledText', background='#2c3e50', foreground='#ecf0f1', insertbackground='#ecf0f1')

        main_frame = ttk.Frame(self, padding="20 20 20 20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title Label
        title_label = ttk.Label(main_frame, text="Security Toolkit", font=('Helvetica', 20, 'bold'), foreground="#f39c12")
        title_label.pack(pady=(0, 20))

        # Input and Controls Frame
        controls_frame = ttk.Frame(main_frame, padding="10")
        controls_frame.pack(fill=tk.X, pady=(0, 10))

        # Target IP and Port input for Port Scanner
        ttk.Label(controls_frame, text="Target IP:").pack(side=tk.LEFT, padx=(0, 5))
        self.ip_entry = ttk.Entry(controls_frame, width=20)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Label(controls_frame, text="Ports (e.g., 1-100):").pack(side=tk.LEFT, padx=(0, 5))
        self.port_entry = ttk.Entry(controls_frame, width=15)
        self.port_entry.insert(0, "1-100")
        self.port_entry.pack(side=tk.LEFT, padx=(0, 10))

        # Action buttons
        scan_button = ttk.Button(controls_frame, text="Scan Ports", command=self.start_scan)
        scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # New "Port Closer" section
        port_closer_frame = ttk.Frame(main_frame, padding="10")
        port_closer_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(port_closer_frame, text="Port to Close:").pack(side=tk.LEFT, padx=(0, 5))
        self.close_port_entry = ttk.Entry(port_closer_frame, width=10)
        self.close_port_entry.pack(side=tk.LEFT, padx=(0, 10))
        close_button = ttk.Button(port_closer_frame, text="Find and Close", command=self.find_and_close_port)
        close_button.pack(side=tk.LEFT)

        arp_button = ttk.Button(main_frame, text="Check ARP Table", command=self.check_arp_table)
        arp_button.pack(fill=tk.X, pady=(0, 10))

        privesc_button = ttk.Button(main_frame, text="Check for Privileges", command=self.check_privilege_escalation)
        privesc_button.pack(fill=tk.X, pady=(0, 10))

        fact_button = ttk.Button(main_frame, text="Get Security Fact", command=self.display_fact)
        fact_button.pack(fill=tk.X, pady=(0, 10))

        # Output text area
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill=tk.BOTH, expand=True)
        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, bg='#2c3e50', fg='#ecf0f1', font=('Consolas', 10), relief=tk.FLAT)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        self.output_text.insert(tk.END, "Welcome to the Cybersecurity Toolkit!\n\nThis application is for educational purposes only. Always have permission before scanning any network or system that you do not own or manage.")
        self.output_text.config(state=tk.DISABLED)

    def log(self, message):
        """Helper function to append messages to the output text widget."""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, f"\n\n{message}")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def start_scan(self):
        """Validates input and starts the port scanning process in a new thread."""
        target_ip = self.ip_entry.get()
        port_range_str = self.port_entry.get()

        if not target_ip or not port_range_str:
            self.log("Error: Please enter a target IP and port range.")
            return

        try:
            start_port, end_port = map(int, port_range_str.split('-'))
            if start_port > end_port:
                raise ValueError
        except (ValueError, IndexError):
            self.log("Error: Invalid port range format. Please use 'start-end' (e.g., 1-100).")
            return

        self.log(f"Starting port scan for {target_ip} on ports {start_port}-{end_port}...")
        
        # Disable buttons to prevent multiple scans
        self.set_buttons_state(tk.DISABLED)

        # Start a new thread for the scan to prevent GUI freeze
        thread = threading.Thread(target=self.port_scan_worker, args=(target_ip, start_port, end_port))
        thread.daemon = True
        thread.start()
        
        # Start a thread to poll the queue for results
        self.poll_queue()

    def set_buttons_state(self, state):
        """Helper function to set the state of all buttons."""
        for widget in self.winfo_children():
            if isinstance(widget, ttk.Frame):
                for sub_widget in widget.winfo_children():
                    if isinstance(sub_widget, ttk.Button):
                        sub_widget.config(state=state)

    def port_scan_worker(self, target_ip, start_port, end_port):
        """Worker thread for port scanning."""
        open_ports = []
        for port in range(start_port, end_port + 1):
            try:
                # Create a socket object
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1) # Timeout in seconds

                # Attempt to connect to the port
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    self.scan_queue.put(f"Port {port} is OPEN.")
                
                sock.close()
            except socket.gaierror:
                self.scan_queue.put(f"Error: Hostname could not be resolved for {target_ip}. Stopping scan.")
                break # Break the loop, as subsequent ports will also fail
            except socket.error:
                # Log the error but continue to the next port
                self.scan_queue.put(f"Connection error on port {port}. Continuing scan.")
        
        self.scan_queue.put("Scan finished.")

    def poll_queue(self):
        """Polls the queue for results from the port scan worker thread."""
        try:
            while not self.scan_queue.empty():
                message = self.scan_queue.get(block=False)
                self.log(message)
                if message == "Scan finished.":
                    self.set_buttons_state(tk.NORMAL)
                    return
        except queue.Empty:
            pass
        self.after(100, self.poll_queue) # Check again in 100ms

    def find_and_close_port(self):
        """
        Finds the process listening on a given port and provides instructions to close it.
        This is a demonstration of how to implement the "port closer" functionality.
        It does not automatically kill the process.
        """
        port_to_close = self.close_port_entry.get().strip()
        if not port_to_close.isdigit():
            self.log("Error: Please enter a valid port number.")
            return

        self.log(f"Attempting to find process on port {port_to_close}...")
        
        try:
            if os.name == 'nt': # Windows
                # Use netstat to find PID
                command = f'netstat -ano | findstr ":{port_to_close} LISTEN"'
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                output = result.stdout.strip()

                if not output:
                    self.log(f"No process found listening on port {port_to_close}.")
                    return

                # Parse output to find PID
                lines = output.split('\n')
                for line in lines:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        protocol, local_address, foreign_address, state, pid = parts
                        self.log(f"Found process with PID {pid} listening on port {port_to_close}.")
                        self.log(f"To terminate this process, open an elevated Command Prompt (Run as Administrator) and run: taskkill /PID {pid} /F")
                        return

            else: # Linux/macOS
                # Use lsof to find PID
                command = ["sudo", "lsof", "-i", f"tcp:{port_to_close}"]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                output = result.stdout.strip()
                
                if not output:
                    self.log(f"No process found listening on port {port_to_close}.")
                    return

                # Parse output to find PID
                lines = output.split('\n')
                if len(lines) > 1: # The first line is the header
                    line = lines[1]
                    parts = re.split(r'\s+', line)
                    pid = parts[1]
                    self.log(f"Found process with PID {pid} listening on port {port_to_close}.")
                    self.log(f"To terminate this process, open a terminal and run: sudo kill -9 {pid}")
                    return
            
            self.log(f"Error: Could not find process information for port {port_to_close}. You may need to run this as an administrator or with 'sudo'.")

        except subprocess.CalledProcessError as e:
            self.log(f"Error executing command: {e.stderr}. This operation requires administrator privileges.")
        except FileNotFoundError:
            self.log(f"Error: '{'netstat' if os.name == 'nt' else 'lsof'}' command not found. Please ensure it is in your system's PATH.")


    def check_arp_table(self):
        """Executes the `arp -a` command to check the ARP table and logs the output."""
        self.log("Checking ARP table. This requires proper permissions.")
        
        try:
            if os.name == 'nt':
                command = ["arp", "-a"]
            else:
                command = ["arp", "-a"]
            
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            output = result.stdout
            
            self.log("--- ARP Table Analysis ---")
            
            # Use regex for more reliable parsing
            # Matches IP and MAC addresses in the format 127.0.0.1 00-00-00-00-00-00
            pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})")
            
            mac_to_ips = {}
            for line in output.splitlines():
                match = pattern.search(line)
                if match:
                    ip, mac = match.groups()
                    mac = mac.replace('-', ':').lower() # Normalize MAC format
                    if mac not in mac_to_ips:
                        mac_to_ips[mac] = []
                    mac_to_ips[mac].append(ip)

            spoofing_detected = False
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1:
                    self.log(f"WARNING: Potential ARP Spoofing! MAC Address {mac} is associated with multiple IP addresses: {', '.join(ips)}")
                    spoofing_detected = True
            
            if not spoofing_detected:
                self.log("No signs of ARP spoofing detected (based on simple MAC-IP checks).")

            self.log("\n--- Full ARP Table Output ---")
            self.log(output)

        except subprocess.CalledProcessError as e:
            self.log(f"Error executing command: {e.stderr}. You may need to run this script as an administrator or with 'sudo'.")
        except FileNotFoundError:
            self.log("Error: 'arp' command not found. Please ensure it's in your system's PATH.")
    
    def check_privilege_escalation(self):
        """
        Performs a basic, educational check for common privilege escalation vectors.
        This is a very simple check and not a comprehensive security audit.
        """
        self.log("Performing a basic check for potential privilege escalation vectors...")
        
        # Check for SUID/SGID files (Linux/macOS)
        if sys.platform != 'win32':
            try:
                self.log("Checking for SUID/SGID binaries (a common privesc vector)...")
                # Find all SUID/SGID files and ignore common ones to reduce noise
                command = "find / -type f \\( -perm -4000 -o -perm -2000 \\) -exec ls -ld {} \\; 2>/dev/null"
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
                output = result.stdout.strip()

                if output:
                    self.log("\nWARNING: The following SUID/SGID binaries were found. These are potential security risks if misconfigured:")
                    self.log(output)
                    self.log("Examine each binary to ensure it's a legitimate system file and not a malicious one.")
                else:
                    self.log("No non-standard SUID/SGID binaries found. (This check is not exhaustive).")
            except subprocess.CalledProcessError as e:
                self.log(f"Error checking for SUID/SGID binaries: {e.stderr}. You may need to run this script with 'sudo'.")
        else:
            self.log("SUID/SGID checks are not applicable to Windows. Checking for common vulnerabilities instead.")
            self.log("On Windows, common privilege escalation vectors include unquoted service paths and weak service permissions.")
            
            # Simple check for weak folder permissions (e.g., world-writable)
            self.log("\nChecking C:\\ directory permissions...")
            try:
                output = subprocess.check_output('icacls "C:\\"', shell=True, text=True)
                if "Everyone:(" in output:
                    self.log("WARNING: The C:\\ drive has permissions for 'Everyone'. This is a potential security risk.")
                else:
                    self.log("C:\\ permissions appear normal (based on simple check).")
            except subprocess.CalledProcessError:
                self.log("Could not check permissions. Run as administrator to check.")


        self.log("\nPrivilege escalation check complete.")


    def display_fact(self):
        """Displays a random security fact."""
        fact = random.choice(SECURITY_FACTS)
        self.log(f"--- Security Fact ---\n{fact}")

if __name__ == "__main__":
    try:
        app = SecurityToolkit()
        app.mainloop()
    except Exception as e:
        print(f"An unhandled error occurred: {e}")
