🔧 System Requirements
✅ Supported Operating Systems
Windows 10/11 (x64)

Ubuntu 20.04/22.04 or newer

Kali Linux, Parrot OS (optional for security testing)

🧰 Linux Dependencies
Make sure to install the following packages before running Burt Army:

bash
Copy
Edit
sudo apt update && sudo apt install -y \
  python3 python3-pip \
  xterm nmap curl \
  libpcap-dev build-essential \
  git net-tools
💡 You may also need gnome-terminal or xfce4-terminal depending on your desktop environment.

🧰 Windows Requirements
✅ Python 3.10+

✅ Git for Windows

✅ Optional: Nmap (if you want port scanning)

✅ Powershell v5.1 or higher

Optional: Npcap if using raw socket functions

📦 Python Dependencies
After cloning the repository, install Python dependencies with:

bash
Copy
Edit
pip install -r requirements.txt
If you don’t have pip, install it first:

bash
Copy
Edit
sudo apt install python3-pip  # for Linux
