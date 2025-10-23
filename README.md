# SecToolKit
A modern, all-in-one security toolkit built with Python &amp; CustomTkinter. Includes password generators, hash tools, encoders, QR creator, and more — all in a sleek, animated interface.

# 🔐 Security Toolkit — by Reax7
**A modern, all-in-one cybersecurity toolkit built with Python & CustomTkinter.**  
Generate, test, encode, and secure with style — featuring animations, light/dark themes, and 20 + useful tools for ethical-security and daily coding use.

---

## 🚀 Features
- 🔑 Password & Token Generators  
- 🧠 Password Strength Analyzer  
- 🧩 MD5 / SHA-256 Hash Tools  
- 🧬 Base64 Encoder / Decoder  
- 🎲 Diceware Passphrase Creator  
- 📧 Username & Email Generator  
- 🎨 Color Code Picker  
- 📷 QR Code Generator  
- 🕘 History Log + Export  
- 🌈 Theme Color Picker  
- ☀️ / 🌙 Light & Dark Mode  
- 🔒 Login System (with stored credentials)  
- ⚡ Searchable Tool Menu  
- 🎡 Animated Navigation & Transitions  

All modules are fully offline — no internet required after installation.

---

## 🧰 Installation & Running

### 🪟 Windows
```bash
# 1. Install Python 3.10 or higher from python.org
#    (check "Add Python to PATH" during setup)

# 2. Open Command Prompt in your project folder
cd "C:\Users\<YourName>\Desktop\Token Checker"

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python passchecker.py
🐧 Linux (Ubuntu, Debian, Kali, Arch…)
bash
Code kopieren
sudo apt update && sudo apt install python3 python3-pip -y
cd ~/Desktop/Token\ Checker

# for Kali or externally managed envs
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python3 passchecker.py
💡 Tip: CustomTkinter v5+ works out-of-the-box on Linux GTK-based desktops.

🍎 macOS
bash
Code kopieren
brew install python
cd ~/Desktop/Token\ Checker
pip3 install -r requirements.txt
python3 passchecker.py
⚙️ Requirements
css
Code kopieren
customtkinter
qrcode[pil]
pillow
Install manually if needed:

bash
Code kopieren
pip install customtkinter qrcode[pil] pillow
🧱 Project Structure
bash
Code kopieren
security-toolkit/
├── passchecker.py        # main app
├── requirements.txt
├── README.md
├── .gitignore
└── credentials.txt        # auto-created after first login
🛠️ Troubleshooting
❌ “externally-managed-environment” error
Use a virtual environment (Kali / Debian fix):

bash
Code kopieren
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
❌ QR Code feature not working
Install extras:

bash
Code kopieren
pip install qrcode[pil] pillow
❌ GUI colors look wrong
Update CustomTkinter:

bash
Code kopieren
pip install --upgrade customtkinter
🎨 Customization
Change accent colors or themes in Settings

Toggle between light / dark modes

Adjust startup page in App.show_login()

Fonts and sizes can be tuned via CustomTkinter styles

🧠 How It Works
Security Toolkit runs locally on your device.
All data (like saved logins or generated passwords) are stored in plain text only on your machine.
It does not send or collect any remote information — fully offline and safe for testing or educational use.

🧑‍💻 Author
Reax7
Built with ❤️ and Python + CustomTkinter
If you like it, ⭐ star the repo or fork to contribute!


python passchecker.py
