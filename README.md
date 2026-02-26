# 🦠 VirusTotal Telegram Bot

<div align="center">

🎬 **Breaking Bad–Themed Malware Scanner Bot**  
Saul prepares → Walter cooks → Results reveal 🔬

A Telegram bot that scans **files, URLs, and hashes** using the VirusTotal API.

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

</div>

---

## ✨ Features

- 🔍 **Hash Lookup** — MD5, SHA1, SHA256
- 🔗 **URL Analysis** — Detect malware & phishing
- 📁 **File Scanning** — Upload files up to 32MB
- 🎬 **Breaking Bad GIF Flow**
  - Saul: “Getting ready…”
  - Walter: “Let him cook…”
  - Final result reveal
- ⚡ **Async & Fast** — Built with Pyrogram + aiohttp
- 🔐 Secure environment variable handling

---

## 🚀 Quick Start

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/vt-telegram-bot.git
cd vt-telegram-bot
2️⃣ Install Dependencies
pip install -r requirements.txt
3️⃣ Configure Environment Variables
cp .env.example .env
nano .env

Fill in your keys:

Variable	Description	Where to Get
VT_API_KEY	VirusTotal API key	https://virustotal.com

TELEGRAM_TOKEN	Bot token	@BotFather
TELEGRAM_API_ID	Telegram API ID	https://my.telegram.org

TELEGRAM_API_HASH	Telegram API Hash	https://my.telegram.org

⚠️ Never commit your .env file.

4️⃣ Run the Bot
python3 app.py

Your bot is now live 🚀

📖 Usage

Send any of the following to your bot:

Input Type	Example
Hash	d41d8cd98f00b204e9800998ecf8427e
URL	https://example.com
File	Upload file (≤32MB)
Command	/start
🎬 How It Works
User sends URL / File / Hash
        ↓
📸 Saul GIF — "Getting ready..."
        ↓
🔥 Walter GIF — "Let him cook..."
        ↓
🟢 Safe
🟡 Suspicious
🔴 Dangerous
📂 Project Structure
vt-telegram-bot/
├── app.py              # Main bot logic
├── requirements.txt    # Dependencies
├── .env.example        # Environment template
├── .gitignore          # Git ignore rules
├── README.md           # Documentation
└── LICENSE             # MIT License
⚠️ Important Notes

❌ Max file size: 32MB (VirusTotal limit)

⏱ Free API rate limit: 4 requests/minute

🔐 Never commit .env

🗑 Files are not stored permanently

🛠 Troubleshooting
Issue	Fix
Missing environment variables	Check .env file
Invalid bot token	Regenerate from @BotFather
Rate limit exceeded	Wait a few minutes
Hash not found	Upload the actual file
📦 Dependencies
pyrogram>=2.0.106
aiohttp>=3.9.0
python-dotenv>=1.0.0
TgCrypto>=1.2.5
🤝 Contributing

Fork the repository

Create a new branch

git checkout -b feature/amazing-feature

Commit your changes

git commit -m "✨ Add amazing feature"

Push

git push origin feature/amazing-feature

Open a Pull Request

📜 License

MIT License — see the LICENSE file for details.

⚠️ Disclaimer

This project is for educational and legitimate security purposes only.
The developers are not responsible for misuse.

<div align="center">

🧠 Concept & Prompt Engineering by Syed Sameer
🤖 Developed with AI assistance
🛡 Powered by VirusTotal API

⭐ Star this repo if you found it useful!

</div> ```
