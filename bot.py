#!/usr/bin/env python3
"""
🦠 VirusTotal Telegram Bot
A Breaking Bad-themed bot that scans files, URLs, and hashes using VirusTotal API.

Author: Syed Sameer
License: MIT (Educational Use Only)
"""

import os
import re
import asyncio
import logging
from datetime import datetime
from dotenv import load_dotenv
from pyrogram import Client, filters
from pyrogram.types import Message
import aiohttp

# ================= CONFIG =================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
TELEGRAM_API_ID = int(os.getenv("TELEGRAM_API_ID", 0))
TELEGRAM_API_HASH = os.getenv("TELEGRAM_API_HASH", "")
BOT_TOKEN = os.getenv("TELEGRAM_TOKEN")

# Fixed: No trailing spaces in URLs
VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB
MAX_CONCURRENT = 4
TIMEOUT = 30
POLL_DELAY = 6
MAX_POLLS = 5
PREPARE_GIF_DURATION = 2  # seconds

# ================= GIFS =================

GIFS = {
    # 📸 Before scanning - Saul Goodman preparing
    "prepare": "https://media.giphy.com/media/QNGHqtEdHDAcgDPJCj/giphy.gif",
    
    # 🔥 During scanning - Walter White "Let him cook"
    "cooking": "https://media.tenor.com/akRQReAe9JoAAAAM/walter-white-let-him-cook.gif",
    
    # 🔴 Malicious result - Walter White "Someone cooked here"
    "danger": "https://tenor.com/dyjRpOuEmXE.gif",
    
    # 🟢 Safe result - Clean/Secure animation
    "safe": "https://media.giphy.com/media/KIpm9dzD2OAK2p60Xu/giphy.gif",
    
    # 🟡 Suspicious result - "That's suspicious" 👀
    "suspicious": "https://media.tenor.com/m/2701645392250261304.gif",
}

scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ================= HELPERS =================

def is_hash(text: str) -> bool:
    """Check if text is a valid hash (MD5/SHA1/SHA256)."""
    return bool(re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", text.strip()))

def is_url(text: str) -> bool:
    """Check if text is a valid URL."""
    return text.strip().startswith(("http://", "https://"))

def format_results(stats: dict, link: str = None) -> tuple:
    """Format VirusTotal results with appropriate GIF and message (plain text)."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        verdict = "🔴 DANGEROUS"
        gif = GIFS["danger"]
        caption_prefix = "⚠️ DANGER DETECTED! ⚠️\n\n"
    elif suspicious > 0:
        verdict = "🟡 SUSPICIOUS"
        gif = GIFS["suspicious"]
        caption_prefix = "⚠️ THAT'S SUSPICIOUS... 👀 ⚠️\n\n"
    else:
        verdict = "🟢 SAFE"
        gif = GIFS["safe"]
        caption_prefix = "✅ SAFE TO USE ✅\n\n"

    msg = (
        f"{caption_prefix}"
        f"🔍 VirusTotal Results\n\n"
        f"🚨 Malicious: {malicious}\n"
        f"⚠️ Suspicious: {suspicious}\n"
        f"✅ Harmless: {harmless}\n"
        f"⏭ Undetected: {undetected}\n\n"
        f"🧾 Verdict: {verdict}"
    )
    
    if link:
        msg += f"\n\n🔗 View Full Report: {link}"
    
    return msg, gif

async def vt_request(session: aiohttp.ClientSession, method: str, url: str, **kwargs) -> tuple:
    """Make a request to VirusTotal API with rate limiting."""
    async with scan_semaphore:
        try:
            async with session.request(
                method,
                url,
                headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=TIMEOUT),
                **kwargs
            ) as resp:
                if resp.status == 429:
                    logger.warning("Rate limited by VirusTotal API")
                    return 429, None
                
                try:
                    data = await resp.json()
                except aiohttp.ContentTypeError:
                    logger.error(f"VirusTotal returned non-JSON response: {resp.status}")
                    return resp.status, None
                
                return resp.status, data
        except asyncio.TimeoutError:
            logger.error("VirusTotal request timeout")
            return None, None
        except Exception as e:
            logger.error(f"VT request error: {e}")
            return None, None

async def poll_analysis(session: aiohttp.ClientSession, analysis_id: str) -> tuple:
    """Poll VirusTotal analysis until complete or max polls reached."""
    for i in range(MAX_POLLS):
        await asyncio.sleep(POLL_DELAY * (2 ** i))
        status, data = await vt_request(session, "GET", f"{VT_BASE}/analyses/{analysis_id}")
        
        if status == 200 and data and data.get("data", {}).get("attributes", {}).get("status") == "completed":
            return status, data
    
    logger.warning(f"Analysis {analysis_id} did not complete within max polls")
    return None, None

# ================= HASH SCAN =================

async def scan_hash(app: Client, message: Message, value: str):
    """Scan a hash (MD5/SHA1/SHA256) using VirusTotal API."""
    prepare_msg = await message.reply_animation(
        animation=GIFS["prepare"],
        caption="📸 Getting ready to scan..."
    )
    await asyncio.sleep(PREPARE_GIF_DURATION)
    
    try:
        await prepare_msg.delete()
    except Exception as e:
        logger.warning(f"Could not delete prepare message: {e}")
    
    cook_msg = await message.reply_animation(
        animation=GIFS["cooking"],
        caption="🔍 Checking hash..."
    )
    
    try:
        async with aiohttp.ClientSession() as session:
            status, data = await vt_request(session, "GET", f"{VT_BASE}/files/{value}")
        
        await cook_msg.delete()
        
        if status == 200:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            vt_link = f"https://www.virustotal.com/gui/file/{value}"
            result_msg, result_gif = format_results(stats, vt_link)
            await message.reply_animation(
                animation=result_gif,
                caption=result_msg
            )
        elif status == 404:
            await message.reply_text("❌ Hash not found in VirusTotal database.")
        else:
            await message.reply_text("❌ Error retrieving hash information.")
    except Exception as e:
        logger.error(f"Hash scan error: {e}")
        await message.reply_text("❌ An error occurred during hash scanning.")
        try:
            await cook_msg.delete()
        except:
            pass

# ================= URL SCAN =================

async def scan_url(app: Client, message: Message, value: str):
    """Scan a URL using VirusTotal API."""
    prepare_msg = await message.reply_animation(
        animation=GIFS["prepare"],
        caption="📸 Preparing to scan URL..."
    )
    await asyncio.sleep(PREPARE_GIF_DURATION)
    
    try:
        await prepare_msg.delete()
    except Exception as e:
        logger.warning(f"Could not delete prepare message: {e}")
    
    cook_msg = await message.reply_animation(
        animation=GIFS["cooking"],
        caption="🔥 Let him cook..."
    )
    
    try:
        async with aiohttp.ClientSession() as session:
            status, submit = await vt_request(session, "POST", f"{VT_BASE}/urls", data={"url": value})
            
            if status != 200:
                await cook_msg.delete()
                await message.reply_text("❌ URL submission failed.")
                return
            
            analysis_id = submit["data"]["id"]
            status, result = await poll_analysis(session, analysis_id)
        
        await cook_msg.delete()
        
        if status == 200:
            stats = result["data"]["attributes"]["stats"]
            vt_link = f"https://www.virustotal.com/gui/url/{analysis_id}"
            result_msg, result_gif = format_results(stats, vt_link)
            await message.reply_animation(
                animation=result_gif,
                caption=result_msg
            )
        elif status == 429:
            await message.reply_text("⏳ VirusTotal API rate limit reached. Please try again later.")
        else:
            await message.reply_text("❌ URL analysis incomplete.")
    except Exception as e:
        logger.error(f"URL scan error: {e}")
        await message.reply_text("❌ An error occurred during URL scanning.")
        try:
            await cook_msg.delete()
        except:
            pass

# ================= FILE SCAN =================

async def scan_file(app: Client, message: Message):
    """Scan an uploaded file using VirusTotal API."""
    doc = message.document
    
    if not doc:
        await message.reply_text("❌ No file found in message.")
        return
    
    if doc.file_size and doc.file_size > MAX_FILE_SIZE:
        size_mb = MAX_FILE_SIZE / (1024 * 1024)
        await message.reply_text(f"❌ File too large (max {size_mb:.0f}MB).")
        return
    
    prepare_msg = await message.reply_animation(
        animation=GIFS["prepare"],
        caption="📸 Preparing to upload file..."
    )
    await asyncio.sleep(PREPARE_GIF_DURATION)
    
    try:
        await prepare_msg.delete()
    except Exception as e:
        logger.warning(f"Could not delete prepare message: {e}")
    
    cook_msg = await message.reply_animation(
        animation=GIFS["cooking"],
        caption="🔥 Uploading & scanning..."
    )
    
    # Fixed: Sanitize filename (replace spaces and special chars)
    safe_filename = doc.file_name.replace(" ", "_").replace("/", "_").replace("\\", "_") if doc.file_name else "uploaded_file"
    temp_name = f"temp_{int(datetime.now().timestamp())}_{safe_filename}"
    
    # Fixed: Use absolute path in home directory
    temp_path = os.path.join(os.path.expanduser("~"), temp_name)
    
    try:
        # Download file with error handling
        logger.info(f"Downloading file to: {temp_path}")
        downloaded_file = await message.download(file_name=temp_path)
        
        # Verify file exists
        if not downloaded_file or not os.path.exists(temp_path):
            raise FileNotFoundError(f"Download failed: {temp_path}")
        
        logger.info(f"File downloaded successfully: {temp_path}")
        
        async with aiohttp.ClientSession() as session:
            with open(temp_path, "rb") as f:
                form = aiohttp.FormData()
                form.add_field("file", f, filename=doc.file_name)
                status, submit = await vt_request(session, "POST", f"{VT_BASE}/files", data=form)
            
            if status != 200:
                await cook_msg.delete()
                await message.reply_text("❌ File upload to VirusTotal failed.")
                return
            
            analysis_id = submit["data"]["id"]
            status, result = await poll_analysis(session, analysis_id)
        
        await cook_msg.delete()
        
        if status == 200:
            stats = result["data"]["attributes"]["stats"]
            vt_link = f"https://www.virustotal.com/gui/file/{analysis_id}"
            result_msg, result_gif = format_results(stats, vt_link)
            await message.reply_animation(
                animation=result_gif,
                caption=result_msg
            )
        elif status == 429:
            await message.reply_text("⏳ VirusTotal API rate limit reached. Please try again later.")
        else:
            await message.reply_text("❌ File analysis incomplete.")
            
    except FileNotFoundError as e:
        logger.error(f"File not found error: {e}")
        await cook_msg.delete()
        await message.reply_text("❌ Failed to download file. Please try again with a smaller file.")
    except PermissionError as e:
        logger.error(f"Permission error: {e}")
        await cook_msg.delete()
        await message.reply_text("❌ Permission denied. Check Termux storage permissions.")
    except Exception as e:
        logger.error(f"File scan error: {e}")
        await cook_msg.delete()
        await message.reply_text("❌ An error occurred during file scanning.")
    finally:
        # Cleanup: Delete temp file
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.info(f"Temp file cleaned up: {temp_path}")
            except Exception as e:
                logger.warning(f"Could not delete temp file {temp_path}: {e}")

# ================= CREATE APP =================

app = Client(
    name="virustotal_bot",
    api_id=TELEGRAM_API_ID,
    api_hash=TELEGRAM_API_HASH,
    bot_token=BOT_TOKEN,
    workers=10,
)

# ================= HANDLERS =================

@app.on_message(filters.command("start"))
async def start_cmd(app: Client, message: Message):
    """Handle /start command."""
    await message.reply_text(
        "👋 VirusTotal Telegram Bot\n\n"
        "Send:\n"
        "• File hash (MD5/SHA1/SHA256)\n"
        "• URL (http/https)\n"
        "• Upload file (≤32MB)\n\n"
        "Powered by VirusTotal API."
    )

@app.on_message(filters.document)
async def handle_document(app: Client, message: Message):
    """Handle document uploads."""
    await scan_file(app, message)

@app.on_message(filters.text)
async def handle_text(app: Client, message: Message):
    """Handle text messages (hash or URL)."""
    text = message.text.strip() if message.text else ""
    
    # Skip commands and empty texts
    if not text or text.startswith("/") or message.edit_date:
        return
    
    if is_hash(text):
        await scan_hash(app, message, text)
    elif is_url(text):
        await scan_url(app, message, text)
    else:
        await message.reply_text("❓ Send a valid hash, URL, or upload a file.")

# ================= MAIN =================

def main():
    """Start the bot."""
    required_vars = ["VT_API_KEY", "TELEGRAM_TOKEN", "TELEGRAM_API_ID", "TELEGRAM_API_HASH"]
    missing = [var for var in required_vars if not os.getenv(var)]
    
    if missing:
        print(f"❌ Missing environment variables: {', '.join(missing)}")
        print("Required: VT_API_KEY, TELEGRAM_TOKEN, TELEGRAM_API_ID, TELEGRAM_API_HASH")
        return
    
    print("🚀 VirusTotal Bot starting...")
    print("🎬 Breaking Bad theme activated!")
    print("👀 'That's suspicious' GIF added!")
    print("📁 File scanning: Termux compatible!")
    app.run()

if __name__ == "__main__":
    main()
