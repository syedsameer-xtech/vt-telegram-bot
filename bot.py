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
    "prepare": "https://media.giphy.com/media/QNGHqtEdHDAcgDPJCj/giphy.gif",
    "cooking": "https://media.tenor.com/akRQReAe9JoAAAAM/walter-white-let-him-cook.gif",
    "danger": "https://media.giphy.com/media/2lu3fIfUbfTStOIXx1/giphy.gif",
    "safe": "https://media.giphy.com/media/KIpm9dzD2OAK2p60Xu/giphy.gif",
    "suspicious": "https://media.tenor.com/mH8K9vLqJ5kAAAAM/thinking-hmm.gif",
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
    """Format VirusTotal results with appropriate GIF and message."""
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    if malicious > 0:
        verdict = "🔴 DANGEROUS"
        gif = GIFS["danger"]
        caption_prefix = "⚠️ **DANGER DETECTED!** ⚠️\n\n"
    elif suspicious > 0:
        verdict = "🟡 SUSPICIOUS"
        gif = GIFS["suspicious"]
        caption_prefix = "⚠️ **SUSPICIOUS FILE/URL** ⚠️\n\n"
    else:
        verdict = "🟢 SAFE"
        gif = GIFS["safe"]
        caption_prefix = "✅ **SAFE TO USE** ✅\n\n"

    msg = (
        f"{caption_prefix}"
        "🔍 **VirusTotal Results**\n\n"
        f"🚨 Malicious: {malicious}\n"
        f"⚠️ Suspicious: {suspicious}\n"
        f"✅ Harmless: {harmless}\n"
        f"⏭ Undetected: {undetected}\n\n"
        f"🧾 Verdict: {verdict}"
    )
    
    if link:
        msg += f"\n\n🔗 [View Full Report]({link})"
    
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
                caption=result_msg,
                parse_mode="Markdown"
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
                caption=result_msg,
                parse_mode="Markdown"
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
    
    temp_name = f"temp_{datetime.now().timestamp()}_{doc.file_name}"
    
    try:
        await message.download(file_name=temp_name)
        
        async with aiohttp.ClientSession() as session:
            with open(temp_name, "rb") as f:
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
                caption=result_msg,
                parse_mode="Markdown"
            )
        elif status == 429:
            await message.reply_text("⏳ VirusTotal API rate limit reached. Please try again later.")
        else:
            await message.reply_text("❌ File analysis incomplete.")
    except Exception as e:
        logger.error(f"File scan error: {e}")
        await message.reply_text("❌ An error occurred during file scanning.")
        try:
            await cook_msg.delete()
        except:
            pass
    finally:
        if os.path.exists(temp_name):
            try:
                os.remove(temp_name)
            except Exception as e:
                logger.warning(f"Could not delete temp file {temp_name}: {e}")

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
        "👋 **VirusTotal Telegram Bot**\n\n"
        "Send:\n"
        "• File hash (MD5/SHA1/SHA256)\n"
        "• URL (http/https)\n"
        "• Upload file (≤32MB)\n\n"
        "Powered by VirusTotal API.",
        parse_mode="Markdown"
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
    app.run()

if __name__ == "__main__":
    main()
