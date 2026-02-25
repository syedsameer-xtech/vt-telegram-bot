import os
import re
import asyncio
import logging
import aiohttp
from datetime import datetime
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    MessageHandler,
    CommandHandler,
    ContextTypes,
    filters,
)

# ================= CONFIG =================

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")

VT_BASE = "https://www.virustotal.com/api/v3"
HEADERS = {"x-apikey": VT_API_KEY}

MAX_FILE_SIZE = 32 * 1024 * 1024  # 32MB
MAX_CONCURRENT = 4
TIMEOUT = 30
POLL_DELAY = 6
MAX_POLLS = 5

COOK_GIF = "https://media.tenor.com/akRQReAe9JoAAAAM/walter-white-let-him-cook.gif"

scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ================= HELPERS =================

def is_hash(text):
    return re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", text)

def is_url(text):
    return text.startswith(("http://", "https://"))

def format_results(stats, link=None):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    verdict = "🟢 CLEAN"
    if malicious > 0:
        verdict = "🔴 MALICIOUS"
    elif suspicious > 0:
        verdict = "🟡 SUSPICIOUS"

    msg = (
        "🔍 **VirusTotal Results**\n\n"
        f"🚨 Malicious: {malicious}\n"
        f"⚠️ Suspicious: {suspicious}\n"
        f"✅ Harmless: {harmless}\n"
        f"⏭ Undetected: {undetected}\n\n"
        f"🧾 Verdict: {verdict}"
    )

    if link:
        msg += f"\n\n🔗 [View Full Report]({link})"

    return msg

async def vt_request(session, method, url, **kwargs):
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
                    return 429, None
                data = await resp.json()
                return resp.status, data
        except Exception as e:
            logger.error(f"VT request error: {e}")
            return None, None

async def poll_analysis(session, analysis_id):
    for i in range(MAX_POLLS):
        await asyncio.sleep(POLL_DELAY * (2 ** i))
        status, data = await vt_request(
            session,
            "GET",
            f"{VT_BASE}/analyses/{analysis_id}",
        )
        if status == 200:
            if data["data"]["attributes"]["status"] == "completed":
                return status, data
    return None, None

# ================= HASH SCAN =================

async def scan_hash(update: Update, value: str):
    await update.message.reply_text("🔍 Checking hash...")

    async with aiohttp.ClientSession() as session:
        status, data = await vt_request(
            session,
            "GET",
            f"{VT_BASE}/files/{value}"
        )

    if status == 200:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        vt_link = f"https://www.virustotal.com/gui/file/{value}"
        await update.message.reply_text(
            format_results(stats, vt_link),
            parse_mode="Markdown"
        )
    elif status == 404:
        await update.message.reply_text("❌ Hash not found.")
    else:
        await update.message.reply_text("❌ Error retrieving hash.")

# ================= URL SCAN =================

async def scan_url(update: Update, value: str):
    cook_msg = await update.message.reply_animation(
        animation=COOK_GIF,
        caption="🔥 Let him cook..."
    )

    async with aiohttp.ClientSession() as session:
        status, submit = await vt_request(
            session,
            "POST",
            f"{VT_BASE}/urls",
            data={"url": value}
        )

        if status != 200:
            await cook_msg.delete()
            await update.message.reply_text("❌ URL submission failed.")
            return

        analysis_id = submit["data"]["id"]
        status, result = await poll_analysis(session, analysis_id)

    await cook_msg.delete()

    if status == 200:
        stats = result["data"]["attributes"]["stats"]
        vt_link = f"https://www.virustotal.com/gui/url/{analysis_id}"
        await update.message.reply_text(
            format_results(stats, vt_link),
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Analysis incomplete.")

# ================= FILE SCAN =================

async def scan_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document

    if doc.file_size > MAX_FILE_SIZE:
        await update.message.reply_text("❌ File too large (max 32MB).")
        return

    cook_msg = await update.message.reply_animation(
        animation=COOK_GIF,
        caption="🔥 Uploading & scanning..."
    )

    file = await doc.get_file()
    temp_name = f"temp_{datetime.now().timestamp()}_{doc.file_name}"
    await file.download_to_drive(temp_name)

    async with aiohttp.ClientSession() as session:
        with open(temp_name, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("file", f, filename=doc.file_name)

            status, submit = await vt_request(
                session,
                "POST",
                f"{VT_BASE}/files",
                data=form
            )

        if status != 200:
            await cook_msg.delete()
            await update.message.reply_text("❌ Upload failed.")
            os.remove(temp_name)
            return

        analysis_id = submit["data"]["id"]
        status, result = await poll_analysis(session, analysis_id)

    os.remove(temp_name)
    await cook_msg.delete()

    if status == 200:
        stats = result["data"]["attributes"]["stats"]
        vt_link = f"https://www.virustotal.com/gui/file/{analysis_id}"
        await update.message.reply_text(
            format_results(stats, vt_link),
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text("❌ Analysis incomplete.")

# ================= ROUTER =================

async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    if is_hash(text):
        await scan_hash(update, text)
    elif is_url(text):
        await scan_url(update, text)
    else:
        await update.message.reply_text(
            "❓ Send a valid hash, URL, or upload a file."
        )

# ================= COMMANDS =================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 **VirusTotal Telegram Bot**\n\n"
        "Send:\n"
        "• File hash\n"
        "• URL\n"
        "• Upload file (≤32MB)\n\n"
        "Powered by VirusTotal API.",
        parse_mode="Markdown"
    )

async def error_handler(update, context):
    logger.error(f"Error: {context.error}")

# ================= MAIN =================

def main():
    if not VT_API_KEY or not TELEGRAM_TOKEN:
        print("❌ Missing .env keys!")
        return

    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, scan_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    app.add_error_handler(error_handler)

    print("🚀 Bot running...")
    app.run_polling()

if __name__ == "__main__":
    main()
