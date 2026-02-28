#!/usr/bin/env python3
"""
🦠 VirusTotal Telegram Bot
Breaking Bad & Better Call Saul Edition — v3.0

What makes this better than the website:
  • Risk score 0–100 so you understand severity instantly
  • Engine breakdown — see WHICH antivirus flagged it, not just a number
  • Plain-English explanation — no jargon, just the truth
  • First seen / last seen dates — is this a fresh threat or old news?
  • Threat category labels — phishing, trojan, ransomware, etc.
  • Rescan button — force a fresh scan any time
  • Share button — forward the verdict card to anyone
  • Watchlist — monitor a URL or IP, get alerted the moment it turns dangerous
  • Personal report (/report) — your full threat history with BB-themed commentary
  • Multiple random BB/BCS GIFs — never the same twice

Install:
  pip install python-telegram-bot aiohttp aiosqlite python-dotenv

Setup:
  1. Copy .env.example to .env and fill in your two keys
  2. pip install -r requirements.txt
  3. python vt_bot.py
"""

import os
import re
import asyncio
import logging
import hashlib
import base64
import ipaddress
import random
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

import aiohttp
import aiosqlite
from dotenv import load_dotenv
from telegram import Update, InlineKeyboardMarkup, InlineKeyboardButton
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    CallbackQueryHandler,
    ContextTypes,
    filters,
)
from telegram.constants import ParseMode

# ─────────────────────────────────────────────────────────────
# 1. CONFIG
# ─────────────────────────────────────────────────────────────
load_dotenv()

VT_KEY        = os.getenv("VT_API_KEY",        "").strip()
TG_TOKEN      = os.getenv("TELEGRAM_TOKEN",    "").strip()
MAX_MB        = int(os.getenv("MAX_FILE_SIZE_MB", "32"))
RATE_PER_HOUR = int(os.getenv("RATE_LIMIT",    "10"))
MAX_WATCHLIST = int(os.getenv("MAX_WATCHLIST", "10"))

if not VT_KEY:   raise SystemExit("❌  VT_API_KEY missing from .env")
if not TG_TOKEN: raise SystemExit("❌  TELEGRAM_TOKEN missing from .env")

VT_BASE   = "https://www.virustotal.com/api/v3"
VT_HDR    = {"x-apikey": VT_KEY}
MAX_BYTES = MAX_MB * 1024 * 1024
TIMEOUT   = aiohttp.ClientTimeout(total=60)

# ─────────────────────────────────────────────────────────────
# 2. PATHS & LOGGING
# ─────────────────────────────────────────────────────────────
BASE_DIR = Path("~/.vtbot").expanduser()
TEMP_DIR = BASE_DIR / "temp"
DB_PATH  = BASE_DIR / "scans.db"
LOG_PATH = BASE_DIR / "bot.log"

for d in (BASE_DIR, TEMP_DIR):
    d.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# 3. BREAKING BAD + BETTER CALL SAUL THEME
#    Multiple GIFs per mood — bot picks one at random each time
# ─────────────────────────────────────────────────────────────
GIFS = {
    # Saul Goodman — getting ready, reviewing the case
    "prep": [
        "https://media.giphy.com/media/3o7TKSjRrfIPjeiVyE/giphy.gif",
        "https://media.giphy.com/media/l0MYEqEzwMWFCg8rm/giphy.gif",
        "https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif",
    ],
    # Walter White — cooking in the lab
    "cook": [
        "https://media.giphy.com/media/26BRuo6sLetdllPAQ/giphy.gif",
        "https://media.giphy.com/media/3ohzdYJK1wAdPWVk88/giphy.gif",
        "https://media.giphy.com/media/xT9IgHqp9H6M4/giphy.gif",
    ],
    # Jesse — "Yeah science!" / clean result
    "safe": [
        "https://media.giphy.com/media/KIpm9dzD2OAK2p60Xu/giphy.gif",
        "https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif",
        "https://media.giphy.com/media/3ohc14lCEdXHSpnnSU/giphy.gif",
    ],
    # Gus Fring / Walter threatening — dangerous result
    "danger": [
        "https://media.giphy.com/media/xT9IgG50Lg7russbGB/giphy.gif",
        "https://media.giphy.com/media/QNGHqtEdHDAcgDPJCj/giphy.gif",
        "https://media.giphy.com/media/3o6Zt11R527E2l64tW/giphy.gif",
    ],
    # Mike Ehrmantraut — suspicious, watching, silent
    "sus": [
        "https://media.giphy.com/media/l0HlQ7LRalQqdWfao/giphy.gif",
        "https://media.giphy.com/media/26BRtW4jOJxOMsKdi/giphy.gif",
        "https://media.giphy.com/media/3o6ZtpxSZbQRRnwCKQ/giphy.gif",
    ],
    # Saul shrugging — error / something went wrong
    "err": [
        "https://media.giphy.com/media/l0HlNQ03J5JxX6lva/giphy.gif",
        "https://media.giphy.com/media/3o7TKF1fSIs1R19B8k/giphy.gif",
    ],
    # Walter "I am the danger" — rate limit hit
    "ratelimit": [
        "https://media.giphy.com/media/xT9IgG50Lg7russbGB/giphy.gif",
        "https://media.giphy.com/media/QNGHqtEdHDAcgDPJCj/giphy.gif",
    ],
    # Watchlist alert — verdict changed
    "alert": [
        "https://media.giphy.com/media/3ohzdYJK1wAdPWVk88/giphy.gif",
        "https://media.giphy.com/media/l0MYt5jPR6QX5pnqM/giphy.gif",
    ],
}


def gif(key: str) -> str:
    """Pick a random GIF for a given mood."""
    return random.choice(GIFS.get(key, GIFS["err"]))


# Character-voiced messages — randomly chosen each time for freshness
PREP_MSGS = [
    "👔 *Better Call Saul — he's reviewing your case file...*",
    "📋 *Saul Goodman & Associates on the case. Please hold.*",
    "🏛️ *It's all good, man! Saul is preparing the evidence...*",
    "💼 *Jimmy McGill is getting the paperwork ready...*",
]

COOK_MSGS = [
    "🥼 *Walter just put on his hazmat suit. Stand back.*",
    "⚗️ *The Blue Sky analysis is in progress. 99.1% pure.*",
    "🔬 *Say my name... I am the one who scans.*",
    "👨‍🔬 *Mr. White is in the lab. Do. Not. Interrupt. Him.*",
    "💊 *Cooking the analysis. This is going to be pure.*",
]

SAFE_INTROS = [
    "✅ *Yeah science, bitch! It's clean!*",
    "✅ *Jesse would approve. This one's pure.*",
    "✅ *Hank ran the plates — nothing suspicious here.*",
    "✅ *Saul says: My client is completely innocent!*",
]

DANGER_INTROS = [
    "☣️ *Gus Fring would like a word with you.*",
    "☣️ *I am the danger. And THIS is the danger.*",
    "☣️ *You know who I am? I AM the one who warns you.*",
    "☣️ *Tread lightly. This one is cooking up trouble.*",
]

SUS_INTROS = [
    "👀 *Mike has eyes on this. Something is off.*",
    "👀 *Mike Ehrmantraut doesn't like what he sees...*",
    "👀 *Something is cooking and it ain't Blue Sky...*",
    "👀 *Half measures, Walter. This needs watching.*",
]


def pick(lst: list) -> str:
    return random.choice(lst)


# ─────────────────────────────────────────────────────────────
# 4. PATTERN DETECTION
# ─────────────────────────────────────────────────────────────
HASH_RE = {
    "md5":    re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1":   re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}
URL_RE    = re.compile(r"^https?://\S+$", re.I)
IP_RE_RAW = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def is_valid_ip(text: str) -> bool:
    if not IP_RE_RAW.match(text):
        return False
    try:
        ipaddress.IPv4Address(text)
        return True
    except ipaddress.AddressValueError:
        return False


def detect_type(text: str) -> Optional[str]:
    t = text.strip()
    if HASH_RE["sha256"].match(t): return "sha256"
    if HASH_RE["sha1"].match(t):   return "sha1"
    if HASH_RE["md5"].match(t):    return "md5"
    if URL_RE.match(t):            return "url"
    if is_valid_ip(t):             return "ip"
    return None


# ─────────────────────────────────────────────────────────────
# 5. IN-MEMORY CACHE
# ─────────────────────────────────────────────────────────────
class Cache:
    def __init__(self, ttl_minutes: int = 60):
        self._store: dict = {}
        self._ttl         = timedelta(minutes=ttl_minutes)
        self._lock        = asyncio.Lock()

    async def get(self, key: str):
        async with self._lock:
            entry = self._store.get(key)
            if entry:
                val, ts = entry
                if datetime.now() - ts < self._ttl:
                    return val
                del self._store[key]
        return None

    async def set(self, key: str, val):
        async with self._lock:
            self._store[key] = (val, datetime.now())

    async def delete(self, key: str):
        async with self._lock:
            self._store.pop(key, None)

    async def purge(self) -> int:
        async with self._lock:
            now     = datetime.now()
            expired = [k for k, (_, ts) in self._store.items()
                       if now - ts > self._ttl]
            for k in expired:
                del self._store[k]
            return len(expired)


cache = Cache()

# ─────────────────────────────────────────────────────────────
# 6. RATE LIMITER  (sliding window, per user)
# ─────────────────────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_per_hour: int = 10):
        self.max   = max_per_hour
        self._hits: dict[int, list[float]] = {}
        self._lock = asyncio.Lock()

    async def allow(self, uid: int) -> bool:
        async with self._lock:
            now  = datetime.now().timestamp()
            hits = [t for t in self._hits.get(uid, []) if now - t < 3600]
            self._hits[uid] = hits
            if len(hits) >= self.max:
                return False
            self._hits[uid].append(now)
            return True

    async def remaining(self, uid: int) -> int:
        async with self._lock:
            now  = datetime.now().timestamp()
            used = len([t for t in self._hits.get(uid, []) if now - t < 3600])
            return max(0, self.max - used)


limiter = RateLimiter(RATE_PER_HOUR)

# ─────────────────────────────────────────────────────────────
# 7. DATABASE  (scans + watchlist)
# ─────────────────────────────────────────────────────────────
class Database:
    def __init__(self, path: Path):
        self.path  = path
        self._lock = asyncio.Lock()

    async def init(self):
        async with aiosqlite.connect(self.path) as c:
            await c.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id    INTEGER  NOT NULL,
                    kind       TEXT     NOT NULL,
                    target     TEXT     NOT NULL,
                    malicious  INTEGER  DEFAULT 0,
                    suspicious INTEGER  DEFAULT 0,
                    harmless   INTEGER  DEFAULT 0,
                    verdict    TEXT     NOT NULL,
                    link       TEXT,
                    ts         DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS ix_scans_uid ON scans(user_id);

                CREATE TABLE IF NOT EXISTS watchlist (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id      INTEGER NOT NULL,
                    kind         TEXT    NOT NULL,
                    target       TEXT    NOT NULL,
                    last_verdict TEXT,
                    last_scan    DATETIME,
                    active       INTEGER DEFAULT 1,
                    ts           DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS ix_watch_uid ON watchlist(user_id);
            """)
            await c.commit()

    async def log_scan(
        self, uid: int, kind: str, target: str,
        stats: dict, verdict: str, link: str,
    ) -> int:
        async with self._lock:
            async with aiosqlite.connect(self.path) as c:
                cur = await c.execute(
                    "INSERT INTO scans"
                    "(user_id,kind,target,malicious,suspicious,harmless,verdict,link)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    (
                        uid, kind, target[:500],
                        stats.get("malicious",  0),
                        stats.get("suspicious", 0),
                        stats.get("harmless",   0),
                        verdict, link[:500],
                    ),
                )
                await c.commit()
                return cur.lastrowid

    async def get_scan(self, scan_id: int) -> Optional[dict]:
        async with aiosqlite.connect(self.path) as c:
            c.row_factory = aiosqlite.Row
            cur = await c.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
            row = await cur.fetchone()
            return dict(row) if row else None

    async def get_stats(self, uid: int) -> dict:
        async with aiosqlite.connect(self.path) as c:
            c.row_factory = aiosqlite.Row
            cur = await c.execute(
                "SELECT COUNT(*) AS total,"
                " SUM(CASE WHEN verdict='SAFE'       THEN 1 ELSE 0 END) AS safe,"
                " SUM(CASE WHEN verdict='SUSPICIOUS' THEN 1 ELSE 0 END) AS sus,"
                " SUM(CASE WHEN verdict='DANGEROUS'  THEN 1 ELSE 0 END) AS danger"
                " FROM scans WHERE user_id=?",
                (uid,),
            )
            row = await cur.fetchone()
            return dict(row) if row else {"total": 0, "safe": 0, "sus": 0, "danger": 0}

    async def get_history(self, uid: int, limit: int = 5) -> list:
        async with aiosqlite.connect(self.path) as c:
            c.row_factory = aiosqlite.Row
            cur = await c.execute(
                "SELECT id,kind,target,verdict,link,ts FROM scans"
                " WHERE user_id=? ORDER BY ts DESC LIMIT ?",
                (uid, limit),
            )
            return [dict(r) for r in await cur.fetchall()]

    # ── Watchlist ──────────────────────────────────────────────
    async def watch_add(self, uid: int, kind: str, target: str, verdict: str) -> Optional[int]:
        async with self._lock:
            async with aiosqlite.connect(self.path) as c:
                cur = await c.execute(
                    "SELECT COUNT(*) FROM watchlist WHERE user_id=? AND active=1", (uid,)
                )
                if (await cur.fetchone())[0] >= MAX_WATCHLIST:
                    return None
                cur = await c.execute(
                    "SELECT id FROM watchlist WHERE user_id=? AND target=? AND active=1",
                    (uid, target),
                )
                row = await cur.fetchone()
                if row:
                    return row[0]
                cur = await c.execute(
                    "INSERT INTO watchlist(user_id,kind,target,last_verdict,last_scan)"
                    " VALUES(?,?,?,?,datetime('now'))",
                    (uid, kind, target[:500], verdict),
                )
                await c.commit()
                return cur.lastrowid

    async def watch_remove(self, uid: int, watch_id: int) -> bool:
        async with self._lock:
            async with aiosqlite.connect(self.path) as c:
                cur = await c.execute(
                    "UPDATE watchlist SET active=0 WHERE id=? AND user_id=?",
                    (watch_id, uid),
                )
                await c.commit()
                return cur.rowcount > 0

    async def watch_list(self, uid: int) -> list:
        async with aiosqlite.connect(self.path) as c:
            c.row_factory = aiosqlite.Row
            cur = await c.execute(
                "SELECT id,kind,target,last_verdict,last_scan FROM watchlist"
                " WHERE user_id=? AND active=1 ORDER BY ts DESC",
                (uid,),
            )
            return [dict(r) for r in await cur.fetchall()]

    async def watch_all_active(self) -> list:
        async with aiosqlite.connect(self.path) as c:
            c.row_factory = aiosqlite.Row
            cur = await c.execute(
                "SELECT id,user_id,kind,target,last_verdict"
                " FROM watchlist WHERE active=1"
            )
            return [dict(r) for r in await cur.fetchall()]

    async def watch_update(self, watch_id: int, verdict: str):
        async with self._lock:
            async with aiosqlite.connect(self.path) as c:
                await c.execute(
                    "UPDATE watchlist SET last_verdict=?,last_scan=datetime('now')"
                    " WHERE id=?",
                    (verdict, watch_id),
                )
                await c.commit()


db = Database(DB_PATH)

# ─────────────────────────────────────────────────────────────
# 8. VIRUSTOTAL API
# ─────────────────────────────────────────────────────────────
async def vt_get(endpoint: str) -> tuple:
    url = f"{VT_BASE}/{endpoint.lstrip('/')}"
    for attempt in range(3):
        try:
            async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
                async with session.get(url, headers=VT_HDR) as resp:
                    if resp.status == 429:
                        await asyncio.sleep(int(resp.headers.get("Retry-After", 60)))
                        continue
                    if resp.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return resp.status, await resp.json()
        except aiohttp.ClientError as e:
            log.error(f"VT GET error (attempt {attempt+1}): {e}")
            await asyncio.sleep(2 ** attempt)
    return None, None


async def vt_post(endpoint: str, data) -> tuple:
    url = f"{VT_BASE}/{endpoint.lstrip('/')}"
    for attempt in range(3):
        try:
            async with aiohttp.ClientSession(timeout=TIMEOUT) as session:
                async with session.post(url, headers=VT_HDR, data=data) as resp:
                    if resp.status == 429:
                        await asyncio.sleep(int(resp.headers.get("Retry-After", 60)))
                        continue
                    if resp.status >= 500:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    return resp.status, await resp.json()
        except aiohttp.ClientError as e:
            log.error(f"VT POST error (attempt {attempt+1}): {e}")
            await asyncio.sleep(2 ** attempt)
    return None, None


async def poll_analysis(analysis_id: str, max_polls: int = 10) -> Optional[dict]:
    delay = 5
    for _ in range(max_polls):
        await asyncio.sleep(delay)
        delay = min(delay + 5, 30)
        status, data = await vt_get(f"analyses/{analysis_id}")
        if status != 200 or not data:
            continue
        state = data.get("data", {}).get("attributes", {}).get("status")
        if state == "completed":
            return data
        if state == "failed":
            return None
    return None


def vt_url_id(url: str) -> str:
    """VT GUI uses base64url(url) without padding — not sha256."""
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


# ─────────────────────────────────────────────────────────────
# 9. ANALYSIS HELPERS
# ─────────────────────────────────────────────────────────────
def calc_risk(stats: dict) -> int:
    m = stats.get("malicious",  0)
    s = stats.get("suspicious", 0)
    h = stats.get("harmless",   0)
    u = stats.get("undetected", 0)
    total = m + s + h + u
    if total == 0:
        return 0
    return min(100, int(((m * 100) + (s * 40)) / total))


def risk_bar(score: int) -> str:
    filled = score // 10
    bar    = "█" * filled + "░" * (10 - filled)
    colour = "🔴" if score >= 70 else ("🟡" if score >= 30 else "🟢")
    return f"{colour} `[{bar}]` {score}/100"


def top_engines(results: dict, max_show: int = 5) -> list:
    flagged = [
        {
            "name":     engine,
            "category": data.get("category", ""),
            "result":   data.get("result") or data.get("category", ""),
        }
        for engine, data in results.items()
        if data.get("category") in ("malicious", "suspicious")
    ]
    flagged.sort(key=lambda x: (0 if x["category"] == "malicious" else 1, x["name"]))
    return flagged[:max_show]


def get_categories(attrs: dict) -> list:
    cats = []
    for field in ("categories", "popular_threat_classification"):
        raw = attrs.get(field)
        if isinstance(raw, dict):
            for v in raw.values():
                if isinstance(v, str) and v.lower() not in cats:
                    cats.append(v.lower())
        elif isinstance(raw, list):
            for v in raw:
                if isinstance(v, str) and v.lower() not in cats:
                    cats.append(v.lower())
    return cats[:3]


def format_age(ts: int) -> str:
    try:
        diff = datetime.now(tz=timezone.utc) - datetime.fromtimestamp(ts, tz=timezone.utc)
        if diff.days > 365:   return f"{diff.days // 365}y ago"
        if diff.days > 30:    return f"{diff.days // 30}mo ago"
        if diff.days > 0:     return f"{diff.days}d ago"
        if diff.seconds > 3600: return f"{diff.seconds // 3600}h ago"
        return "just now"
    except Exception:
        return "unknown"


def plain_english(stats: dict, categories: list, score: int) -> str:
    m     = stats.get("malicious",  0)
    s     = stats.get("suspicious", 0)
    total = sum(stats.get(k, 0) for k in ("malicious","suspicious","harmless","undetected"))
    cat   = f" — classified as *{', '.join(categories[:2])}*" if categories else ""

    if m == 0 and s == 0:
        return (
            f"💬 *In plain English:*\n"
            f"Zero out of {total} security engines raised an alarm. "
            f"Every independent scanner gave this a clean bill of health. "
            f"You are good to go."
        )
    if m == 0:
        return (
            f"💬 *In plain English:*\n"
            f"{s} out of {total} engines are suspicious{cat}. "
            f"Not confirmed malicious yet, but Mike wouldn't trust it. "
            f"Proceed with extreme caution."
        )
    if m <= 3:
        return (
            f"💬 *In plain English:*\n"
            f"{m} out of {total} engines flagged this{cat}. "
            f"Could be a false positive — but could also be real. "
            f"Don't interact with it unless you're 100% certain of the source."
        )
    if m <= 15:
        return (
            f"💬 *In plain English:*\n"
            f"{m} out of {total} security engines confirmed this is dangerous{cat}. "
            f"That's like {m} independent doctors all diagnosing the same disease. "
            f"This is NOT a false alarm. Stay away."
        )
    return (
        f"💬 *In plain English:*\n"
        f"{m} out of {total} engines are screaming danger{cat}. "
        f"This is as dirty as Heisenberg's competition. "
        f"Do NOT touch it. Do NOT share it. Delete it immediately."
    )


# ─────────────────────────────────────────────────────────────
# 10. RESULT CARD BUILDER
# ─────────────────────────────────────────────────────────────
def build_result(stats: dict, attrs: dict, kind: str) -> tuple:
    """Returns (message_text, gif_key, verdict)."""
    m     = stats.get("malicious",  0)
    s     = stats.get("suspicious", 0)
    h     = stats.get("harmless",   0)
    u     = stats.get("undetected", 0)
    total = m + s + h + u
    score = calc_risk(stats)

    if   m > 0: verdict, gif_key, intro = "DANGEROUS",  "danger", pick(DANGER_INTROS)
    elif s > 0: verdict, gif_key, intro = "SUSPICIOUS", "sus",    pick(SUS_INTROS)
    else:       verdict, gif_key, intro = "SAFE",        "safe",   pick(SAFE_INTROS)

    raw_results = (
        attrs.get("last_analysis_results")
        or attrs.get("results")
        or {}
    )
    flagged    = top_engines(raw_results)
    categories = get_categories(attrs)

    # Threat label
    ptc   = attrs.get("popular_threat_classification", {})
    label = ptc.get("suggested_threat_label", "") if isinstance(ptc, dict) else ""

    # Dates
    first_ts = attrs.get("first_submission_date") or attrs.get("creation_date")
    last_ts  = attrs.get("last_analysis_date")    or attrs.get("last_modification_date")

    lines = [
        intro,
        "",
        f"📊 *Scan Results* ({total} engines)",
        f"🚨 Malicious:   `{m}`",
        f"⚠️  Suspicious:  `{s}`",
        f"✅ Harmless:    `{h}`",
        f"❓ Undetected:  `{u}`",
        "",
        f"💀 *Risk Score:* {risk_bar(score)}",
    ]

    if categories:
        lines.append(f"🏷️ Category: `{' • '.join(categories)}`")
    if label:
        lines.append(f"🔖 Threat label: `{label}`")

    date_lines = []
    if first_ts: date_lines.append(f"📅 First seen: `{format_age(first_ts)}`")
    if last_ts:  date_lines.append(f"🕐 Last scanned: `{format_age(last_ts)}`")
    if date_lines:
        lines.append("")
        lines.extend(date_lines)

    if flagged:
        lines.append("")
        lines.append("🔍 *Flagged by:*")
        for e in flagged:
            icon = "🔴" if e["category"] == "malicious" else "🟡"
            lines.append(f"  {icon} `{e['name']}`: {e['result']}")

    lines.append("")
    lines.append(plain_english(stats, categories, score))

    return "\n".join(lines), gif_key, verdict


def result_keyboard(link: str, scan_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("🔗 Full Report on VirusTotal", url=link)],
        [
            InlineKeyboardButton("🔄 Rescan",       callback_data=f"rescan:{scan_id}"),
            InlineKeyboardButton("📤 Share Result",  callback_data=f"share:{scan_id}"),
        ],
        [InlineKeyboardButton("👁 Add to Watchlist", callback_data=f"watch:{scan_id}")],
    ])


# ─────────────────────────────────────────────────────────────
# 11. ANIMATION HELPERS
# ─────────────────────────────────────────────────────────────
async def _del(msg):
    try:
        await msg.delete()
    except Exception:
        pass


async def _prep_anim(update: Update, text: str):
    m = await update.message.reply_animation(
        gif("prep"), caption=text, parse_mode=ParseMode.MARKDOWN,
    )
    await asyncio.sleep(2)
    await _del(m)


async def _cook_anim(update: Update, text: str):
    return await update.message.reply_animation(
        gif("cook"), caption=text, parse_mode=ParseMode.MARKDOWN,
    )


async def _send_result(
    update: Update, text: str, gif_key: str, link: str, scan_id: int,
):
    await update.message.reply_animation(
        gif(gif_key),
        caption=text,
        reply_markup=result_keyboard(link, scan_id),
        parse_mode=ParseMode.MARKDOWN,
    )


# ─────────────────────────────────────────────────────────────
# 12. SCAN FUNCTIONS
# ─────────────────────────────────────────────────────────────
async def scan_hash(update: Update, value: str, htype: str):
    uid = update.effective_user.id
    key = f"hash:{value.lower()}"

    if cached := await cache.get(key):
        txt, gif_key, link, scan_id = cached
        await _send_result(update, txt, gif_key, link, scan_id)
        return

    await _prep_anim(update, pick(PREP_MSGS))
    cook = await _cook_anim(update, pick(COOK_MSGS))

    try:
        status, data = await vt_get(f"files/{value}")
        await _del(cook)

        if status == 200 and data:
            attrs = data["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            link  = f"https://www.virustotal.com/gui/file/{value}"
            txt, gif_key, verdict = build_result(stats, attrs, "hash")
            scan_id = await db.log_scan(uid, f"hash:{htype}", value, stats, verdict, link)
            await cache.set(key, (txt, gif_key, link, scan_id))
            await _send_result(update, txt, gif_key, link, scan_id)
        elif status == 404:
            await update.message.reply_text(
                "🤷 *Hash not found* in VT database.\n"
                "Upload the actual file and I will scan it from scratch.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await update.message.reply_text(
                f"❌ VirusTotal returned error (code `{status}`). Try again.",
                parse_mode=ParseMode.MARKDOWN,
            )
    except Exception as e:
        log.error(f"Hash scan error: {e}", exc_info=True)
        await _del(cook)
        await update.message.reply_animation(
            gif("err"),
            caption="❌ Something went wrong. Even Saul cannot fix this right now.",
            parse_mode=ParseMode.MARKDOWN,
        )


async def scan_url(update: Update, value: str, bypass_cache: bool = False):
    uid = update.effective_user.id
    key = f"url:{hashlib.sha256(value.encode()).hexdigest()}"

    if not bypass_cache:
        if cached := await cache.get(key):
            txt, gif_key, link, scan_id = cached
            await _send_result(update, txt, gif_key, link, scan_id)
            return

    await update.message.reply_text(
        "⚠️ *Safety notice:* Do NOT visit this URL while we are scanning it!",
        parse_mode=ParseMode.MARKDOWN,
    )
    await _prep_anim(update, pick(PREP_MSGS))
    cook = await _cook_anim(update, pick(COOK_MSGS))

    try:
        status, submit = await vt_post("urls", {"url": value})
        if status != 200 or not submit:
            await _del(cook)
            await update.message.reply_text("❌ Failed to submit URL to VirusTotal.")
            return

        result = await poll_analysis(submit["data"]["id"])
        await _del(cook)

        if result:
            attrs = result["data"]["attributes"]
            stats = attrs["stats"]
            link  = f"https://www.virustotal.com/gui/url/{vt_url_id(value)}"
            txt, gif_key, verdict = build_result(stats, attrs, "url")
            scan_id = await db.log_scan(uid, "url", value[:200], stats, verdict, link)
            await cache.set(key, (txt, gif_key, link, scan_id))
            await _send_result(update, txt, gif_key, link, scan_id)
        else:
            await update.message.reply_text(
                "⏳ VT is slow today. Analysis timed out — try again in a few minutes."
            )
    except Exception as e:
        log.error(f"URL scan error: {e}", exc_info=True)
        await _del(cook)
        await update.message.reply_animation(
            gif("err"), caption="❌ Scan failed. Try again.",
            parse_mode=ParseMode.MARKDOWN,
        )


async def scan_ip(update: Update, value: str, bypass_cache: bool = False):
    uid = update.effective_user.id
    key = f"ip:{value}"

    if not bypass_cache:
        if cached := await cache.get(key):
            txt, gif_key, link, scan_id = cached
            await _send_result(update, txt, gif_key, link, scan_id)
            return

    await _prep_anim(update, "🕵️ *Mike is running surveillance on this IP...*")
    cook = await _cook_anim(update, "🔬 *Mike does not miss. Cross-checking...*")

    try:
        status, data = await vt_get(f"ip_addresses/{value}")
        await _del(cook)

        if status == 200 and data:
            attrs = data["data"]["attributes"]
            stats = attrs["last_analysis_stats"]
            link  = f"https://www.virustotal.com/gui/ip-address/{value}"
            txt, gif_key, verdict = build_result(stats, attrs, "ip")
            scan_id = await db.log_scan(uid, "ip", value, stats, verdict, link)
            await cache.set(key, (txt, gif_key, link, scan_id))
            await _send_result(update, txt, gif_key, link, scan_id)
        elif status == 404:
            await update.message.reply_text("🤷 IP not found in VT database.")
        else:
            await update.message.reply_text(
                f"❌ VT returned error (code `{status}`).",
                parse_mode=ParseMode.MARKDOWN,
            )
    except Exception as e:
        log.error(f"IP scan error: {e}", exc_info=True)
        await _del(cook)
        await update.message.reply_animation(
            gif("err"), caption="❌ Scan failed. Try again.",
            parse_mode=ParseMode.MARKDOWN,
        )


async def scan_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    doc = update.message.document

    if not doc:
        await update.message.reply_text("❌ No file found.")
        return
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text(
            f"❌ File too large! Max allowed: *{MAX_MB} MB*",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    safe_name = re.sub(r"[^\w.\-]", "_", doc.file_name or "file")
    await _prep_anim(
        update,
        f"📦 *Jesse, start cooking — we got a file.*\n`{safe_name}`",
    )
    cook = await _cook_anim(
        update,
        f"🔬 *Scanning with 70+ AV engines...*\n`{safe_name}`",
    )

    temp_path = TEMP_DIR / f"{datetime.now().timestamp()}_{safe_name}"

    try:
        tg_file = await context.bot.get_file(doc.file_id)
        await tg_file.download_to_drive(temp_path)
        if not temp_path.exists():
            raise FileNotFoundError("Temp file missing after download.")

        with open(temp_path, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("file", f, filename=safe_name)
            status, submit = await vt_post("files", form)

        if status != 200 or not submit:
            await _del(cook)
            await update.message.reply_text("❌ Upload to VirusTotal failed.")
            return

        result = await poll_analysis(submit["data"]["id"])
        await _del(cook)

        if result:
            attrs     = result["data"]["attributes"]
            stats     = attrs["stats"]
            file_hash = result.get("meta", {}).get("file_info", {}).get("sha256", "")
            link      = (
                f"https://www.virustotal.com/gui/file/{file_hash}"
                if file_hash
                else "https://www.virustotal.com"
            )
            txt, gif_key, verdict = build_result(stats, attrs, "file")
            scan_id = await db.log_scan(uid, "file", safe_name[:100], stats, verdict, link)
            await _send_result(update, txt, gif_key, link, scan_id)
        else:
            await update.message.reply_text(
                "⏳ Analysis timed out. VirusTotal is slow today. Try again later."
            )
    except Exception as e:
        log.error(f"File scan error: {e}", exc_info=True)
        await _del(cook)
        await update.message.reply_animation(
            gif("err"), caption="❌ File scan failed. Try again.",
            parse_mode=ParseMode.MARKDOWN,
        )
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────
# 13. SHARED HELP TEXT
# ─────────────────────────────────────────────────────────────
HELP_TEXT = (
    "🔬 *VirusTotal Bot — Help*\n\n"
    "*What you can scan:*\n"
    f"• `https://example.com` — URL\n"
    f"• MD5 / SHA1 / SHA256 hash\n"
    f"• `1.2.3.4` — IP address\n"
    f"• 📎 Any file (up to {MAX_MB} MB)\n\n"
    "*Commands:*\n"
    "`/start`        — Welcome screen\n"
    "`/help`         — This message\n"
    "`/stats`        — Your scan statistics\n"
    "`/history`      — Last 5 scans\n"
    "`/report`       — Personal threat report\n"
    "`/watch <url>`  — Monitor a URL or IP daily\n"
    "`/watchlist`    — Everything you are watching\n"
    "`/unwatch <id>` — Stop monitoring\n\n"
    "*What makes this better than the website:*\n"
    "• Risk score 0–100 (instant understanding)\n"
    "• Engine names — see exactly WHO flagged it\n"
    "• Plain-English verdict — no jargon\n"
    "• Watchlist with automatic daily alerts\n"
    "• Personal threat history and report\n\n"
    "🎬 _Breaking Bad and Better Call Saul theme_"
)


# ─────────────────────────────────────────────────────────────
# 14. COMMAND HANDLERS
# ─────────────────────────────────────────────────────────────
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_animation(
        gif("prep"),
        caption=(
            "👔 *Better Call Saul — VirusTotal Bot*\n\n"
            "🎬 _I am the one who scans._\n\n"
            "Send me any *URL*, *hash*, *IP*, or *file* "
            "and I will tell you exactly how dangerous it is.\n\n"
            "You get:\n"
            "• A risk score from 0 to 100\n"
            "• The engine names that flagged it\n"
            "• A plain-English verdict\n"
            "• Dates, categories and threat labels\n"
            "• Buttons to rescan, share and watch\n\n"
            "Type /help for everything."
        ),
        reply_markup=InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🔬 VirusTotal", url="https://virustotal.com"),
                InlineKeyboardButton("❓ Help",        callback_data="cb_help"),
            ],
            [
                InlineKeyboardButton("📊 My Stats",   callback_data="cb_stats"),
                InlineKeyboardButton("📋 History",    callback_data="cb_history"),
            ],
            [InlineKeyboardButton("📄 My Report",     callback_data="cb_report")],
        ]),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)


async def cmd_stats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid   = update.effective_user.id
    s     = await db.get_stats(uid)
    rem   = await limiter.remaining(uid)
    total = s["total"] or 1

    await update.message.reply_animation(
        gif("prep"),
        caption=(
            f"📊 *Your Scan Statistics*\n\n"
            f"🔍 Total scans:       `{s['total']}`\n"
            f"🟢 Safe:              `{s['safe']}`\n"
            f"🟡 Suspicious:        `{s['sus']}`\n"
            f"🔴 Dangerous:         `{s['danger']}`\n\n"
            f"🛡️ Safety rate:       `{int(s['safe'] / total * 100)}%`\n"
            f"⏱ Scans left/hour:   `{rem}`"
        ),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    rows = await db.get_history(uid)

    if not rows:
        await update.message.reply_text(
            "📭 No scans yet!\nSend me a URL, hash, IP, or file to get started."
        )
        return

    icons = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🔴"}
    lines = ["📋 *Your Last 5 Scans*\n"]
    for r in rows:
        icon   = icons.get(r["verdict"], "⚪")
        ts     = (r["ts"] or "")[:16]
        target = r["target"]
        if len(target) > 40:
            target = target[:37] + "…"
        lines.append(f"{icon} `{r['kind']}` — {target}\n    _{ts}_")

    await update.message.reply_text("\n\n".join(lines), parse_mode=ParseMode.MARKDOWN)


async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    s    = await db.get_stats(uid)
    name = update.effective_user.first_name or "Partner"

    if s["total"] == 0:
        await update.message.reply_animation(
            gif("prep"),
            caption=(
                f"📄 *Personal Threat Report — {name}*\n\n"
                "You have not scanned anything yet.\n"
                "Send me a URL, hash, or file to get started."
            ),
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    total    = s["total"]
    danger   = s["danger"] or 0
    sus      = s["sus"]    or 0
    safe     = s["safe"]   or 0
    safe_pct = int(safe / total * 100)

    if danger == 0 and sus == 0:
        commentary = (
            f"🟢 *{name}, you are clean.*\n"
            "Not a single threat found in your history.\n"
            "_Jesse would say: Yeah science, bitch!_"
        )
        gif_key = "safe"
    elif danger >= 10:
        commentary = (
            f"🔴 *{name}... you have been walking into meth labs.*\n"
            f"You have encountered {danger} dangerous targets.\n"
            "_Gus Fring says: You lack discipline._"
        )
        gif_key = "danger"
    elif danger > 0:
        commentary = (
            f"🟡 *{name}, you have had some close calls.*\n"
            f"You dodged {danger} dangerous item{'s' if danger > 1 else ''}.\n"
            "_Saul says: Be more careful, kid. I do not do refunds._"
        )
        gif_key = "sus"
    else:
        commentary = (
            f"🟡 *{name}, Mike has his eye on you.*\n"
            f"{sus} suspicious items in your history.\n"
            "_Mike says: No more half measures._"
        )
        gif_key = "sus"

    await update.message.reply_animation(
        gif(gif_key),
        caption=(
            f"📄 *Personal Threat Report*\n"
            f"👤 {name}\n\n"
            f"🔍 Total scans:    `{total}`\n"
            f"🟢 Safe:           `{safe}` ({safe_pct}%)\n"
            f"🟡 Suspicious:     `{sus}`\n"
            f"🔴 Dangerous:      `{danger}`\n\n"
            f"{commentary}"
        ),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_watch(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    args = context.args

    if not args:
        await update.message.reply_text(
            "Usage: `/watch https://example.com`\nor `/watch 1.2.3.4`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    target = args[0].strip()
    kind   = detect_type(target)

    if kind not in ("url", "ip"):
        await update.message.reply_text(
            "❌ Watchlist supports URLs and IPs only.\n"
            "Example: `/watch https://example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    await update.message.reply_text(
        "🔍 *Quick scan before adding to watchlist...*",
        parse_mode=ParseMode.MARKDOWN,
    )

    verdict = "UNKNOWN"
    try:
        if kind == "url":
            status, submit = await vt_post("urls", {"url": target})
            if status == 200 and submit:
                result = await poll_analysis(submit["data"]["id"])
                if result:
                    stats = result["data"]["attributes"]["stats"]
                    _, _, verdict = build_result(
                        stats, result["data"]["attributes"], "url"
                    )
        else:
            status, data = await vt_get(f"ip_addresses/{target}")
            if status == 200 and data:
                attrs = data["data"]["attributes"]
                stats = attrs["last_analysis_stats"]
                _, _, verdict = build_result(stats, attrs, "ip")
    except Exception as e:
        log.error(f"Watch scan error: {e}")

    watch_id = await db.watch_add(uid, kind, target, verdict)
    if watch_id is None:
        await update.message.reply_text(
            f"❌ Watchlist full! Max {MAX_WATCHLIST} items.\n"
            "Use /watchlist to manage your list.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    icons = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🔴", "UNKNOWN": "⚪"}
    await update.message.reply_animation(
        gif("prep"),
        caption=(
            f"👁️ *Now watching:*\n`{target}`\n\n"
            f"Current verdict: {icons.get(verdict, '⚪')} `{verdict}`\n"
            f"Watch ID: `#{watch_id}`\n\n"
            f"🔔 You will get an alert the moment the verdict changes."
        ),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_watchlist(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    rows = await db.watch_list(uid)

    if not rows:
        await update.message.reply_text(
            "📭 Your watchlist is empty.\n"
            "Add items with `/watch https://example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    icons   = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🔴", "UNKNOWN": "⚪"}
    lines   = ["👁 *Your Watchlist*\n"]
    buttons = []

    for r in rows:
        icon   = icons.get(r["last_verdict"], "⚪")
        target = r["target"]
        if len(target) > 45:
            target = target[:42] + "…"
        lines.append(f"`#{r['id']}` {icon} `{r['kind']}` — {target}")
        buttons.append([
            InlineKeyboardButton(
                f"🗑 Remove #{r['id']}", callback_data=f"unwatch:{r['id']}"
            )
        ])

    await update.message.reply_text(
        "\n".join(lines),
        reply_markup=InlineKeyboardMarkup(buttons),
        parse_mode=ParseMode.MARKDOWN,
    )


async def cmd_unwatch(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid  = update.effective_user.id
    args = context.args

    if not args or not args[0].isdigit():
        await update.message.reply_text(
            "Usage: `/unwatch <id>`\nGet IDs from /watchlist",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    removed = await db.watch_remove(uid, int(args[0]))
    msg = (
        f"✅ Removed watch `#{args[0]}` — Mike stands down."
        if removed
        else "❌ Watch ID not found or already removed."
    )
    await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)


# ─────────────────────────────────────────────────────────────
# 15. MAIN MESSAGE HANDLER
# ─────────────────────────────────────────────────────────────
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message or not update.effective_user:
        return
    if update.message.edit_date:
        return

    uid = update.effective_user.id

    if not await limiter.allow(uid):
        await update.message.reply_animation(
            gif("ratelimit"),
            caption=(
                f"🚧 *I am the rate limiter.*\n\n"
                f"You have hit your {RATE_PER_HOUR} scan limit for this hour.\n"
                "_Saul says: Even I have office hours, kid._"
            ),
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    if update.message.document:
        await scan_file(update, context)
        return

    text = (update.message.text or "").strip()
    if not text:
        return

    scan_type = detect_type(text)

    if scan_type in ("md5", "sha1", "sha256"):
        await scan_hash(update, text, scan_type)
    elif scan_type == "url":
        await scan_url(update, text)
    elif scan_type == "ip":
        await scan_ip(update, text)
    else:
        await update.message.reply_text(
            "❓ *I do not recognise that.*\n\n"
            "Send me:\n"
            "• A URL — `https://example.com`\n"
            "• A hash — 32, 40 or 64 hex characters\n"
            "• An IP — `1.2.3.4`\n"
            "• Or upload a file 📎",
            parse_mode=ParseMode.MARKDOWN,
        )


# ─────────────────────────────────────────────────────────────
# 16. CALLBACK HANDLERS
# ─────────────────────────────────────────────────────────────
async def handle_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    q    = update.callback_query
    await q.answer()
    uid  = q.from_user.id
    data = q.data or ""

    # ── Start menu navigation ──────────────────────────────────
    if data == "cb_help":
        await q.message.reply_text(HELP_TEXT, parse_mode=ParseMode.MARKDOWN)

    elif data == "cb_stats":
        s     = await db.get_stats(uid)
        rem   = await limiter.remaining(uid)
        total = s["total"] or 1
        await q.message.reply_text(
            f"📊 *Stats*\n\n"
            f"🔍 Total: `{s['total']}` | 🟢 `{s['safe']}` | "
            f"🟡 `{s['sus']}` | 🔴 `{s['danger']}`\n"
            f"🛡️ Safety: `{int(s['safe'] / total * 100)}%` | "
            f"⏱ Remaining: `{rem}`",
            parse_mode=ParseMode.MARKDOWN,
        )

    elif data == "cb_history":
        rows = await db.get_history(uid)
        if not rows:
            await q.message.reply_text("📭 No history yet!")
            return
        icons = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🔴"}
        lines = ["📋 *Last 5 Scans*\n"]
        for r in rows:
            icon   = icons.get(r["verdict"], "⚪")
            target = r["target"][:40] + ("…" if len(r["target"]) > 40 else "")
            lines.append(f"{icon} `{r['kind']}` — {target}")
        await q.message.reply_text("\n".join(lines), parse_mode=ParseMode.MARKDOWN)

    elif data == "cb_report":
        class FakeUpdate:
            message        = q.message
            effective_user = q.from_user
        await cmd_report(FakeUpdate(), context)

    # ── Rescan ────────────────────────────────────────────────
    elif data.startswith("rescan:"):
        scan_id = int(data.split(":")[1])
        row     = await db.get_scan(scan_id)
        if not row:
            await q.message.reply_text("❌ Scan record not found.")
            return

        class FakeUpdate:
            message        = q.message
            effective_user = q.from_user

        fake   = FakeUpdate()
        kind   = row["kind"]
        target = row["target"]

        await q.message.reply_text(
            "🔄 *Forcing a fresh rescan...*", parse_mode=ParseMode.MARKDOWN
        )

        if "url" in kind:
            await cache.delete(f"url:{hashlib.sha256(target.encode()).hexdigest()}")
            await scan_url(fake, target, bypass_cache=True)
        elif "ip" in kind:
            await cache.delete(f"ip:{target}")
            await scan_ip(fake, target, bypass_cache=True)
        elif "hash" in kind:
            htype = kind.split(":")[1] if ":" in kind else "sha256"
            await cache.delete(f"hash:{target.lower()}")
            await scan_hash(fake, target, htype)

    # ── Share ─────────────────────────────────────────────────
    elif data.startswith("share:"):
        scan_id = int(data.split(":")[1])
        row     = await db.get_scan(scan_id)
        if not row:
            await q.message.reply_text("❌ Scan record not found.")
            return

        icons  = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "DANGEROUS": "🔴"}
        icon   = icons.get(row["verdict"], "⚪")
        link   = row.get("link") or "https://virustotal.com"
        target = row["target"][:100]

        await q.message.reply_text(
            f"📤 *Shareable Result Card*\n\n"
            f"🔬 Target: `{target}`\n"
            f"🏷️ Type: `{row['kind']}`\n"
            f"{icon} Verdict: `{row['verdict']}`\n"
            f"🔗 [Full Report on VirusTotal]({link})\n\n"
            f"_Forward this message to share it._",
            parse_mode=ParseMode.MARKDOWN,
        )

    # ── Add to watchlist (from result card) ───────────────────
    elif data.startswith("watch:"):
        scan_id = int(data.split(":")[1])
        row     = await db.get_scan(scan_id)
        if not row:
            await q.message.reply_text("❌ Scan record not found.")
            return

        kind   = row["kind"].split(":")[0]
        target = row["target"]

        if kind not in ("url", "ip"):
            await q.message.reply_text("❌ Only URLs and IPs can be watched.")
            return

        watch_id = await db.watch_add(uid, kind, target, row["verdict"])
        if watch_id is None:
            await q.message.reply_text(
                f"❌ Watchlist full ({MAX_WATCHLIST} max).\n"
                "Use /watchlist to remove something first.",
                parse_mode=ParseMode.MARKDOWN,
            )
        else:
            await q.message.reply_text(
                f"👁️ *Now watching:*\n`{target[:80]}`\n"
                f"ID `#{watch_id}` — you will be alerted on any verdict change. 🔔",
                parse_mode=ParseMode.MARKDOWN,
            )

    # ── Remove from watchlist ─────────────────────────────────
    elif data.startswith("unwatch:"):
        watch_id = int(data.split(":")[1])
        removed  = await db.watch_remove(uid, watch_id)
        await q.message.reply_text(
            f"✅ Removed `#{watch_id}` — Mike stands down."
            if removed
            else "❌ Watch ID not found.",
            parse_mode=ParseMode.MARKDOWN,
        )


# ─────────────────────────────────────────────────────────────
# 17. BACKGROUND TASKS
# ─────────────────────────────────────────────────────────────
async def watchlist_monitor(app: Application):
    """Runs every 6 hours. Rescans watched items. Alerts users on verdict changes."""
    while True:
        await asyncio.sleep(6 * 3600)
        log.info("👁 Watchlist monitor running…")

        for item in await db.watch_all_active():
            try:
                kind        = item["kind"]
                target      = item["target"]
                old_verdict = item["last_verdict"]
                new_verdict = None

                if kind == "url":
                    status, submit = await vt_post("urls", {"url": target})
                    if status == 200 and submit:
                        result = await poll_analysis(submit["data"]["id"])
                        if result:
                            stats = result["data"]["attributes"]["stats"]
                            _, _, new_verdict = build_result(
                                stats, result["data"]["attributes"], "url"
                            )
                elif kind == "ip":
                    status, data = await vt_get(f"ip_addresses/{target}")
                    if status == 200 and data:
                        attrs = data["data"]["attributes"]
                        stats = attrs["last_analysis_stats"]
                        _, _, new_verdict = build_result(stats, attrs, "ip")

                if not new_verdict:
                    continue

                await db.watch_update(item["id"], new_verdict)

                if new_verdict != old_verdict:
                    icons = {
                        "SAFE": "🟢", "SUSPICIOUS": "🟡",
                        "DANGEROUS": "🔴", "UNKNOWN": "⚪",
                    }
                    extra = (
                        "\n\n🚨 *This just turned dangerous! Stop using it immediately.*"
                        if new_verdict == "DANGEROUS"
                        else ""
                    )
                    try:
                        await app.bot.send_animation(
                            chat_id=item["user_id"],
                            animation=gif("alert"),
                            caption=(
                                f"🚨 *Watchlist Alert!*\n\n"
                                f"Verdict changed for:\n`{target[:100]}`\n\n"
                                f"Was: {icons.get(old_verdict,'⚪')} `{old_verdict}`\n"
                                f"Now: {icons.get(new_verdict,'⚪')} `{new_verdict}`"
                                f"{extra}"
                            ),
                            parse_mode=ParseMode.MARKDOWN,
                        )
                    except Exception as e:
                        log.error(f"Alert failed for user {item['user_id']}: {e}")

                await asyncio.sleep(2)  # gentle on the VT API

            except Exception as e:
                log.error(f"Watchlist error item {item['id']}: {e}")


async def cache_cleanup():
    while True:
        await asyncio.sleep(300)
        try:
            removed = await cache.purge()
            if removed:
                log.info(f"Cache: purged {removed} expired entries.")
        except Exception as e:
            log.error(f"Cache cleanup error: {e}")


async def post_init(app: Application):
    await db.init()
    log.info("✅ Database ready.")
    asyncio.create_task(cache_cleanup())
    asyncio.create_task(watchlist_monitor(app))
    log.info("✅ Background tasks started.")


# ─────────────────────────────────────────────────────────────
# 18. MAIN
# ─────────────────────────────────────────────────────────────
def main():
    print("╔══════════════════════════════════════════════╗")
    print("║  🦠  VirusTotal Bot — BB + BCS Edition  v3  ║")
    print("║       I am the one who scans.               ║")
    print("╚══════════════════════════════════════════════╝\n")

    application = (
        Application.builder()
        .token(TG_TOKEN)
        .post_init(post_init)
        .build()
    )

    application.add_handler(CommandHandler("start",     cmd_start))
    application.add_handler(CommandHandler("help",      cmd_help))
    application.add_handler(CommandHandler("stats",     cmd_stats))
    application.add_handler(CommandHandler("history",   cmd_history))
    application.add_handler(CommandHandler("report",    cmd_report))
    application.add_handler(CommandHandler("watch",     cmd_watch))
    application.add_handler(CommandHandler("watchlist", cmd_watchlist))
    application.add_handler(CommandHandler("unwatch",   cmd_unwatch))
    application.add_handler(CallbackQueryHandler(handle_callback))
    application.add_handler(
        MessageHandler(filters.ALL & ~filters.COMMAND, handle_message)
    )

    log.info("🚀 Bot polling started…")
    application.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()
