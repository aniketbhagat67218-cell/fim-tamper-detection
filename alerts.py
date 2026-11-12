"""
Real-time Alert Dispatcher for FIM Sentinel.
Supports instant phone & desktop notifications via:
1. Telegram Bot API
2. Discord Webhook

Designed for zero external dependencies using standard Python urllib.
"""
import os
import json
import logging
import threading
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("FIM_Notifier")

BASE_DIR = Path(__file__).resolve().parent
ALERT_CONFIG_FILE = BASE_DIR / "alert_config.json"


def get_alert_config() -> dict:
    """Reads alert configuration from JSON file or environment variables."""
    cfg = {
        "telegram_enabled": False,
        "telegram_token": os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
        "telegram_chat_id": os.environ.get("TELEGRAM_CHAT_ID", "").strip(),
        "discord_enabled": False,
        "discord_webhook": os.environ.get("DISCORD_WEBHOOK_URL", "").strip(),
    }

    if ALERT_CONFIG_FILE.exists():
        try:
            with open(ALERT_CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
                cfg.update(saved)
        except Exception as e:
            logger.warning("Could not read alert_config.json: %s", e)

    # Automatically enable if tokens are present
    if cfg["telegram_token"] and cfg["telegram_chat_id"]:
        cfg["telegram_enabled"] = True
    if cfg["discord_webhook"]:
        cfg["discord_enabled"] = True

    return cfg


def save_alert_config(new_cfg: dict) -> dict:
    """Saves alert configuration to JSON file."""
    cfg = get_alert_config()
    cfg.update(new_cfg)
    try:
        with open(ALERT_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        logger.error("Failed to save alert_config.json: %s", e)
    return cfg


def _send_telegram(token: str, chat_id: str, html_message: str) -> bool:
    """Sends HTML formatted message via Telegram Bot API."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": html_message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "FIM-Sentinel-Alert-Bot"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.status == 200
    except Exception as e:
        logger.error("Telegram send failed: %s", e)
        return False


def _send_discord(webhook_url: str, title: str, description: str, fields: list, color: int = 15548997) -> bool:
    """Sends rich embed via Discord Webhook."""
    payload = json.dumps({
        "username": "FIM Sentinel SOC",
        "embeds": [{
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "footer": {"text": "FIM Sentinel • File Integrity Monitoring & Tamper Detection"},
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }]
    }).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "FIM-Sentinel-Webhook"}
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.status in (200, 204)
    except Exception as e:
        logger.error("Discord send failed: %s", e)
        return False


def dispatch_tamper_alert(file_name: str, event_type: str, risk_level: str, risk_score: int, diff_summary: str = "", source: str = "Sentinel Core", async_send: bool = True):
    """
    Dispatches a real-time tampering alert to all configured channels (Telegram / Discord).
    Runs asynchronously by default to avoid blocking the main server thread.
    """
    cfg = get_alert_config()
    if not cfg["telegram_enabled"] and not cfg["discord_enabled"]:
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_color_discord = 15548997 if risk_level.upper() == "HIGH" else 15105570 if risk_level.upper() == "MEDIUM" else 3066993

    # Telegram HTML Message
    tg_msg = (
        f"🚨 <b>FIM SENTINEL: SECURITY TAMPER ALERT</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"📁 <b>Asset:</b> <code>{file_name}</code>\n"
        f"⚠️ <b>Event:</b> <b>{event_type.upper()}</b>\n"
        f"📊 <b>Risk Level:</b> <b>{risk_level.upper()}</b> ({risk_score}/100)\n"
        f"🔍 <b>Delta:</b> <code>{diff_summary or 'Hash divergence detected'}</code>\n"
        f"🛡️ <b>Engine:</b> SHA-256 Verification\n"
        f"💻 <b>Source:</b> {source}\n"
        f"🕒 <b>Time:</b> {timestamp}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"<i>Inspect diff on the FIM Sentinel Dashboard immediately.</i>"
    )

    # Discord Embed Fields
    discord_fields = [
        {"name": "📁 Monitored Asset", "value": f"`{file_name}`", "inline": True},
        {"name": "⚠️ Event Type", "value": f"**{event_type}**", "inline": True},
        {"name": "📊 Risk Level", "value": f"**{risk_level}** ({risk_score}/100)", "inline": True},
        {"name": "🔍 Modification Delta", "value": f"`{diff_summary or 'Modified'}`", "inline": False},
        {"name": "🛡️ Cryptographic Hash", "value": "SHA-256", "inline": True},
        {"name": "💻 Detection Source", "value": source, "inline": True},
    ]

    def _worker():
        if cfg["telegram_enabled"] and cfg["telegram_token"] and cfg["telegram_chat_id"]:
            _send_telegram(cfg["telegram_token"], cfg["telegram_chat_id"], tg_msg)
        if cfg["discord_enabled"] and cfg["discord_webhook"]:
            _send_discord(cfg["discord_webhook"], f"🚨 File Tampering Detected: {file_name}", "Unauthorized modification detected against trusted SHA-256 baseline.", discord_fields, risk_color_discord)

    if async_send:
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
    else:
        _worker()


def dispatch_test_alert() -> dict:
    """Dispatches a test notification to verify Telegram / Discord connectivity."""
    cfg = get_alert_config()
    results = {"telegram": "disabled", "discord": "disabled"}

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if cfg["telegram_token"] and cfg["telegram_chat_id"]:
        test_msg = (
            f"🔔 <b>FIM SENTINEL: TEST NOTIFICATION</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"✅ Real-time alert dispatcher is connected!\n"
            f"🛡️ Engine: <b>SHA-256 Enterprise Cryptography</b>\n"
            f"🕒 Timestamp: <code>{timestamp}</code>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━\n"
            f"<i>You will receive instant alerts here whenever file tampering is detected.</i>"
        )
        ok = _send_telegram(cfg["telegram_token"], cfg["telegram_chat_id"], test_msg)
        results["telegram"] = "success" if ok else "failed"

    if cfg["discord_webhook"]:
        fields = [
            {"name": "Status", "value": "✅ Webhook Connected", "inline": True},
            {"name": "Engine", "value": "SHA-256 Integrity Monitor", "inline": True},
            {"name": "Time", "value": timestamp, "inline": False},
        ]
        ok = _send_discord(cfg["discord_webhook"], "🔔 FIM Sentinel: Test Alert", "Alert notification webhook successfully connected to FIM Sentinel SOC.", fields, 3066993)
        results["discord"] = "success" if ok else "failed"

    return results
