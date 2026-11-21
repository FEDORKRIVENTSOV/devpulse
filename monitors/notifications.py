import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


def send_telegram(chat_id, text):
    """Send a Telegram message. Never raises: a failed notification must not break checks."""
    token = settings.TELEGRAM_BOT_TOKEN
    if not token or not chat_id:
        logger.info("Telegram notification skipped (no token or chat id)")
        return False
    try:
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text},
            timeout=10,
        )
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as exc:
        # Log only the exception type: the message contains the URL with the bot token.
        logger.warning("Telegram notification failed: %s", type(exc).__name__)
        return False


def notify_incident_opened(incident):
    monitor = incident.monitor
    text = (
        f"DOWN: {monitor.name}\n{monitor.url}\n"
        f"Cause: {incident.cause or 'unknown'}\n"
        f"Since: {incident.started_at:%Y-%m-%d %H:%M UTC}"
    )
    return send_telegram(monitor.telegram_chat_id, text)


def notify_incident_resolved(incident):
    monitor = incident.monitor
    duration = incident.resolved_at - incident.started_at
    minutes = int(duration.total_seconds() // 60)
    text = f"RECOVERED: {monitor.name}\n{monitor.url}\nDowntime: about {minutes} min"
    return send_telegram(monitor.telegram_chat_id, text)
