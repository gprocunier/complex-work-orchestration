from __future__ import annotations

import re
from urllib.parse import urlparse


CHATGPT_HOSTS = {"chatgpt.com", "www.chatgpt.com", "chat.openai.com"}
CHATGPT_SHARE_URL_RE = re.compile(
    r"https://(?:www\.)?(?:chatgpt\.com|chat\.openai\.com)/(?:s|share)/[^\s\"'<>),\]&]+"
)


def valid_chatgpt_share_url(value: str) -> bool:
    parsed = urlparse(value)
    return parsed.scheme == "https" and (parsed.hostname or "").lower() in CHATGPT_HOSTS and (
        parsed.path.startswith("/s/") or parsed.path.startswith("/share/")
    )


def approved_chatgpt_origin(value: str) -> str | None:
    """Return ``https://<host>`` when ``value`` is on a ChatGPT origin, else None.

    The URL must use HTTPS with a ChatGPT host and no user information or
    explicit port, so look-alikes such as ``chatgpt.com.example``,
    ``chatgpt.com@host`` or ``chatgpt.com:8443`` are refused.
    """
    try:
        parsed = urlparse(str(value))
    except ValueError:
        return None
    netloc = parsed.netloc.lower()
    if parsed.scheme != "https" or netloc not in CHATGPT_HOSTS:
        return None
    return f"https://{netloc}"
