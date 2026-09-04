"""
IMAP Email Monitor Module

Connects to an IMAP server, polls for new emails at a configurable interval,
and runs each new email through the threat analysis pipeline.
"""

import email as email_lib
import imaplib
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class IMAPMonitor:
    """Background IMAP email monitor that polls for new messages."""

    def __init__(self):
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._config: dict[str, Any] = {}
        self._status: dict[str, Any] = {
            "active": False,
            "emails_processed": 0,
            "last_check": None,
            "error": None,
            "connected_to": None,
        }
        self._seen_uids: set[str] = set()

    @property
    def status(self) -> dict[str, Any]:
        return {**self._status}

    @property
    def is_active(self) -> bool:
        return self._status["active"]

    def start(self, config: dict[str, Any], analysis_callback) -> dict[str, Any]:
        """Start the IMAP monitor with the given config."""
        if self.is_active:
            return {"success": False, "message": "Monitor is already running"}

        self._config = config
        self._stop_event.clear()
        self._status["error"] = None
        self._status["emails_processed"] = 0
        self._seen_uids = set()

        # Test connection first
        try:
            conn = self._connect()
            conn.logout()
        except Exception as e:
            return {"success": False, "message": f"Connection failed: {str(e)}"}

        self._thread = threading.Thread(
            target=self._poll_loop,
            args=(analysis_callback,),
            daemon=True,
        )
        self._thread.start()
        self._status["active"] = True
        self._status["connected_to"] = config.get("email", "")

        return {"success": True, "message": "IMAP monitor started"}

    def stop(self) -> dict[str, Any]:
        """Stop the IMAP monitor."""
        if not self.is_active:
            return {"success": False, "message": "Monitor is not running"}

        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)
        self._status["active"] = False
        self._status["connected_to"] = None

        return {"success": True, "message": "IMAP monitor stopped"}

    def _connect(self) -> imaplib.IMAP4_SSL:
        """Create and authenticate an IMAP connection."""
        host = self._config["host"]
        port = int(self._config.get("port", 993))
        email_addr = self._config["email"]
        password = self._config["password"]

        conn = imaplib.IMAP4_SSL(host, port)
        conn.login(email_addr, password)
        return conn

    def _poll_loop(self, analysis_callback):
        """Main polling loop that checks for new emails."""
        interval = int(self._config.get("interval", 30))
        folder = self._config.get("folder", "INBOX")

        while not self._stop_event.is_set():
            try:
                conn = self._connect()
                conn.select(folder, readonly=True)

                # Search for all emails (or UNSEEN for unread only)
                status, data = conn.search(None, "ALL")
                if status == "OK" and data[0]:
                    uids = data[0].split()
                    # Only process new UIDs
                    new_uids = [uid for uid in uids if uid.decode() not in self._seen_uids]

                    for uid in new_uids[-10:]:  # Process max 10 new emails per cycle
                        uid_str = uid.decode()
                        if uid_str in self._seen_uids:
                            continue

                        try:
                            status, msg_data = conn.fetch(uid, "(RFC822)")
                            if status == "OK" and msg_data[0]:
                                raw_email = msg_data[0][1]
                                if isinstance(raw_email, bytes):
                                    analysis_callback(raw_email, f"imap_email_{uid_str}.eml")
                                    self._status["emails_processed"] += 1
                        except Exception as e:
                            logger.warning(f"Failed to process email UID {uid_str}: {e}")

                        self._seen_uids.add(uid_str)

                self._status["last_check"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                self._status["error"] = None
                conn.logout()

            except Exception as e:
                logger.error(f"IMAP poll error: {e}")
                self._status["error"] = str(e)

            # Wait for interval or stop signal
            self._stop_event.wait(timeout=interval)

        self._status["active"] = False


# Global singleton
imap_monitor = IMAPMonitor()
