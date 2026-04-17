import imaplib
import email
import email.policy
from dataclasses import dataclass
from typing import Optional


GMAIL_IMAP = "imap.gmail.com"
GMAIL_PORT = 993


@dataclass
class EmailSummary:
    uid: str
    subject: str
    sender: str
    date: str
    raw: str


def connect(address: str, app_password: str) -> imaplib.IMAP4_SSL:
    conn = imaplib.IMAP4_SSL(GMAIL_IMAP, GMAIL_PORT)
    conn.login(address, app_password)
    return conn


def fetch_inbox(conn: imaplib.IMAP4_SSL, limit: int = 30) -> list[EmailSummary]:
    conn.select("INBOX", readonly=True)
    _, data = conn.search(None, "ALL")
    uids = data[0].split()
    uids = uids[-limit:]  # most recent N
    uids = list(reversed(uids))  # newest first

    emails = []
    for uid in uids:
        _, msg_data = conn.fetch(uid, "(RFC822)")
        raw = msg_data[0][1]
        if isinstance(raw, bytes):
            raw_str = raw.decode("utf-8", errors="replace")
        else:
            raw_str = str(raw)

        msg = email.message_from_string(raw_str, policy=email.policy.default)
        emails.append(EmailSummary(
            uid=uid.decode(),
            subject=_decode_header(msg.get("Subject", "(no subject)")),
            sender=msg.get("From", "(unknown)"),
            date=msg.get("Date", ""),
            raw=raw_str,
        ))
    return emails


def fetch_folder(conn: imaplib.IMAP4_SSL, folder: str, limit: int = 30) -> list[EmailSummary]:
    conn.select(folder, readonly=True)
    _, data = conn.search(None, "ALL")
    uids = data[0].split()
    uids = uids[-limit:]
    uids = list(reversed(uids))

    emails = []
    for uid in uids:
        _, msg_data = conn.fetch(uid, "(RFC822)")
        raw = msg_data[0][1]
        if isinstance(raw, bytes):
            raw_str = raw.decode("utf-8", errors="replace")
        else:
            raw_str = str(raw)

        msg = email.message_from_string(raw_str, policy=email.policy.default)
        emails.append(EmailSummary(
            uid=uid.decode(),
            subject=_decode_header(msg.get("Subject", "(no subject)")),
            sender=msg.get("From", "(unknown)"),
            date=msg.get("Date", ""),
            raw=raw_str,
        ))
    return emails


def list_folders(conn: imaplib.IMAP4_SSL) -> list[str]:
    _, folders = conn.list()
    names = []
    for f in folders:
        parts = f.decode().split('"/"')
        if parts:
            name = parts[-1].strip().strip('"')
            names.append(name)
    return names


def _decode_header(value: str) -> str:
    try:
        from email.header import decode_header
        parts = decode_header(value)
        decoded = []
        for part, enc in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return "".join(decoded)
    except Exception:
        return value
