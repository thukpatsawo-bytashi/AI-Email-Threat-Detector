# 📧 RFC-822 Email Parser Module

The Email Parser (`backend/analyzers/email_parser.py`) converts raw RFC-822 `.eml` byte streams into a normalized Python dictionary consumed by the header, NLP, URL, and IP analysis pipelines.

---

## Usage

```python
from analyzers import parse_email

with open("sample.eml", "rb") as f:
    file_bytes = f.read()

parsed = parse_email(file_bytes)
```

---

## Output Dictionary Schema

The parser normalizes message data into the following structure:

| Key | Type | Description |
|---|---|---|
| `from` | `str` | Full `From:` header content including display name and address |
| `to` | `str` | Full `To:` header recipient string |
| `subject` | `str` | Decoded email subject line |
| `reply_to` | `str` | `Reply-To:` header if present (fallback to `From`) |
| `return_path` | `str` | Envelope sender (`Return-Path:`) |
| `message_id` | `str` | Unique RFC-822 `Message-ID:` identifier |
| `body` | `str` | Sanitized plain-text body (HTML stripped, script tags removed, entities decoded) |
| `raw_html` | `str` | Concatenated `text/html` parts for URL & anchor analysis |
| `raw_headers` | `dict[str, str]` | Normalized dictionary of all RFC-822 headers |
| `received_chain` | `list[str]` | Ordered list of all `Received:` hops from newest to oldest |
