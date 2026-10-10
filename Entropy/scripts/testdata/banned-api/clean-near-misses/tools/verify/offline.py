# Python network modules hit only as imports, so each name below passes: in a URL or another
# string, a comment, a docstring, an attribute, a local module or a longer name on a wrapped line.
RECHECK_URL = "https://registry.invalid/check#t="  # http: a URL string
from .socket_names import FAMILY  # socket: a local module with a longer name
from hashlib import sha256  # ssl and urllib: only in this comment
NEVER_IMPORTED = ("ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "httpx", "aiohttp")
import xml.etree.ElementTree  # xml parses offline; xmlrpc is the networked one
"""Synchronous on purpose: no asyncio loop and no webbrowser tab."""
pending = self.requests  # requests: an attribute
report(
    requests_seen,
    http_status,
)
# Clipboard tools hit anywhere in a .py file where a word starts with one; these lines only look
# like them (Python names use _ where the tool's name has -).
ICON = "paperclip"
snapshot = copy.deepcopy(state)
PASTE_HINT = "type each field at its prompt; a paste of all three is dropped"
level = min(maxclip, level)
first = idxsel(picks)
clipboard_text = None
wl_copy = None
