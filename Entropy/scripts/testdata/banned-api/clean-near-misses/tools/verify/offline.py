# Python network modules hit only as imports, so each name below passes: in a URL or another
# string, a comment, a docstring, an attribute, a local module or a longer name in an import.
RECHECK_URL = "https://registry.invalid/check#t="  # http: a URL string
from .socket_names import FAMILY  # socket: a local module with a longer name
import ssl_pins  # ssl: a local module with a longer name
import json, http_codes  # http: a longer name in an import list
from urllib_parts import QUERY  # urllib: a longer name after from
ALREADY = "reimport socket"  # socket: after a longer word that ends in import
from hashlib import sha256  # ssl and urllib: only in this comment
NEVER_IMPORTED = ("ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "httpx", "aiohttp")
C_MODULES = ("_socket", "_ssl")  # the C modules behind socket and ssl, as strings
import xml.etree.ElementTree  # xml parses offline; xmlrpc is the networked one
"""Synchronous on purpose: no asyncio loop and no webbrowser tab."""
pending = self.requests  # requests: an attribute
report(
    requests_seen,
    http_status,
)
NOTE = "a socket import is refused"  # socket import: only in a string and this comment
cert_note = with_ssl \
    or None  # a continued line that ends in a longer name
# Clipboard tools hit anywhere in a .py file where a word starts with one; these lines only look
# like them (inside a longer name, or with _ where the tool's name has -).
ICON = "paperclip"
snapshot = copy.deepcopy(state)
PASTE_HINT = "type each field at its prompt; a paste of all three is dropped"
level = min(maxclip, level)
first = idxsel(picks)
clipboard_text = None
wl_copy = None
hint_id = "no_pyperclip"
skip_clipboard_get = True
