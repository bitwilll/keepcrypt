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
    handlers_seen,
)
NOTE = "a socket import is refused"  # socket import: only in a string and this comment
cert_note = with_ssl \
    or None  # a continued line that ends in a longer name
import urllib3_shim  # urllib3: a local module with a longer name
from socketserver_notes import PORTS  # socketserver: a longer name after from
import json, wsgiref_docs  # wsgiref: a longer name in an import list
smtpd_port = 25  # smtpd: a name, not an import
loop = self.asyncore_loop  # asyncore: inside a longer attribute
"""No asynchat session and no nntplib group."""
from multiprocessing import Pool  # the package runs offline; its connection module is refused
import logging  # the package runs offline; logging.handlers is refused
from db_notes import connection_count  # connection: a longer name in an import
from logging import StreamHandler  # handlers: only in this comment
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
# Look-alikes of the other routes too: the module import, the Qt attribute, pandas, tkinter, the
# PowerShell cmdlets, the Windows tool and the AppleScript phrase.
has_win32clipboard = False
last_selection_get = None
allow_to_clipboard = False
skip_read_clipboard = True
wl_paste = None
HINTS = ("target-clipboard", "asset-clipboard")  # the two cmdlets, inside longer words
get_clipboard_text = set_clipboard_text = None  # with _ where the cmdlets have -
PLAYER = "videoclip.exe"  # inside a longer name
clip = summary[:40]  # a common word, so only its .exe form hits
the_clipboard = None  # a name, not osascript's phrase
SHOP = "lathe clipboard"  # after a longer word that ends in the
text = history.clipboard_text  # a longer attribute
import clipboard_notes  # a local module with a longer name
