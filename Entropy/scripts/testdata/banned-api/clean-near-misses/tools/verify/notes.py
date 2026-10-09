import secrets  # never the random module
import randomart
from randomart import draw
import os, randomart
import os, secrets  # no random module
key = os.urandom(32)
token = secrets.token_bytes(32)  # docs/design.md: "In Python use os.urandom or secrets only"
from randomart import (
    draw,
    randomart,
)
words = ["random", "range"]
