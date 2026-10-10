# AppleScript ignores letter case.
subprocess.run(["osascript", "-e", 'set The Clipboard to "' + code + '"'], check=True)
