subprocess.run(["osascript", "-l", "JavaScript", "-e", "Application.currentApplication().setTheClipboardTo('x')"], check=True)
