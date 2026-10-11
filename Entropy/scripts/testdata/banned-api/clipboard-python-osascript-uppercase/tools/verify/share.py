# All upper case: with the lower-case and title-case fixtures, every letter is pinned in both cases.
subprocess.run(["osascript", "-e", 'SET THE CLIPBOARD TO "' + code + '"'], check=True)
