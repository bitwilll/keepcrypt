# All upper case: with the title-case and lower-case fixtures, every letter is pinned in both cases.
rolls = subprocess.run(["powershell", "-Command", "GET-CLIPBOARD"], capture_output=True, check=True).stdout
