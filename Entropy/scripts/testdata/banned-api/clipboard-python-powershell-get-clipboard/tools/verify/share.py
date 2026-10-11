rolls = subprocess.run(["powershell", "-Command", "Get-Clipboard"], capture_output=True, check=True).stdout
