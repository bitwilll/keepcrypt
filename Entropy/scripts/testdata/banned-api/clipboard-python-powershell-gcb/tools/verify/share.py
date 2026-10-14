rolls = subprocess.run(["powershell", "-Command", "gcb"], capture_output=True, check=True).stdout
