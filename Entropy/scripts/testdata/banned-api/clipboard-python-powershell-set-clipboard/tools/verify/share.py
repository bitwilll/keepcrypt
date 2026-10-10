# PowerShell ignores letter case.
subprocess.run(["pwsh", "-c", "set-clipboard"], input=data, check=True)
