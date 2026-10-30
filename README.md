# Simple Python Security Scanner (SAST)

A custom static code analysis tool that checks Python files for security flaws like hardcoded secrets, `eval()`, and insecure `subprocess` commands.

## How to Run

Pass the file or directory you want to scan as an argument:

```bash
# Scan a specific file
python scanner.py vulnerabletest.py

# Scan the current dissrectory
python scanner.py .
```
