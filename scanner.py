import ast
import os
import re
import sys


SECRET_PATTERNS = [
    re.compile(r'(?i)(password|secret|passwd|aws_key|token|api_key)\s*=\s*[\'"][^\'"]+[\'"]'),
    re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----')
]

class SecurityScanner(ast.NodeVisitor): 
    def __init__(self, filename):
        self.filename = filename
        self.issues = []

    def visit_Call(self, node):
       
        if isinstance(node.func, ast.Name):
            if node.func.id in ['eval', 'exec']:
                self.issues.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "CRITICAL",
                    "issue": f"Insecure utilize of dangerous builtin function: {node.func.id}()"
                })
        
       
        elif isinstance(node.func, ast.Attribute):
            if node.func.attr in ['run', 'Popen', 'call', 'check_output']:
                
                for kw in node.keywords:
                    if kw.arg == 'shell' and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.issues.append({
                            "file": self.filename,
                            "line": node.lineno,
                            "severity": "HIGH",
                            "issue": "Subprocess call with shell=True detected. High risk of Command Injection."
                        })
        
        self.generic_visit(node)

    def scan_raw_text(self, content):
        """Scans code line-by-line for things AST might miss, like hardcoded secrets in strings."""
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    self.issues.append({
                        "file": self.filename,
                        "line": idx,
                        "severity": "HIGH",
                        "issue": f"Possible hardcoded secret or token found: {line.strip()}"
                    })

def scan_file(filepath):
    """Parses and scans a single Python file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        scanner = SecurityScanner(filepath)
        scanner.scan_raw_text(content) 
        
        tree = ast.parse(content, filename=filepath)
        scanner.visit(tree)
        
        return scanner.issues
    except SyntaxError:
        return [{"file": filepath, "line": 0, "severity": "LOW", "issue": "Syntax error. Could not parse file into AST."}]
    except Exception as e:
        return [{"file": filepath, "line": 0, "severity": "LOW", "issue": f"Error reading file: {str(e)}"}]

def main():
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    
    if not os.path.exists(target_dir):
        print(f"Error: Target path '{target_dir}' does not exist.")
        sys.exit(1)
        
    all_issues = []
    print(f"  Starting Python Security Scan on target: {target_dir}\n" + "="*60)
    
    if os.path.isfile(target_dir) and target_dir.endswith('.py'):
        all_issues.extend(scan_file(target_dir))
    else:
        for root, _, files in os.walk(target_dir):
            for file in files:
                if file.endswith('.py') and file != 'scanner.py': 
                    full_path = os.path.join(root, file)
                    all_issues.extend(scan_file(full_path))
                    
    if not all_issues:
        print(" No critical vulnerabilities found!")
        sys.exit(0)
        
    for issue in all_issues:
        print(f"[{issue['severity']}] {issue['file']}:{issue['line']} -> {issue['issue']}")
        
    print("="*60)
    print(f" Scan complete. Found {len(all_issues)} security flaw(s).")
    sys.exit(1) 

if __name__ == '__main__':
    main()
