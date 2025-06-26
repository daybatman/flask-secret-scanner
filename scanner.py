import os
import re
import sys
import json
import csv
from datetime import datetime

# Define regex patterns for common secrets
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Slack Token": r"xox[baprs]-([0-9a-zA-Z]{10,48})",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "GitHub Personal Access Token": r"gho_[0-9a-zA-Z]{36}",
    "GitHub Fine-grained Token": r"github_pat_[0-9a-zA-Z]{82}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Discord Token": r"[MN][a-zA-Z0-9]{23}\.[\w-]{6}\.[\w-]{27}",
    "Firebase URL": r".*firebaseio\.com",
    "MongoDB Connection String": r"mongodb(\+srv)?://[a-zA-Z0-9.-]+:[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+",
    "PostgreSQL Connection String": r"postgresql://[a-zA-Z0-9.-]+:[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+",
    "MySQL Connection String": r"mysql://[a-zA-Z0-9.-]+:[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+",
    "Redis Connection String": r"redis://[a-zA-Z0-9.-]+:[a-zA-Z0-9.-]+@[a-zA-Z0-9.-]+",
    "Generic API Key": r"(?i)(api[_-]?key|apikey)[\s\"']*[:=][\s\"']*[0-9a-zA-Z!@#$%^&*()_+=\-]{8,}",
    "Generic Secret": r"(?i)(secret|password|token|key)[\s\"']*[:=][\s\"']*[0-9a-zA-Z!@#$%^&*()_+=\-]{8,}",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "RSA Private Key": r"-----BEGIN RSA PRIVATE KEY-----",
    "SSH Private Key": r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "Certificate": r"-----BEGIN CERTIFICATE-----",
    "Base64 Encoded Secret": r"(?i)(secret|password|token|key)[\s\"']*[:=][\s\"']*[A-Za-z0-9+/]{20,}={0,2}",
    "Hex Encoded Secret": r"(?i)(secret|password|token|key)[\s\"']*[:=][\s\"']*[0-9a-fA-F]{16,}",
    "JWT Token": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
    "UUID": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Credit Card Number": r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
    "Email Address": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "Phone Number": r"(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}",
    "IP Address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "URL": r"https?://[^\s<>\"{}|\\^`\[\]]+",
    "File Path": r"(?i)(file|path|dir)[\s\"']*[:=][\s\"']*[/\\][^\s\"']+",
    "Environment Variable": r"\$[A-Z_][A-Z0-9_]*",
    "Hardcoded Credentials": r"(?i)(username|user|login|email)[\s\"']*[:=][\s\"']*[^\s\"']+[\s\"']*[,}\n][\s\"']*(password|pass|pwd)[\s\"']*[:=][\s\"']*[^\s\"']+"
}

# Directories and files to ignore
IGNORE_DIRS = {".git", "venv", "__pycache__", "node_modules", ".vscode", ".idea", "dist", "build", ".pytest_cache", "coverage"}

# Global variables to store scan results
scan_results = {
    "directory_findings": [],
    "code_findings": [],
    "scan_metadata": {}
}

# ANSI color codes for better interface
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_header():
    """Print the application header"""
    print(f"{Colors.HEADER}{Colors.BOLD}")
    print("=" * 70)
    print("           🔍 SECRET SCANNER 🔍")
    print("     Advanced Code & Directory Scanner")
    print("=" * 70)
    print(f"{Colors.ENDC}")


def print_about():
    """Print detailed information about the tool"""
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}=== ABOUT SECRET SCANNER ==={Colors.ENDC}")
    print(f"{Colors.OKBLUE}What this tool does:{Colors.ENDC}")
    print("  • Scans code and files for sensitive information and secrets")
    print("  • Detects API keys, tokens, passwords, and other credentials")
    print("  • Identifies hardcoded secrets that could be security risks")
    print("  • Supports both individual code snippets and entire directories")
    print("  • Generates detailed reports for security audits")
    
    print(f"\n{Colors.OKBLUE}Security Categories Detected:{Colors.ENDC}")
    print("  🔐 Authentication Tokens (GitHub, Slack, Discord, etc.)")
    print("  💳 Payment & API Keys (Stripe, AWS, Google, etc.)")
    print("  🗄️  Database Connection Strings (MongoDB, PostgreSQL, etc.)")
    print("  🔑 Private Keys & Certificates (RSA, SSH, SSL)")
    print("  📧 Personal Information (Emails, Phone Numbers, IPs)")
    print("  💳 Financial Data (Credit Cards, Account Numbers)")
    print("  🔗 URLs & File Paths (Potential information disclosure)")
    
    print(f"\n{Colors.WARNING}⚠️  IMPORTANT:{Colors.ENDC}")
    print("  • This tool is for security auditing and educational purposes")
    print("  • Always handle found secrets responsibly and securely")
    print("  • Consider using environment variables instead of hardcoded secrets")
    print("  • Regularly rotate and update your API keys and tokens")


def print_success(message):
    """Print success message"""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")


def print_warning(message):
    """Print warning message"""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")


def print_error(message):
    """Print error message"""
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")


def print_info(message):
    """Print info message"""
    print(f"{Colors.OKBLUE}ℹ {message}{Colors.ENDC}")


def print_secret_found(secret_type, value):
    """Print found secret with formatting"""
    display_value = value[:80] + "..." if len(value) > 80 else value
    print(f"{Colors.FAIL}  🔐 {secret_type}: {display_value}{Colors.ENDC}")


def export_results(format_type="txt"):
    """Export scan results to various formats"""
    if not scan_results["directory_findings"] and not scan_results["code_findings"]:
        print_warning("No scan results to export. Please run a scan first.")
        return
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format_type == "txt":
        filename = f"secret_scan_report_{timestamp}.txt"
        export_txt_report(filename)
    elif format_type == "json":
        filename = f"secret_scan_report_{timestamp}.json"
        export_json_report(filename)
    elif format_type == "csv":
        filename = f"secret_scan_report_{timestamp}.csv"
        export_csv_report(filename)
    elif format_type == "html":
        filename = f"secret_scan_report_{timestamp}.html"
        export_html_report(filename)
    else:
        print_error("Invalid export format. Supported: txt, json, csv, html")
        return
    
    print_success(f"Report exported to: {filename}")


def export_txt_report(filename):
    """Export results as text report"""
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("           SECRET SCANNER REPORT\n")
        f.write("=" * 70 + "\n\n")
        
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scanner Version: 2.0\n\n")
        
        # Directory findings
        if scan_results["directory_findings"]:
            f.write("DIRECTORY SCAN RESULTS:\n")
            f.write("-" * 30 + "\n")
            for file_path, findings in scan_results["directory_findings"]:
                f.write(f"\nFile: {file_path}\n")
                for secret_type, matches in findings:
                    f.write(f"  {secret_type}:\n")
                    for match in set(matches):
                        f.write(f"    - {match}\n")
        
        # Code findings
        if scan_results["code_findings"]:
            f.write("\n\nPASTED CODE SCAN RESULTS:\n")
            f.write("-" * 30 + "\n")
            for secret_type, matches in scan_results["code_findings"]:
                f.write(f"\n{secret_type}:\n")
                for match in set(matches):
                    f.write(f"  - {match}\n")
        
        # Summary
        f.write("\n\nSUMMARY:\n")
        f.write("-" * 10 + "\n")
        f.write(f"Total files with secrets: {len(scan_results['directory_findings'])}\n")
        f.write(f"Total secret types in code: {len(scan_results['code_findings'])}\n")
        
        if scan_results["scan_metadata"]:
            f.write(f"Files scanned: {scan_results['scan_metadata'].get('files_scanned', 0)}\n")
            f.write(f"Scan duration: {scan_results['scan_metadata'].get('duration', 0):.2f} seconds\n")


def export_json_report(filename):
    """Export results as JSON report"""
    report_data = {
        "scan_info": {
            "date": datetime.now().isoformat(),
            "scanner_version": "2.0",
            "total_files_with_secrets": len(scan_results["directory_findings"]),
            "total_secret_types_in_code": len(scan_results["code_findings"]),
            "metadata": scan_results["scan_metadata"]
        },
        "directory_findings": scan_results["directory_findings"],
        "code_findings": scan_results["code_findings"]
    }
    
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)


def export_csv_report(filename):
    """Export results as CSV report"""
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Source', 'File Path', 'Secret Type', 'Value'])
        
        # Directory findings
        for file_path, findings in scan_results["directory_findings"]:
            for secret_type, matches in findings:
                for match in set(matches):
                    writer.writerow(['Directory', file_path, secret_type, match])
        
        # Code findings
        for secret_type, matches in scan_results["code_findings"]:
            for match in set(matches):
                writer.writerow(['Pasted Code', 'N/A', secret_type, match])


def export_html_report(filename):
    """Export results as HTML report"""
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secret Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; color: #333; border-bottom: 2px solid #007bff; padding-bottom: 20px; margin-bottom: 30px; }}
        .section {{ margin-bottom: 30px; }}
        .section h2 {{ color: #007bff; border-left: 4px solid #007bff; padding-left: 15px; }}
        .secret-item {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; margin: 5px 0; border-radius: 4px; }}
        .file-path {{ color: #6c757d; font-size: 0.9em; margin-bottom: 10px; }}
        .secret-type {{ font-weight: bold; color: #dc3545; }}
        .secret-value {{ font-family: monospace; background: #f8f9fa; padding: 2px 4px; border-radius: 2px; }}
        .summary {{ background: #e9ecef; padding: 15px; border-radius: 4px; }}
        .no-secrets {{ color: #28a745; font-style: italic; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Secret Scanner Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h2>📁 Directory Scan Results</h2>
"""
    
    if scan_results["directory_findings"]:
        for file_path, findings in scan_results["directory_findings"]:
            html_content += f'<div class="file-path">📄 {file_path}</div>\n'
            for secret_type, matches in findings:
                for match in set(matches):
                    html_content += f'<div class="secret-item"><span class="secret-type">{secret_type}:</span> <span class="secret-value">{match}</span></div>\n'
    else:
        html_content += '<p class="no-secrets">✓ No secrets found in directory scan</p>\n'
    
    html_content += """
        </div>
        
        <div class="section">
            <h2>📝 Pasted Code Scan Results</h2>
"""
    
    if scan_results["code_findings"]:
        for secret_type, matches in scan_results["code_findings"]:
            for match in set(matches):
                html_content += f'<div class="secret-item"><span class="secret-type">{secret_type}:</span> <span class="secret-value">{match}</span></div>\n'
    else:
        html_content += '<p class="no-secrets">✓ No secrets found in pasted code</p>\n'
    
    html_content += f"""
        </div>
        
        <div class="section">
            <h2>📊 Summary</h2>
            <div class="summary">
                <p><strong>Total files with secrets:</strong> {len(scan_results["directory_findings"])}</p>
                <p><strong>Total secret types in code:</strong> {len(scan_results["code_findings"])}</p>
"""
    
    if scan_results["scan_metadata"]:
        html_content += f"""
                <p><strong>Files scanned:</strong> {scan_results['scan_metadata'].get('files_scanned', 0)}</p>
                <p><strong>Scan duration:</strong> {scan_results['scan_metadata'].get('duration', 0):.2f} seconds</p>
"""
    
    html_content += """
            </div>
        </div>
    </div>
</body>
</html>
"""
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html_content)


def scan_content(content, source_name="pasted code"):
    """Scan content for secrets and return findings"""
    secrets_found = []
    
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            # Clean up matches and remove duplicates
            cleaned_matches = []
            for match in matches:
                if isinstance(match, tuple):
                    # Handle groups in regex
                    match = ''.join(match)
                if match and match not in cleaned_matches:
                    cleaned_matches.append(match)
            
            if cleaned_matches:
                secrets_found.append((name, cleaned_matches))
    
    return secrets_found


def scan_file(file_path):
    """Scan a file for secrets"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            return scan_content(content, file_path)
    except Exception as e:
        print_error(f"Error reading {file_path}: {e}")
        return []


def scan_directory(directory):
    """Scan a directory for secrets in files"""
    total_findings = 0
    files_scanned = 0
    start_time = datetime.now()
    
    print_info(f"Scanning directory: {directory}")
    print_info("This may take a while for large directories...")
    
    # Clear previous directory findings
    scan_results["directory_findings"] = []
    
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for file in files:
            full_path = os.path.join(root, file)
            files_scanned += 1
            
            # Show progress every 100 files
            if files_scanned % 100 == 0:
                print_info(f"Scanned {files_scanned} files...")
            
            results = scan_file(full_path)
            if results:
                total_findings += 1
                scan_results["directory_findings"].append((full_path, results))
                print(f"\n{Colors.WARNING}[!] Secrets found in {full_path}{Colors.ENDC}")
                for name, matches in results:
                    for match in set(matches):
                        print_secret_found(name, match)
    
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    # Store metadata
    scan_results["scan_metadata"] = {
        "files_scanned": files_scanned,
        "duration": duration,
        "directory": directory
    }
    
    print(f"\n{Colors.OKBLUE}{'='*50}{Colors.ENDC}")
    print_info(f"Directory scan completed in {duration:.2f} seconds")
    print_info(f"Files scanned: {files_scanned}")
    
    if total_findings == 0:
        print_success("No secrets found in scanned files.")
    else:
        print_warning(f"Total files with secrets: {total_findings}")
    
    return total_findings


def scan_pasted_code():
    """Scan pasted code for secrets"""
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}=== Code Input Mode ==={Colors.ENDC}")
    print_info("Paste your code below:")
    print_info("• Press Ctrl+D (Unix/Linux) or Ctrl+Z (Windows) when done")
    print_info("• Or type 'END' on a new line to finish")
    print_info("• Or type 'FILE:path/to/file' to scan a specific file")
    print(f"{Colors.OKBLUE}{'─'*50}{Colors.ENDC}")
    
    lines = []
    try:
        while True:
            line = input()
            if line.strip() == "END":
                break
            if line.strip().startswith("FILE:"):
                file_path = line.strip()[5:].strip()
                if os.path.isfile(file_path):
                    print_info(f"Scanning file: {file_path}")
                    results = scan_file(file_path)
                    if results:
                        print(f"\n{Colors.WARNING}[!] Secrets found in {file_path}{Colors.ENDC}")
                        for name, matches in results:
                            for match in set(matches):
                                print_secret_found(name, match)
                    else:
                        print_success(f"No secrets found in {file_path}")
                else:
                    print_error(f"File not found: {file_path}")
                return
            lines.append(line)
    except EOFError:
        pass
    
    if not lines:
        print_warning("No code provided.")
        return
    
    content = '\n'.join(lines)
    results = scan_content(content, "pasted code")
    
    # Store code findings
    scan_results["code_findings"] = results
    
    print(f"\n{Colors.OKBLUE}{'='*50}{Colors.ENDC}")
    
    if results:
        print_warning(f"Found {len(results)} types of secrets in pasted code:")
        for name, matches in results:
            print(f"\n{Colors.WARNING}  {name}:{Colors.ENDC}")
            for match in set(matches):
                print_secret_found(name, match)
    else:
        print_success("No secrets found in pasted code.")


def combined_scan():
    """Scan both pasted code and a directory"""
    print(f"\n{Colors.OKCYAN}{Colors.BOLD}=== Combined Scan Mode ==={Colors.ENDC}")
    
    # First, get the directory
    while True:
        target_dir = input(f"{Colors.OKBLUE}Enter directory to scan: {Colors.ENDC}").strip()
        if os.path.isdir(target_dir):
            break
        else:
            print_error("Invalid directory. Please try again.")
    
    # Then get the pasted code
    print(f"\n{Colors.OKBLUE}Now paste your code to scan:{Colors.ENDC}")
    print_info("Press Ctrl+D (Unix/Linux) or Ctrl+Z (Windows) when done, or type 'END'")
    
    lines = []
    try:
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
    except EOFError:
        pass
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== SCANNING RESULTS ==={Colors.ENDC}")
    
    # Scan directory
    print(f"\n{Colors.OKCYAN}1. Directory Scan Results:{Colors.ENDC}")
    dir_findings = scan_directory(target_dir)
    
    # Scan pasted code
    print(f"\n{Colors.OKCYAN}2. Pasted Code Scan Results:{Colors.ENDC}")
    if lines:
        content = '\n'.join(lines)
        code_results = scan_content(content, "pasted code")
        scan_results["code_findings"] = code_results
        
        if code_results:
            print_warning(f"Found {len(code_results)} types of secrets in pasted code:")
            for name, matches in code_results:
                print(f"\n{Colors.WARNING}  {name}:{Colors.ENDC}")
                for match in set(matches):
                    print_secret_found(name, match)
        else:
            print_success("No secrets found in pasted code.")
    else:
        print_warning("No code provided for scanning.")
        scan_results["code_findings"] = []
    
    # Summary
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== SUMMARY ==={Colors.ENDC}")
    print_info(f"Directory files with secrets: {dir_findings}")
    print_info(f"Pasted code secret types: {len(scan_results['code_findings'])}")
    
    if dir_findings == 0 and len(scan_results["code_findings"]) == 0:
        print_success("🎉 No secrets found in either source!")
    else:
        print_warning("⚠️  Secrets were found. Please review and secure them!")


def show_help():
    """Show help information"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}=== HELP ==={Colors.ENDC}")
    print_info("This tool scans for various types of secrets and sensitive information:")
    print("\nSecret Types Detected:")
    for secret_type in SECRET_PATTERNS.keys():
        print(f"  • {secret_type}")
    
    print(f"\n{Colors.OKBLUE}Usage Tips:{Colors.ENDC}")
    print("  • Use option 1 for quick code scanning")
    print("  • Use option 2 for scanning entire directories")
    print("  • Use option 3 for comprehensive scanning")
    print("  • Use option 6 to export results in various formats")
    print("  • In code input mode, you can also type 'FILE:path' to scan a specific file")
    print("  • The tool ignores common directories like .git, node_modules, etc.")
    
    print(f"\n{Colors.OKBLUE}Export Formats:{Colors.ENDC}")
    print("  • TXT: Simple text report")
    print("  • JSON: Structured data format")
    print("  • CSV: Spreadsheet-friendly format")
    print("  • HTML: Beautiful web report")


def main():
    """Main function with enhanced menu"""
    while True:
        print_header()
        print(f"{Colors.OKBLUE}Select an option:{Colors.ENDC}")
        print("  1. 🔍 Scan pasted code")
        print("  2. 📁 Scan directory")
        print("  3. 🔄 Combined scan (code + directory)")
        print("  4. ℹ️  About this tool")
        print("  5. ❓ Help")
        print("  6. 📄 Export results")
        print("  7. 🚪 Exit")
        
        choice = input(f"\n{Colors.OKCYAN}Enter your choice (1-7): {Colors.ENDC}").strip()
        
        if choice == "1":
            scan_pasted_code()
        elif choice == "2":
            target_dir = input(f"{Colors.OKBLUE}Enter directory to scan: {Colors.ENDC}").strip()
    if os.path.isdir(target_dir):
        scan_directory(target_dir)
    else:
                print_error("Invalid directory.")
        elif choice == "3":
            combined_scan()
        elif choice == "4":
            print_about()
        elif choice == "5":
            show_help()
        elif choice == "6":
            if not scan_results["directory_findings"] and not scan_results["code_findings"]:
                print_warning("No scan results to export. Please run a scan first.")
            else:
                print(f"\n{Colors.OKBLUE}Select export format:{Colors.ENDC}")
                print("  1. TXT (Text report)")
                print("  2. JSON (Structured data)")
                print("  3. CSV (Spreadsheet)")
                print("  4. HTML (Web report)")
                format_choice = input(f"{Colors.OKCYAN}Enter format choice (1-4): {Colors.ENDC}").strip()
                
                format_map = {"1": "txt", "2": "json", "3": "csv", "4": "html"}
                if format_choice in format_map:
                    export_results(format_map[format_choice])
                else:
                    print_error("Invalid format choice.")
        elif choice == "7":
            print(f"\n{Colors.OKGREEN}Thank you for using Secret Scanner! 👋{Colors.ENDC}")
            break
        else:
            print_error("Invalid choice. Please select 1-7.")
        
        if choice in ["1", "2", "3"]:
            input(f"\n{Colors.OKBLUE}Press Enter to continue...{Colors.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Scan interrupted by user.{Colors.ENDC}")
        sys.exit(0)
