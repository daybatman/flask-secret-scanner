from flask import Flask, render_template, request, jsonify, send_file, session
import os
import re
import json
import csv
import io
from datetime import datetime
from werkzeug.utils import secure_filename
import tempfile
import zipfile

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

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

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {'.txt', '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.c', '.cpp', '.h', '.hpp', '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.sh', '.bash', '.zsh', '.fish', '.ps1', '.bat', '.cmd', '.yml', '.yaml', '.json', '.xml', '.html', '.htm', '.css', '.scss', '.sass', '.less', '.sql', '.md', '.rst', '.ini', '.cfg', '.conf', '.env', '.properties', '.toml', '.lock', '.log', '.csv', '.tsv', '.dat', '.bak', '.tmp', '.temp'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS)

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

def scan_file_content(file_content, filename):
    """Scan file content for secrets"""
    try:
        # Try to decode as text
        if isinstance(file_content, bytes):
            content = file_content.decode('utf-8', errors='ignore')
        else:
            content = file_content
        return scan_content(content, filename)
    except Exception as e:
        return []

def scan_uploaded_files(files):
    """Scan multiple uploaded files"""
    results = []
    total_files = 0
    files_with_secrets = 0
    
    for file in files:
        if file and allowed_file(file.filename):
            total_files += 1
            try:
                content = file.read()
                file_results = scan_file_content(content, file.filename)
                if file_results:
                    files_with_secrets += 1
                    results.append({
                        'filename': file.filename,
                        'findings': file_results
                    })
            except Exception as e:
                continue
    
    return {
        'files_scanned': total_files,
        'files_with_secrets': files_with_secrets,
        'results': results
    }

def scan_zip_file(zip_file):
    """Scan contents of a ZIP file"""
    results = []
    total_files = 0
    files_with_secrets = 0
    
    try:
        with zipfile.ZipFile(zip_file, 'r') as zip_ref:
            for file_info in zip_ref.filelist:
                if not file_info.is_dir() and allowed_file(file_info.filename):
                    total_files += 1
                    try:
                        with zip_ref.open(file_info.filename) as file:
                            content = file.read()
                            file_results = scan_file_content(content, file_info.filename)
                            if file_results:
                                files_with_secrets += 1
                                results.append({
                                    'filename': file_info.filename,
                                    'findings': file_results
                                })
                    except Exception:
                        continue
    except Exception:
        pass
    
    return {
        'files_scanned': total_files,
        'files_with_secrets': files_with_secrets,
        'results': results
    }

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """Handle scanning requests"""
    try:
        scan_type = request.form.get('scan_type')
        results = {}
        
        if scan_type == 'text':
            # Scan pasted text
            text_content = request.form.get('text_content', '')
            if text_content.strip():
                findings = scan_content(text_content, "pasted text")
                results = {
                    'type': 'text',
                    'findings': findings,
                    'total_secrets': len(findings)
                }
            else:
                results = {
                    'type': 'text',
                    'findings': [],
                    'total_secrets': 0,
                    'error': 'No text provided'
                }
        
        elif scan_type == 'file':
            # Scan uploaded files
            files = request.files.getlist('files')
            if files and any(f.filename for f in files):
                results = scan_uploaded_files(files)
                results['type'] = 'file'
            else:
                results = {
                    'type': 'file',
                    'files_scanned': 0,
                    'files_with_secrets': 0,
                    'results': [],
                    'error': 'No files uploaded'
                }
        
        elif scan_type == 'zip':
            # Scan ZIP file
            zip_file = request.files.get('zip_file')
            if zip_file and zip_file.filename.endswith('.zip'):
                # Save to temporary file
                with tempfile.NamedTemporaryFile(delete=False) as tmp:
                    zip_file.save(tmp.name)
                    results = scan_zip_file(tmp.name)
                    os.unlink(tmp.name)  # Clean up
                results['type'] = 'zip'
            else:
                results = {
                    'type': 'zip',
                    'files_scanned': 0,
                    'files_with_secrets': 0,
                    'results': [],
                    'error': 'No ZIP file uploaded'
                }
        
        # Store results in session for export
        session['scan_results'] = results
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/export/<format_type>')
def export_results(format_type):
    """Export scan results"""
    results = session.get('scan_results', {})
    
    if not results:
        return jsonify({'error': 'No scan results to export'}), 400
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if format_type == 'json':
        filename = f"secret_scan_report_{timestamp}.json"
        return send_file(
            io.BytesIO(json.dumps(results, indent=2, ensure_ascii=False).encode('utf-8')),
            mimetype='application/json',
            as_attachment=True,
            download_name=filename
        )
    
    elif format_type == 'csv':
        filename = f"secret_scan_report_{timestamp}.csv"
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Source', 'File Path', 'Secret Type', 'Value'])
        
        if results.get('type') == 'text':
            for secret_type, matches in results.get('findings', []):
                for match in set(matches):
                    writer.writerow(['Pasted Text', 'N/A', secret_type, match])
        else:
            for file_result in results.get('results', []):
                for secret_type, matches in file_result.get('findings', []):
                    for match in set(matches):
                        writer.writerow([results.get('type', 'Unknown'), file_result['filename'], secret_type, match])
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    
    elif format_type == 'txt':
        filename = f"secret_scan_report_{timestamp}.txt"
        output = io.StringIO()
        
        output.write("=" * 70 + "\n")
        output.write("           SECRET SCANNER REPORT\n")
        output.write("=" * 70 + "\n\n")
        output.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        output.write(f"Scanner Version: 2.0\n\n")
        
        if results.get('type') == 'text':
            output.write("TEXT SCAN RESULTS:\n")
            output.write("-" * 30 + "\n")
            for secret_type, matches in results.get('findings', []):
                output.write(f"\n{secret_type}:\n")
                for match in set(matches):
                    output.write(f"  - {match}\n")
        else:
            output.write("FILE SCAN RESULTS:\n")
            output.write("-" * 30 + "\n")
            for file_result in results.get('results', []):
                output.write(f"\nFile: {file_result['filename']}\n")
                for secret_type, matches in file_result.get('findings', []):
                    output.write(f"  {secret_type}:\n")
                    for match in set(matches):
                        output.write(f"    - {match}\n")
        
        output.write("\n\nSUMMARY:\n")
        output.write("-" * 10 + "\n")
        if results.get('type') == 'text':
            output.write(f"Total secret types found: {results.get('total_secrets', 0)}\n")
        else:
            output.write(f"Files scanned: {results.get('files_scanned', 0)}\n")
            output.write(f"Files with secrets: {results.get('files_with_secrets', 0)}\n")
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/plain',
            as_attachment=True,
            download_name=filename
        )
    
    else:
        return jsonify({'error': 'Invalid export format'}), 400

@app.route('/about')
def about():
    """About page"""
    return render_template('about.html', patterns=SECRET_PATTERNS)

if __name__ == '__main__':
    # For local development
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000))) 