# 🔍 Secret Scanner - Flask Web Application

A modern, web-based security auditing tool that scans code and files for sensitive information, secrets, and potential security vulnerabilities.

## ✨ Features

### 🔐 **Comprehensive Secret Detection**
- **Authentication Tokens**: GitHub, Slack, Discord, and more
- **API Keys**: AWS, Google, Stripe, and other service integrations
- **Database Connections**: MongoDB, PostgreSQL, MySQL, Redis
- **Private Keys**: RSA, SSH, SSL certificates
- **Personal Information**: Emails, phone numbers, IP addresses
- **Financial Data**: Credit card numbers, account information
- **Hardcoded Secrets**: Passwords, tokens, and credentials

### 🌐 **Modern Web Interface**
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Scanning**: Instant results with progress indicators
- **Multiple Input Methods**: Text input, file upload, ZIP archives
- **Drag & Drop**: Easy file upload with visual feedback
- **Export Options**: JSON, CSV, and TXT report formats

### 🚀 **Advanced Capabilities**
- **50+ File Formats**: Supports all major programming languages
- **Batch Processing**: Scan entire projects via ZIP upload
- **Smart Filtering**: Ignores common directories (.git, node_modules, etc.)
- **Detailed Reports**: Comprehensive findings with context
- **Security Best Practices**: Built-in warnings and recommendations

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package installer)

### Setup Instructions

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd secret-scanner
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the web interface**
   Open your browser and go to: `http://localhost:5000`

## 📖 Usage Guide

### 🎯 **Quick Start**

1. **Open the web interface** at `http://localhost:5000`
2. **Choose your scanning method**:
   - **Text Input**: Paste code directly
   - **File Upload**: Upload individual files
   - **ZIP Archive**: Upload entire projects

3. **Review results** and export reports as needed

### 🔍 **Scanning Methods**

#### **Text Input**
- Perfect for quick code snippets
- Instant scanning and results
- No file upload required
- Supports any text content

#### **File Upload**
- Upload multiple files at once
- Supports 50+ file formats
- Drag and drop interface
- Individual file results

#### **ZIP Archive**
- Scan entire projects
- Batch processing
- Comprehensive results
- Maintains file structure

### 📊 **Understanding Results**

The scanner categorizes findings into:

- **🔐 Authentication Tokens**: Login credentials and access tokens
- **💳 Payment & API Keys**: Service integration keys
- **🗄️ Database Connections**: Connection strings and credentials
- **🔑 Private Keys**: Cryptographic materials
- **📧 Personal Information**: Contact details and identifiers
- **💳 Financial Data**: Payment and account information
- **🔗 URLs & Paths**: Potential information disclosure

### 📄 **Export Options**

#### **JSON Format**
- Structured data for programmatic analysis
- Complete scan metadata
- Machine-readable format

#### **CSV Format**
- Spreadsheet-friendly format
- Easy data analysis
- Import into Excel/Google Sheets

#### **TXT Format**
- Human-readable report
- Simple text format
- Easy to share and print

## 🔧 **Configuration**

### **Customizing Secret Patterns**

Edit the `SECRET_PATTERNS` dictionary in `app.py` to add or modify detection patterns:

```python
SECRET_PATTERNS = {
    "Custom Pattern": r"your-regex-pattern-here",
    # ... existing patterns
}
```

### **File Format Support**

Modify the `ALLOWED_EXTENSIONS` set to add support for additional file types:

```python
ALLOWED_EXTENSIONS = {
    '.your-extension',
    # ... existing extensions
}
```

### **Ignored Directories**

Update the `IGNORE_DIRS` set to customize which directories are skipped:

```python
IGNORE_DIRS = {
    'your-ignore-dir',
    # ... existing directories
}
```

## 🛡️ **Security Considerations**

### **Important Warnings**

⚠️ **This tool is for security auditing and educational purposes only.**

- **Handle found secrets responsibly** and securely
- **Use environment variables** instead of hardcoded secrets
- **Regularly rotate** API keys and tokens
- **Store sensitive information** in secure vaults
- **Limit access** to credentials to only those who need them

### **Best Practices**

1. **Environment Variables**: Use `.env` files or system environment variables
2. **Secret Management**: Implement proper secret management systems
3. **Access Control**: Restrict access to sensitive credentials
4. **Regular Audits**: Schedule regular security scans
5. **Documentation**: Document security practices and procedures

## 🚀 **Deployment**

### **Production Deployment**

For production use, consider:

1. **Use a production WSGI server** (Gunicorn, uWSGI)
2. **Set up HTTPS** with proper SSL certificates
3. **Configure proper logging** and monitoring
4. **Implement rate limiting** and access controls
5. **Use environment variables** for configuration

### **Docker Deployment**

Create a `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 5000
CMD ["python", "app.py"]
```

## 🤝 **Contributing**

### **Development Setup**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### **Adding New Patterns**

To add new secret detection patterns:

1. Add the pattern to `SECRET_PATTERNS`
2. Test with sample data
3. Update documentation
4. Consider false positive rates

## 📝 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 **Support**

### **Common Issues**

**Q: The scanner isn't detecting expected secrets**
A: Check if the pattern matches your data format. Consider adding custom patterns.

**Q: Large files are slow to scan**
A: The scanner processes files in memory. Consider breaking large files into smaller chunks.

**Q: False positives in results**
A: Review and adjust pattern specificity. Some patterns may need refinement for your use case.

### **Getting Help**

- Check the documentation
- Review the about page in the web interface
- Examine the pattern definitions
- Test with known sample data

## 🔄 **Version History**

### **v2.0.0** (Current)
- Flask web application
- Modern responsive UI
- Multiple input methods
- Export functionality
- Comprehensive secret detection

### **v1.0.0**
- Command-line interface
- Basic file scanning
- Simple text output

---

**Built with ❤️ for security professionals and developers** 