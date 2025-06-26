# 🚀 Deployment Guide - Secret Scanner

This guide covers deploying the Secret Scanner Flask application to AWS Amplify and other platforms.

## 📋 Prerequisites

- AWS Account
- Git repository with your code
- Basic knowledge of AWS services

## 🎯 AWS Amplify Deployment

### Step 1: Prepare Your Repository

1. **Ensure your repository structure:**
   ```
   secret-scanner/
   ├── app.py
   ├── wsgi.py
   ├── requirements.txt
   ├── amplify.yml
   ├── templates/
   │   ├── index.html
   │   └── about.html
   └── README.md
   ```

2. **Push your code to GitHub/GitLab/Bitbucket**

### Step 2: Connect to AWS Amplify

1. **Go to AWS Amplify Console**
   - Navigate to [AWS Amplify Console](https://console.aws.amazon.com/amplify/)
   - Click "New app" → "Host web app"

2. **Connect Repository**
   - Choose your Git provider (GitHub, GitLab, Bitbucket)
   - Authorize AWS Amplify to access your repositories
   - Select your secret-scanner repository
   - Choose the branch to deploy (usually `main` or `master`)

3. **Configure Build Settings**
   - Amplify will auto-detect the `amplify.yml` file
   - Review the build settings
   - Click "Save and deploy"

### Step 3: Environment Variables (Optional)

In Amplify Console → App settings → Environment variables:

```
SECRET_KEY=your-secure-secret-key-here
FLASK_ENV=production
```

### Step 4: Deploy

1. **Monitor the build process** in the Amplify Console
2. **Wait for deployment** to complete
3. **Access your app** at the provided Amplify URL

## 🔧 Alternative Deployment Options

### Option 1: Docker Deployment

1. **Build the Docker image:**
   ```bash
   docker build -t secret-scanner .
   ```

2. **Run the container:**
   ```bash
   docker run -p 5000:5000 -e SECRET_KEY=your-key secret-scanner
   ```

3. **Deploy to AWS ECS/Fargate:**
   - Create ECS cluster
   - Define task definition
   - Deploy service

### Option 2: AWS Elastic Beanstalk

1. **Install EB CLI:**
   ```bash
   pip install awsebcli
   ```

2. **Initialize EB application:**
   ```bash
   eb init secret-scanner
   eb create secret-scanner-env
   ```

3. **Deploy:**
   ```bash
   eb deploy
   ```

### Option 3: Heroku

1. **Create Procfile:**
   ```
   web: gunicorn wsgi:app
   ```

2. **Deploy to Heroku:**
   ```bash
   heroku create your-app-name
   git push heroku main
   ```

## 🛠️ Configuration Files

### amplify.yml
```yaml
version: 1
frontend:
  phases:
    preBuild:
      commands:
        - echo "Installing Python dependencies..."
        - python -m pip install --upgrade pip
        - pip install -r requirements.txt
        - pip install gunicorn
    build:
      commands:
        - echo "Building Flask application..."
        - echo "Flask app is ready for deployment"
  artifacts:
    baseDirectory: /
    files:
      - '**/*'
  cache:
    paths:
      - venv/**/*
      - .venv/**/*
```

### wsgi.py
```python
from app import app

if __name__ == "__main__":
    app.run()
```

## 🔒 Security Considerations

### Environment Variables
- Set `SECRET_KEY` to a secure random string
- Use environment variables for sensitive configuration
- Never commit secrets to version control

### Production Settings
- Disable debug mode (`debug=False`)
- Use HTTPS in production
- Set up proper logging
- Configure rate limiting

## 📊 Monitoring & Maintenance

### Amplify Console Features
- **Build logs**: Monitor deployment status
- **Performance monitoring**: Track app performance
- **Error tracking**: Monitor application errors
- **Custom domains**: Set up custom domain names

### Health Checks
- Amplify automatically health checks your application
- Ensure your app responds to root path (`/`)
- Monitor application logs for errors

## 🚨 Troubleshooting

### Common Issues

1. **Build Failures**
   - Check `requirements.txt` for missing dependencies
   - Verify Python version compatibility
   - Review build logs in Amplify Console

2. **Application Errors**
   - Check application logs
   - Verify environment variables
   - Test locally before deploying

3. **Performance Issues**
   - Monitor resource usage
   - Optimize file upload sizes
   - Consider caching strategies

### Debug Commands

```bash
# Test locally
python app.py

# Test with gunicorn
gunicorn wsgi:app

# Check dependencies
pip list

# Verify file structure
ls -la
```

## 📈 Scaling Considerations

### Amplify Limitations
- **File upload size**: 50MB limit
- **Build time**: 15-minute limit
- **Concurrent builds**: Varies by plan

### Optimization Tips
- **Compress files** before upload
- **Use CDN** for static assets
- **Implement caching** for repeated scans
- **Optimize images** and assets

## 🔄 Continuous Deployment

### Automatic Deployments
- Amplify automatically deploys on code pushes
- Configure branch-specific deployments
- Set up preview deployments for pull requests

### Manual Deployments
- Use Amplify Console for manual deployments
- Rollback to previous versions if needed
- Monitor deployment status

## 📞 Support

### AWS Support
- **Documentation**: [AWS Amplify Docs](https://docs.aws.amazon.com/amplify/)
- **Forums**: [AWS Amplify Community](https://amplify.aws/community/)
- **Support**: AWS Support plans available

### Application Support
- Check application logs
- Review error messages
- Test functionality locally

---

**Happy Deploying! 🚀** 