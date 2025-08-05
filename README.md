# 🛡️ Zero-Trust Infrastructure Scanner

<div align="center">

![Zero-Trust Banner](https://img.shields.io/badge/Zero--Trust-Infrastructure%20Scanner-blue?style=for-the-badge&logo=shield)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue?style=flat-square&logo=typescript)
![Enterprise Grade](https://img.shields.io/badge/Enterprise-Grade-gold?style=flat-square)
![Real-Time](https://img.shields.io/badge/Real--Time-Monitoring-green?style=flat-square)

**Enterprise-grade security scanning platform for modern cloud infrastructure**

*Comprehensive zero-trust security with behavioral analysis and real-time monitoring*

</div>

## ⚡ Quick Overview

The **Zero-Trust Infrastructure Scanner** is a comprehensive security platform that implements zero-trust principles across your entire infrastructure:

- 🔍 **Network Micro-Segmentation** - Analyze and secure network policies
- 👤 **Identity Permission Mining** - Detect over-privileged accounts
- 📦 **Supply Chain Security** - Scan containers and dependencies
- 📋 **Compliance Automation** - SOC2, PCI, HIPAA compliance checking
- 📡 **Real-Time Monitoring** - Live security monitoring with WebSocket dashboard
- 🧠 **Behavioral Analysis** - ML-powered anomaly detection with statistical models

📖 **[View Complete Documentation](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/wiki)** - Comprehensive guides, advanced features, and detailed configuration options

## 🚀 Quick Start

```bash
# Clone and setup
git clone https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner.git
cd Zero-Trust-Infrastructure-Scanner
npm install && npm run build

# Initialize configuration
npm run scan config -- --init

# Run security scans
npm run scan-all                    # Comprehensive scan
npm run scan:network                # Network security
npm run scan:identity               # Identity permissions
npm run scan:supply-chain          # Dependencies & containers
npm run scan:compliance            # Compliance checking

# Real-time monitoring
node dist/cli.js monitor --targets localhost --interval 30
node dist/cli.js dashboard --port 3000    # Web dashboard

# Behavioral analysis
node dist/cli.js behavioral monitor --real-time
```

## 📡 Real-Time Dashboard

Get live security monitoring in seconds:

```bash
# Terminal 1: Start monitoring
node dist/cli.js monitor --targets localhost --interval 30

# Terminal 2: Start web dashboard  
node dist/cli.js dashboard --port 3000

# Open: http://localhost:3000
```

**Features:**
- 📊 Live security metrics and event stream
- 🚨 Multi-channel alerts (Slack, Teams, webhooks, email)
- 🧠 Behavioral analysis with ML anomaly detection
- 🔄 Continuous scanning with configurable intervals

## 🛠️ Core Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `network` | Network security analysis | `npm run scan network --target 10.0.0.0/16` |
| `identity` | IAM permissions audit | `npm run scan identity --provider aws-iam` |
| `supply-chain` | Vulnerability scanning | `npm run scan supply-chain --image nginx:latest` |
| `compliance` | Compliance checking | `npm run scan compliance --standard soc2` |
| `monitor` | Real-time monitoring | `node dist/cli.js monitor --targets localhost` |
| `behavioral` | Behavioral analysis | `node dist/cli.js behavioral profiles --list` |

## 📡 Real-Time Monitoring

The Zero-Trust Infrastructure Scanner now includes powerful real-time monitoring capabilities for continuous security assessment.

### Starting Real-Time Monitoring

```bash
# Start monitoring with default settings
npm run scan monitor --targets localhost

# Monitor multiple targets with custom interval
npm run scan monitor --targets "192.168.1.0/24,10.0.0.0/16" --interval 60

# Monitor with Slack alerts
npm run scan monitor --targets localhost --slack-webhook "https://hooks.slack.com/..."

# Monitor with multiple alert channels
npm run scan monitor \
  --targets localhost \
  --interval 30 \
  --slack-webhook "https://hooks.slack.com/..." \
  --teams-webhook "https://outlook.office.com/webhook/..." \
  --email-alerts "security@company.com,admin@company.com"
```

### Live Web Dashboard

```bash
# Start the web dashboard (monitors on port 3001 by default)
npm run scan dashboard --port 3000

# Connect to custom monitor port
npm run scan dashboard --port 3000 --monitor-port 3002
```

Then open your browser to `http://localhost:3000` to view:

- **Live Security Metrics**: Real-time counts of targets, scans, and alerts
- **Event Stream**: Live feed of security findings with severity-based color coding
- **Connection Status**: WebSocket connection health with auto-reconnection
- **Target Overview**: Number of monitored targets and active scans

### Monitoring Features

- **🔄 Continuous Scanning**: Configurable scan intervals (default: 30 seconds)
- **📡 WebSocket Updates**: Real-time dashboard updates via WebSocket connection
- **🚨 Multi-Channel Alerts**: Slack, Microsoft Teams, webhooks, and email notifications
- **📊 Live Metrics**: Real-time monitoring statistics and event counts
- **🔍 Change Detection**: Intelligent baseline comparison and delta reporting
- **⚡ Event-Driven**: Scalable architecture for enterprise deployments
- **🛡️ Rate Limiting**: Alert throttling to prevent notification spam

### Alert Configuration

```bash
# Basic monitoring with webhooks
npm run scan monitor --webhooks "https://api.company.com/alerts"

# Enterprise setup with multiple channels
npm run scan monitor \
  --targets "prod-network,staging-network" \
  --interval 120 \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --teams-webhook "https://outlook.office.com/webhook/..." \
  --webhooks "https://api.company.com/alerts,https://siem.company.com/webhook" \
  --email-alerts "security-team@company.com"
```

## ⚙️ Configuration

Create a configuration file to customize scanner behavior:

```bash
npm run scan config -- --init
```

This creates `ztis.config.json` with comprehensive settings for all scanner modules.

### Example Configuration

```json
{
  "scanner": {
    "parallelScans": 3,
    "scanTimeout": 300000,
    "outputDirectory": "./reports"
  },
  "network": {
    "defaultScanDepth": 3,
    "cloudProviders": [
      {
        "name": "aws",
        "enabled": true,
        "regions": ["us-east-1", "us-west-2"]
      }
    ]
  },
  "compliance": {
    "standards": [
      {
        "name": "SOC2",
        "enabled": true
      }
    ]
  }
}
```

## 🏗️ Architecture

### Core Components

- **Scanner Engine**: Central orchestration and execution
- **Real-Time Monitor**: WebSocket-based continuous monitoring engine
- **Configuration Manager**: Flexible configuration system
- **Health Monitor**: System health and performance monitoring
- **Logger**: Structured logging with multiple outputs
- **Live Dashboard**: Real-time web interface with WebSocket updates

### Scanner Modules

- **Network Scanner**: Network topology and security analysis
- **Identity Scanner**: IAM and permission analysis
- **Supply Chain Scanner**: Vulnerability and dependency analysis
- **Compliance Scanner**: Automated compliance verification

## 📊 Reporting

The scanner generates comprehensive reports in multiple formats:

- **JSON**: Machine-readable for integration
- **YAML**: Human-readable structured data
- **HTML**: Interactive web reports with charts
- **PDF**: Professional compliance reports

### Report Structure

```json
{
  "scanId": "scan_1691234567_abc123",
  "timestamp": "2025-08-04T10:30:00Z",
  "target": {
    "type": "network",
    "target": "10.0.0.0/16"
  },
  "findings": [
    {
      "severity": "high",
      "category": "network-security",
      "title": "Unprotected Database Port",
      "description": "Database port 3306 is accessible from 0.0.0.0/0",
      "recommendation": "Restrict access to database subnet only"
    }
  ],
  "metrics": {
    "total_checks": 150,
    "passed_checks": 142,
    "failed_checks": 8
  }
}
```

## 🔧 Development

### Project Structure

```
src/
├── core/           # Core scanner engine
├── scanners/       # Individual scanner modules
├── monitoring/     # Real-time monitoring and WebSocket server
├── config/         # Configuration management
├── utils/          # Utilities and helpers
├── api/           # REST API endpoints
└── web/           # Web dashboard
```

### Building and Testing

```bash
# Development mode
npm run dev

# Build project
npm run build

# Run tests
npm run test

# Run with coverage
npm run test:coverage

# Lint code
npm run lint
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/new-scanner`
3. Make your changes and add tests
4. Run the test suite: `npm test`
5. Submit a pull request

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- 📖 Documentation: [Wiki](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/wiki)
- 🐛 Issues: [GitHub Issues](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/discussions)

---

**Made with ❤️ for enterprise security teams**
