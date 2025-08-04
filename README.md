# Zero-Trust Infrastructure Scanner

Enterprise-grade security scanning platform for modern cloud infrastructure.

## 🛡️ Features

### Core Security Modules
- **🔍 Network Micro-Segmentation**: Analyze and recommend network security policies
- **👤 Identity Permission Mining**: Detect over-privileged accounts and analyze IAM permissions
- **📦 Supply Chain Security**: Scan container images and dependencies for vulnerabilities
- **📋 Compliance Automation**: Automated SOC2, PCI, HIPAA compliance checking

### Real-Time Monitoring
- **📡 Live Monitoring**: Continuous security monitoring with WebSocket-based live updates
- **🚨 Real-Time Alerts**: Instant notifications for security findings via Slack, Teams, webhooks, and email
- **📊 Live Dashboard**: Web-based real-time monitoring dashboard with live metrics
- **🔄 Event-Driven Architecture**: Scalable monitoring with intelligent change detection
- **⚡ Continuous Scanning**: Configurable scan intervals for proactive threat detection

### Enterprise Capabilities
- **⚡ High Performance**: Parallel scanning with intelligent resource management
- **🔧 Configurable**: Comprehensive configuration system with validation
- **📊 Rich Reporting**: Multiple output formats (JSON, YAML, HTML, PDF)
- **🌐 Multi-Cloud**: Support for AWS, Azure, GCP
- **🔌 Extensible**: Plugin architecture for custom scanners

> **Latest Update**: The scanner now includes enterprise-grade real-time monitoring capabilities with WebSocket-based live updates, multi-channel alerting, and a professional web dashboard. Over **4,500+ lines** of production-ready TypeScript code across all modules.

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner.git
cd Zero-Trust-Infrastructure-Scanner

# Install dependencies
npm install

# Build the project
npm run build
```

### Basic Usage

```bash
# Initialize configuration
npm run scan config -- --init

# Run comprehensive security scan
npm run scan-all

# Scan specific modules
npm run scan:network
npm run scan:identity
npm run scan:supply-chain
npm run scan:compliance

# Real-time monitoring
npm run scan monitor --targets localhost --interval 30
npm run scan dashboard --port 3000

# Start web dashboard
npm run scan server
```

## � Real-Time Monitoring Quick Start

Get started with live security monitoring in just a few commands:

```bash
# Terminal 1: Start the real-time monitor
node dist/cli.js monitor --targets localhost --interval 30

# Terminal 2: Start the web dashboard
node dist/cli.js dashboard --port 3000

# Open browser to: http://localhost:3000
```

You'll immediately see:
- **Live security scans** running every 30 seconds
- **Real-time findings** appearing in the dashboard
- **WebSocket connection status** with automatic reconnection
- **Event stream** with color-coded severity levels

For production deployments with alerts:

```bash
# Production monitoring with Slack alerts
node dist/cli.js monitor \
  --targets "production-network,staging-network" \
  --interval 60 \
  --slack-webhook "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
```

## �📋 CLI Commands

### Network Security
```bash
# Scan network micro-segmentation
npm run scan network --target 10.0.0.0/16 --cloud-provider aws

# Analyze Kubernetes network policies
npm run scan network --k8s-namespace production
```

### Identity Security
```bash
# Scan AWS IAM permissions
npm run scan identity --provider aws-iam

# Analyze over-privileged accounts
npm run scan identity --privilege-threshold high
```

### Supply Chain Security
```bash
# Scan container image
npm run scan supply-chain --image nginx:latest

# Scan current project dependencies
npm run scan supply-chain --file package.json
```

### Compliance Checking
```bash
# Run SOC2 compliance scan
npm run scan compliance --standard soc2

# Generate compliance report
npm run scan compliance --standard all --report-format pdf
```

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
