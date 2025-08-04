# Zero-Trust Infrastructure Scanner

Enterprise-grade security scanning platform for modern cloud infrastructure.

## 🛡️ Features

### Core Security Modules
- **🔍 Network Micro-Segmentation**: Analyze and recommend network security policies
- **👤 Identity Permission Mining**: Detect over-privileged accounts and analyze IAM permissions
- **📦 Supply Chain Security**: Scan container images and dependencies for vulnerabilities
- **📋 Compliance Automation**: Automated SOC2, PCI, HIPAA compliance checking

### Enterprise Capabilities
- **⚡ High Performance**: Parallel scanning with intelligent resource management
- **🔧 Configurable**: Comprehensive configuration system with validation
- **📊 Rich Reporting**: Multiple output formats (JSON, YAML, HTML, PDF)
- **🌐 Multi-Cloud**: Support for AWS, Azure, GCP
- **🔌 Extensible**: Plugin architecture for custom scanners

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

# Start web dashboard
npm run scan server
```

## 📋 CLI Commands

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
- **Configuration Manager**: Flexible configuration system
- **Health Monitor**: System health and performance monitoring
- **Logger**: Structured logging with multiple outputs
- **Web Dashboard**: Real-time monitoring and control interface

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
├── config/         # Configuration management
├── utils/          # Utilities and helpers
├── monitoring/     # Health and performance monitoring
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
