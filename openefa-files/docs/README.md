# OpenEFA Documentation

**Open Email Filtering and Analytics System**

Version 1.5.x | Last Updated: 2025-10-19

---

## 📋 Quick Navigation

### 🚀 Getting Started

**New to OpenEFA?** Start here:

- **[What is OpenEFA?](01-overview/introduction.md)** - System overview and key features
- **[Installation Guide](02-installation/new-installation.md)** - Complete setup instructions
- **[Architecture Overview](01-overview/architecture.md)** - How the system is designed
- **[System Requirements](01-overview/requirements.md)** - Hardware and software needs

---

### 📚 Understanding OpenEFA

**Learn how OpenEFA works:**

- **[How It Works](03-core-concepts/how-it-works.md)** - Email processing pipeline explained
- **[Scoring System](03-core-concepts/scoring-system.md)** - How spam scores are calculated
- **[Learning Philosophy](03-core-concepts/learning-philosophy.md)** ⭐ - System-wide vs per-domain learning
- **[Multi-Tenant Support](03-core-concepts/multi-tenant.md)** - Serving multiple companies/domains
- **[Quarantine System](03-core-concepts/quarantine-system.md)** - Email quarantine and release

---

### ⚙️ Configuration & Administration

**For system administrators:**

#### User & Domain Management
- **[User Management](07-administration/user-management.md)** - Creating and managing users
- **[Domain Configuration](07-administration/domain-configuration.md)** - Adding/removing domains
- **[User Roles & Permissions](06-web-interface/user-roles.md)** - Role-based access control

#### Email Filtering
- **[Whitelist/Blacklist Management](07-administration/whitelist-blacklist.md)** - Managing allow/block lists
- **[Threshold Tuning](05-scoring-breakdown/threshold-tuning.md)** - Adjusting spam score thresholds
- **[False Positive Handling](11-troubleshooting/false-positives.md)** - Dealing with misclassified emails

#### System Operations
- **[Notification System](07-administration/notification-system.md)** - SMS/Email alerts configuration
- **[Backup & Restore](07-administration/backup-restore.md)** - Data protection strategies
- **[System Monitoring](07-administration/monitoring.md)** - Health checks and performance
- **[Maintenance Tasks](07-administration/maintenance.md)** - Routine system upkeep

---

### 🔧 Modules & Features

**Deep dive into OpenEFA's capabilities:**

#### Core Analysis Modules
- **[Module Overview](04-modules/overview.md)** - Architecture and module system
- **[NLP Analysis Engine](04-modules/nlp-analysis.md)** - SpaCy NLP integration
- **[Conversation Learner](04-modules/conversation-learner.md)** - Adaptive learning system

#### Advanced Threat Detection
- **[BEC Detection](04-modules/bec-detector.md)** - Business Email Compromise prevention
- **[Brand Impersonation](04-modules/brand-impersonation.md)** - Brand protection and typosquatting
- **[Behavioral Analysis](04-modules/behavioral-analysis.md)** - Baseline behavior monitoring
- **[URL Reputation](04-modules/url-reputation.md)** - Link analysis and scoring

#### Security Integration
- **[Antivirus Integration](04-modules/antivirus-integration.md)** - ClamAV malware scanning
- **[Attachment Analysis](04-modules/attachment-analysis.md)** - File attachment processing
- **[Email Blocking](04-modules/email-blocking.md)** - Sender blocking system

---

### 📊 Scoring & Analytics

**Understanding the scoring system:**

- **[Scoring Overview](05-scoring-breakdown/scoring-overview.md)** - How spam scores work
- **[Component Scores](05-scoring-breakdown/component-scores.md)** - Individual scoring components
- **[Threshold Tuning](05-scoring-breakdown/threshold-tuning.md)** - Adjusting detection sensitivity
- **[Score Interpretation](05-scoring-breakdown/score-interpretation.md)** - Reading and understanding scores

---

### 🖥️ Web Interface

**Using the web dashboard:**

- **[Dashboard Overview](06-web-interface/dashboard.md)** - Main dashboard features
- **[Quarantine Management](06-web-interface/quarantine-management.md)** - Managing quarantined emails
- **[User Roles](06-web-interface/user-roles.md)** - Admin, DomainAdmin, User permissions
- **[Domain Management](06-web-interface/domain-management.md)** - Web-based domain configuration
- **[Reporting & Analytics](06-web-interface/reporting.md)** - Email statistics and trends
- **[Configuration Settings](06-web-interface/configuration.md)** - Web-based system configuration

---

### 🔍 Troubleshooting

**Common issues and solutions:**

- **[Common Issues](11-troubleshooting/common-issues.md)** - FAQ and known problems
- **[Email Processing](11-troubleshooting/email-processing.md)** - Email not being filtered
- **[False Positives](11-troubleshooting/false-positives.md)** - Legitimate emails blocked
- **[Performance Issues](11-troubleshooting/performance.md)** - Optimization and tuning
- **[Log Files](11-troubleshooting/logs.md)** - Understanding system logs
- **[Diagnostic Commands](11-troubleshooting/diagnostics.md)** - Troubleshooting commands

---

### 🛠️ Configuration Files

**Configuration reference:**

- **[Configuration Files Overview](08-configuration/configuration-files.md)** - All config files explained
- **[Email Filter Configuration](08-configuration/email-filter-config.md)** - Main filter settings
- **[BEC Configuration](08-configuration/bec-config.md)** - BEC detection tuning
- **[Antivirus Configuration](08-configuration/antivirus-config.md)** - ClamAV settings
- **[Notification Configuration](08-configuration/notification-config.md)** - Alert settings
- **[Database Configuration](08-configuration/database-config.md)** - Database connection settings

---

### 💾 Database

**Database structure and operations:**

- **[Schema Overview](10-database/schema-overview.md)** - Database architecture
- **[Email Analysis Tables](10-database/email-analysis-tables.md)** - Main analysis data
- **[Learning Tables](10-database/learning-tables.md)** - Conversation learning schema
- **[Quarantine Tables](10-database/quarantine-tables.md)** - Quarantine storage
- **[User & Permission Tables](10-database/user-tables.md)** - User management schema
- **[Common Queries](10-database/queries.md)** - Useful SQL queries

---

### 🔌 API Reference

**Developer API documentation:**

- **[REST API Overview](09-api/rest-api.md)** - API endpoints and usage
- **[Authentication](09-api/authentication.md)** - API authentication methods
- **[Quarantine API](09-api/quarantine-api.md)** - Programmatic quarantine management
- **[Reporting API](09-api/reporting-api.md)** - Report generation endpoints

---

### 👨‍💻 Development

**For developers and contributors:**

- **[Contributing Guide](12-development/contributing.md)** - How to contribute
- **[Code Structure](12-development/code-structure.md)** - Codebase organization
- **[Module Development](12-development/module-development.md)** - Creating new analysis modules
- **[Testing Procedures](12-development/testing.md)** - Testing and validation
- **[Changelog](12-development/changelog.md)** - Version history

---

### 📖 Appendix

**Additional resources:**

- **[Glossary](13-appendix/glossary.md)** - Terms and definitions
- **[Command Reference](13-appendix/command-reference.md)** - CLI commands
- **[Ports & Protocols](13-appendix/ports-protocols.md)** - Network requirements
- **[Credits & Acknowledgments](13-appendix/credits.md)** - Open source components

---

## 🎯 Quick Links by Role

### System Administrator
1. [Installation Guide](02-installation/new-installation.md)
2. [Domain Configuration](07-administration/domain-configuration.md)
3. [User Management](07-administration/user-management.md)
4. [System Monitoring](07-administration/monitoring.md)
5. [Backup & Restore](07-administration/backup-restore.md)

### Domain Administrator
1. [User Roles & Permissions](06-web-interface/user-roles.md)
2. [Quarantine Management](06-web-interface/quarantine-management.md)
3. [Whitelist/Blacklist](07-administration/whitelist-blacklist.md)
4. [Reporting & Analytics](06-web-interface/reporting.md)

### End User
1. [Quarantine Management](06-web-interface/quarantine-management.md)
2. [Understanding Scores](05-scoring-breakdown/score-interpretation.md)
3. [False Positives](11-troubleshooting/false-positives.md)

### Developer
1. [Code Structure](12-development/code-structure.md)
2. [API Reference](09-api/rest-api.md)
3. [Module Development](12-development/module-development.md)
4. [Database Schema](10-database/schema-overview.md)

---

## 📚 Documentation Principles

This documentation follows these principles:

- **Progressive Disclosure:** Information organized from simple to complex
- **Task-Oriented:** Organized by what you want to accomplish
- **Searchable:** Clear naming and comprehensive indexing
- **Practical:** Real-world examples and use cases
- **Current:** Updated with each version release

---

## 🆘 Getting Help

### Documentation Issues
Found an error or unclear section?
- Open an issue on the project repository
- Contact your system administrator

### Technical Support
- Check [Common Issues](11-troubleshooting/common-issues.md) first
- Review [Log Files](11-troubleshooting/logs.md) for errors
- Consult [Diagnostic Commands](11-troubleshooting/diagnostics.md)

### Feature Requests
- Submit via project repository
- Discuss in community forums
- Contact development team

---

## 📄 Document Status

| Section | Status | Last Updated |
|---------|--------|--------------|
| 01-overview | 🚧 In Progress | - |
| 02-installation | 🚧 In Progress | - |
| 03-core-concepts | ✅ Partial | 2025-10-19 |
| 04-modules | 📝 Planned | - |
| 05-scoring-breakdown | 📝 Planned | - |
| 06-web-interface | 📝 Planned | - |
| 07-administration | 📝 Planned | - |
| 08-configuration | 📝 Planned | - |
| 09-api | 📝 Planned | - |
| 10-database | 📝 Planned | - |
| 11-troubleshooting | 📝 Planned | - |
| 12-development | 📝 Planned | - |
| 13-appendix | 📝 Planned | - |

**Legend:**
- ✅ Complete
- 🚧 In Progress
- 📝 Planned
- ⭐ Featured Document

---

## 🔄 Documentation Version

- **Version:** 1.0
- **OpenEFA Version:** 1.5.x
- **Last Updated:** 2025-10-19
- **Format:** Markdown (GitHub-flavored)

---

## 📞 Project Information

**Project Name:** OpenEFA (Open Email Filtering and Analytics)
**Project Type:** Open Source Email Security System
**License:** [Check project repository]
**Repository:** [Project repository URL]

---

**Welcome to OpenEFA Documentation!**

This documentation is continuously evolving. If you can't find what you're looking for, check back soon or contribute to help us improve it.

Happy filtering! 🛡️
