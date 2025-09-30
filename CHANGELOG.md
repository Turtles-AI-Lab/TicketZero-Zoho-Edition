# Changelog

All notable changes to TicketZero AI - Zoho Edition will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-01-30

### Added
- **3-Day Trial License System** - Free trial for evaluation
  - Hardware-locked trials using machine fingerprinting
  - Encrypted trial data storage in multiple locations
  - Tamper detection with checksums
  - Clock manipulation prevention
  - Auto-expiration after 3 days
  - Interactive trial activation flow
  - Clear purchase options after trial expires
- New example script: `ticketzero_zoho_with_trial.py` showing trial integration
- Trial license module with comprehensive documentation
- `trial_license/` package with all trial management code
- Helper functions for Zoho Desk widget integration

### Security Features (Trial System)
- CPU, disk, and MAC address fingerprinting
- AES encryption for trial data
- Multi-location redundant storage (3 hidden locations)
- Prevents common bypass attempts (file deletion, clock changes, reinstalling)
- No hosting infrastructure required - fully local

### Documentation
- Added trial system README with usage examples
- Updated main README with trial information
- Added trial requirements (cryptography package)
- Widget integration examples for trial status display

## [1.0.0] - 2025-01-30

### Added
- Initial portfolio release of TicketZero AI - Zoho Desk Edition
- Automated support ticket resolution for Zoho Desk
- Zoho Desk widget integration
- Zoho Assist API for remote operations
- Microsoft Graph API integration for M365 tasks
- Local LLM-based ticket classification
- Intelligent decision-making for API selection
- Complete workflow automation:
  - Ticket analysis
  - Issue classification
  - Confidence scoring
  - Automated resolution via appropriate API
  - Ticket status updates
  - Resolution notes

### Integrated APIs
- **Zoho Desk API** - Ticket lifecycle management
- **Zoho Assist API** - Remote machine operations (disk cleanup, service restart, etc.)
- **Microsoft Graph API** - Azure AD operations (password reset, licenses, etc.)

### Core Components
- `02_APP_FILES/` - Zoho marketplace app files
  - Widget UI components
  - API handlers
  - Security and permissions
- `03_TEST_ENVIRONMENT/` - Local testing setup
- Multi-LLM engine with cost tracking
- Tier-1 ticket classifier
- Integrated resolution engine
- Security and compliance module

### Use Cases Supported
- Password resets (via Microsoft Graph)
- Disk cleanup (via Zoho Assist)
- Service restarts (via Zoho Assist)
- License assignments (via Microsoft Graph)
- Account management (via Microsoft Graph)
- Printer fixes (via Zoho Assist)
- Software installation (via Zoho Assist)

### Documentation
- Complete README with architecture diagram
- Technical architecture documentation
- Component usage mapping
- Local testing guide
- Response to marketplace questions
- Package contents listing

### License
- Portfolio demonstration version
- Commercial use requires licensing
- Zoho Marketplace ready
- Contact: jgreenia@jandraisolutions.com

[1.1.0]: https://github.com/Turtles-AI-Lab/TicketZero-Zoho-Edition/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Turtles-AI-Lab/TicketZero-Zoho-Edition/releases/tag/v1.0.0
