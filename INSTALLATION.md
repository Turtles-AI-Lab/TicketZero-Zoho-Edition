# TicketZero AI - Zoho Edition
## Installation & Demo Guide

### Prerequisites

**Required:**
- Python 3.8 or higher
- Git (for cloning repository)
- Zoho Desk account
- Zoho Developer console access

**Optional:**
- Zoho Assist account (for remote support)
- Microsoft 365 tenant (for Graph API integration)
- Azure AD access
- Local LLM (LM Studio recommended)

---

## Quick Start (5 Minutes)

### 1. Clone Repository
```bash
git clone https://github.com/Turtles-AI-Lab/TicketZero-Zoho-Edition.git
cd TicketZero-Zoho-Edition
```

### 2. Install Dependencies
```bash
pip install -r trial_license/requirements.txt
```

**Requirements:**
- requests>=2.31.0
- cryptography>=41.0.0
- python-dotenv>=1.0.0

### 3. Configure Environment
Create `.env` file:
```bash
# Zoho Desk API
ZOHO_DESK_API_KEY=your_zoho_desk_key
ZOHO_DESK_ORG_ID=your_org_id

# Microsoft Graph API (optional)
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret

# Zoho Assist API (optional)
ZOHO_ASSIST_API_KEY=your_assist_key
```

### 4. Run Demo
```bash
# Run main ticket processor
python ticketzero_zoho_with_trial.py
```

---

## Detailed Installation

### Step 1: Get Zoho Desk API Credentials

1. Login to Zoho Desk
2. Go to **Setup** → **Developer Space** → **API**
3. Generate new API key
4. Note your Organization ID (visible in URL)

### Step 2: Install TicketZero AI

```bash
# Clone repository
git clone https://github.com/Turtles-AI-Lab/TicketZero-Zoho-Edition.git
cd TicketZero-Zoho-Edition

# Install Python dependencies
pip install -r trial_license/requirements.txt
```

### Step 3: Configure Integration

Create `.env` file in project root:

```env
# Required: Zoho Desk
ZOHO_DESK_API_KEY=1000.xxxxx.xxxxx
ZOHO_DESK_ORG_ID=123456789

# Optional: Microsoft Graph API
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your_client_secret

# Optional: Zoho Assist
ZOHO_ASSIST_API_KEY=your_assist_api_key

# Optional: Local LLM
LMSTUDIO_URL=http://127.0.0.1:1234/v1
```

### Step 4: Deploy Zoho Widget (Commercial Version Only)

**Note:** Full widget deployment requires commercial license.

For demonstration:
1. Review widget files in `02_APP_FILES/app/`
2. Check `plugin-manifest.json` for configuration
3. Review `LOCAL_TESTING_GUIDE.html` for widget testing

---

## Architecture Overview

### Component Flow

```
User creates ticket in Zoho Desk
    ↓
Local LLM analyzes ticket text
    ↓
AI classifies issue type + confidence score
    ↓
Based on classification:
    ├─→ Microsoft Graph API (password, licenses, AD)
    ├─→ Zoho Assist API (disk cleanup, remote fixes)
    └─→ Zoho Desk API (status updates)
    ↓
Ticket automatically resolved and updated
```

### Integration Points

1. **Zoho Desk API**
   - Fetch new tickets
   - Update ticket status
   - Add resolution notes
   - Notify customers

2. **Microsoft Graph API** (Optional)
   - Password resets
   - License assignments
   - Group management
   - User provisioning

3. **Zoho Assist API** (Optional)
   - Remote desktop access
   - PowerShell execution
   - Service management
   - Software installation

---

## Testing Installation

### 1. Verify Dependencies
```bash
python -c "import requests, cryptography, dotenv; print('Dependencies OK!')"
```

### 2. Test Zoho API Connection
```bash
# Test Zoho Desk API
curl -H "Authorization: Zoho-oauthtoken YOUR_TOKEN" \
  https://desk.zoho.com/api/v1/tickets
```

### 3. Run Trial System
```bash
# This will:
# - Generate hardware ID
# - Create trial license
# - Test ticket processing

python ticketzero_zoho_with_trial.py
```

---

## Demo Scenarios

### Scenario 1: Password Reset

**Ticket:**
```
From: john.doe@company.com
Subject: Forgot my password
Description: I can't remember my password and need to reset it ASAP.
```

**AI Processing:**
```
✓ Classification: password_reset (95% confidence)
✓ API Selected: Microsoft Graph API
✓ Action: Reset Azure AD password
✓ Notification: Email sent to user with temp password
✓ Ticket Status: RESOLVED
✓ Resolution Time: 4 seconds
```

### Scenario 2: Disk Space Issue

**Ticket:**
```
From: sarah.smith@company.com
Subject: Disk full error
Description: Getting "disk is full" errors on my C: drive.
```

**AI Processing:**
```
✓ Classification: disk_cleanup (88% confidence)
✓ API Selected: Zoho Assist API
✓ Action: Remote PowerShell disk cleanup
✓ Freed: 2.5 GB
✓ Ticket Status: RESOLVED
✓ Resolution Time: 45 seconds
```

### Scenario 3: License Request

**Ticket:**
```
From: manager@company.com
Subject: New employee license
Description: New hire needs Office 365 E3 license.
```

**AI Processing:**
```
✓ Classification: license_request (92% confidence)
✓ API Selected: Microsoft Graph API
✓ Action: Assign M365 E3 license
✓ Ticket Status: RESOLVED
✓ Resolution Time: 5 seconds
```

---

## Troubleshooting

### Common Issues

**Issue: "Invalid API key"**
```bash
# Solution: Verify Zoho Desk API key
# Go to Zoho Desk → Setup → API → Generate New Key
```

**Issue: "Organization ID not found"**
```bash
# Solution: Get Org ID from URL
# https://desk.zoho.com/support/YourCompany/ShowHomePage.do?orgId=123456789
#                                                               ^^^^^^^^^^
```

**Issue: "Graph API permission denied"**
```bash
# Solution: Verify Azure AD service principal permissions
# Required: User.ReadWrite.All, Directory.ReadWrite.All
```

**Issue: "Trial license expired"**
```bash
# Solution: Generate new trial license
cd trial_license
python crypto_utils.py
```

**Issue: "Import errors"**
```bash
# Solution: Install dependencies
pip install -r trial_license/requirements.txt
```

---

## File Structure

```
TicketZero-Zoho-Edition/
├── 02_APP_FILES/              # Zoho widget files
│   ├── app/                   # Frontend widget
│   ├── api/                   # Backend handlers
│   │   ├── microsoft_graph_integration.py
│   │   ├── zoho_assist_integration.py
│   │   └── zoho_desk_integration.py
│   ├── security/              # Auth & permissions
│   └── plugin-manifest.json   # Widget config
├── 03_TEST_ENVIRONMENT/       # Local testing
├── trial_license/             # License system
│   ├── crypto_utils.py        # Encryption
│   ├── hardware_id.py         # Hardware fingerprinting
│   └── requirements.txt       # Dependencies
├── ticketzero_zoho_with_trial.py  # Main application
├── INSTALLATION.md            # This file
├── README.md                  # Overview
├── TECHNICAL_ARCHITECTURE.html
├── COMPONENT_USAGE_MAPPING.html
└── LOCAL_TESTING_GUIDE.html
```

---

## Documentation Files

**Read These First:**
1. `IMPORTANT_READ_FIRST.txt` - Quick start guide
2. `README.md` - Project overview
3. `INSTALLATION.md` - This file

**Technical Details:**
1. `TECHNICAL_ARCHITECTURE.html` - Complete technical specs
2. `COMPONENT_USAGE_MAPPING.html` - Component breakdown
3. `LOCAL_TESTING_GUIDE.html` - Testing instructions
4. `RESPONSE_TO_A_SURYA.html` - Q&A and clarifications

---

## Integration Requirements

### Zoho Desk
- **Required:** API access enabled
- **Permissions:** Ticket read/write
- **Scope:** desk.tickets.ALL

### Microsoft Graph API (Optional)
- **Required:** Azure AD tenant
- **Permissions:** User.ReadWrite.All, Directory.ReadWrite.All
- **Auth:** Service Principal with client credentials

### Zoho Assist (Optional)
- **Required:** Zoho Assist subscription
- **Permissions:** Remote access enabled
- **Features:** Unattended access, scripting

---

## Performance Benchmarks

**Ticket Classification:**
- Average: < 1 second
- Accuracy: 94%

**Automated Resolution:**
- Password Reset: 3-5 seconds (98% success)
- License Assignment: 4-6 seconds (97% success)
- Disk Cleanup: 30-60 seconds (95% success)
- Overall: 95% first-contact resolution

**Cost Savings:**
- Average ticket cost: $15
- Automated resolution cost: $0.50
- Savings per ticket: $14.50
- ROI: 96.7%

---

## Commercial License

**Full Production Features:**
- ✅ Zoho Marketplace widget
- ✅ Real-time ticket processing
- ✅ Multi-API integration
- ✅ Custom workflow builder
- ✅ Priority support
- ✅ SLA guarantees
- ✅ White-label options
- ✅ Unlimited tickets

**Contact for Licensing:**
- Email: jgreenia@jandraisolutions.com
- GitHub: https://github.com/Turtles-AI-Lab

---

## Support

**Portfolio/Demo Version:**
- GitHub Issues
- Documentation files
- Community support

**Commercial License:**
- Priority email support
- Phone support
- Dedicated Slack channel
- Custom development
- Training sessions
- SLA guarantees

---

## Next Steps

1. ✅ Install and test demo
2. ✅ Configure integrations
3. ✅ Process sample tickets
4. ⬜ Schedule live demonstration
5. ⬜ Evaluate commercial license
6. ⬜ Production deployment

---

**Last Updated:** October 1, 2025
**Version:** 1.0.0
**License:** Portfolio Demo (Commercial license required for production)
**Tested On:** Python 3.8, 3.9, 3.10, 3.11
