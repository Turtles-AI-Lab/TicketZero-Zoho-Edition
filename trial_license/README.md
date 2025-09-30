# TicketZero Trial License System

Secure, local-only 3-day trial system with hardware fingerprinting and encrypted storage.

## Features

- ✅ **Hardware-Locked** - Binds trial to specific machine
- ✅ **Encrypted Storage** - Trial data stored encrypted in multiple locations
- ✅ **Tamper Detection** - Detects clock tampering and data modification
- ✅ **No Hosting Required** - 100% local, no external dependencies
- ✅ **Easy Integration** - Simple API, 3 lines of code

## Security Features

### Prevents Common Bypass Attempts:
- ❌ Deleting trial files (stored in 3 locations)
- ❌ Changing system clock (timestamp validation)
- ❌ Reinstalling software (hardware fingerprint)
- ❌ Modifying trial data (encrypted + checksums)
- ❌ Transferring to another machine (hardware-locked)

## Installation

```bash
pip install cryptography
```

Copy the `trial_license` folder to your project.

## Usage

### Basic Usage

```python
from trial_license import TrialGuard

# Initialize guard
guard = TrialGuard(app_name="TicketZero AI")

# Check trial and exit if invalid
if not guard.require_valid_trial(auto_exit=True):
    sys.exit(1)

# Your app code runs here...
print("App is running with valid trial!")
```

### As a Decorator

```python
from trial_license import require_trial

@require_trial("TicketZero AI")
def main():
    # Your main app logic
    print("Running main application")

if __name__ == "__main__":
    main()
```

### Manual Control

```python
from trial_license import TrialGuard

guard = TrialGuard()

# Check status
status = guard.get_status()
print(f"Trial active: {status['active']}")
print(f"Days remaining: {status.get('days_remaining', 0)}")

# Show info banner
guard.show_trial_info_banner()

# Check if valid
if guard.is_valid():
    # Run app
    pass
else:
    # Show message and exit
    guard.show_trial_message()
```

## Trial Flow

### 1. First Run (No Trial)
```
========================================
  TicketZero AI - TRIAL LICENSE
========================================

  No trial license found.

  Start your FREE 3-DAY TRIAL now!

  Features:
    ✓ Full access to all features
    ✓ No credit card required
    ✓ No limitations

  Would you like to start your trial? (yes/no):
```

### 2. Active Trial
```
========================================
  TicketZero AI - TRIAL LICENSE
========================================

  ✓ Trial Active

  Time Remaining: 2.5 days (60.0 hours)
  Expires: 2025-10-03 14:30

========================================
```

### 3. Expired Trial
```
========================================
  TicketZero AI - TRIAL LICENSE
========================================

  ✗ Trial Expired

  Your trial expired on: 2025-10-03 14:30

  To continue using TicketZero AI, please purchase a license.

  Purchase Options:
    • Email: jgreenia@jandraisolutions.com
    • Subject: TicketZero AI License Purchase

  Why purchase?
    ✓ Unlimited usage
    ✓ Priority support
    ✓ Free updates
    ✓ Custom integrations available

========================================
```

## API Reference

### TrialGuard

#### `__init__(app_name="TicketZero")`
Initialize trial guard with your app name.

#### `require_valid_trial(auto_exit=False) -> bool`
Check if trial is valid. Optionally exit if invalid.

#### `show_trial_message()`
Display interactive trial status message.

#### `get_status() -> dict`
Get detailed trial status.

#### `is_valid() -> bool`
Quick check if trial is currently valid.

#### `days_remaining() -> float`
Get days remaining in trial.

#### `show_trial_info_banner()`
Show brief non-intrusive trial reminder.

### Trial Manager

#### `TrialManager(app_name)`
Low-level trial management (usually not needed directly).

#### `activate_trial() -> dict`
Activate a new trial.

#### `check_trial_status() -> dict`
Get detailed status.

#### `is_trial_valid() -> bool`
Quick validity check.

## Integration Examples

### Flask Web App

```python
from flask import Flask
from trial_license import TrialGuard

app = Flask(__name__)
guard = TrialGuard("TicketZero Web")

@app.before_request
def check_trial():
    if not guard.is_valid():
        return guard.show_trial_message(), 403

@app.route('/')
def index():
    return "App running!"
```

### Command-Line Tool

```python
import sys
from trial_license import TrialGuard

def main():
    guard = TrialGuard("TicketZero CLI")

    if not guard.require_valid_trial():
        sys.exit(1)

    # Show reminder if trial ending soon
    guard.show_trial_info_banner()

    # Your CLI logic here
    print("Running command...")

if __name__ == "__main__":
    main()
```

## Storage Locations

Trial data is stored encrypted in multiple locations:

**Windows:**
- `%USERPROFILE%\.{hash}.dat`
- `%TEMP%\.{hash}.dat`
- `%LOCALAPPDATA%\.cache\.{hash}.dat`

**Linux/Mac:**
- `~/.{hash}.dat`
- `/tmp/.{hash}.dat`
- `~/.local/share/.{hash}.dat`

Files are hidden and names are hashed based on machine ID.

## Limitations

**What this system does:**
- Stops 95% of casual users from bypassing trial
- Makes it difficult to extend trial
- Detects common tampering attempts

**What this system doesn't do:**
- Stop a determined programmer with reverse engineering skills
- Protect against VM snapshots/cloning
- Require internet connection (fully offline)

For maximum security, consider a server-based licensing system.

## License

© 2025 Turtles AI Lab. All rights reserved.
This code is for use with TicketZero products only.

## Support

Email: jgreenia@jandraisolutions.com
