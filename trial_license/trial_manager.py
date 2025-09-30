"""
Trial License Manager
Handles 3-day trial activation, validation, and expiration
"""

import os
import time
import json
from datetime import datetime, timedelta
from pathlib import Path

from .hardware_id import HardwareFingerprint
from .crypto_utils import TrialCrypto


class TrialManager:
    """
    Manages 3-day trial licenses

    Features:
    - Hardware-locked trials
    - Multiple storage locations for redundancy
    - Encrypted trial data
    - Clock tampering detection
    - Auto-expiration after 3 days
    """

    TRIAL_DAYS = 3
    APP_NAME = "TicketZero"

    def __init__(self, app_name=None):
        """
        Initialize trial manager

        Args:
            app_name: Application name (default: TicketZero)
        """
        if app_name:
            self.APP_NAME = app_name

        self.machine_id = HardwareFingerprint.get_machine_id()
        self.storage_paths = self._get_storage_locations()

    def _get_storage_locations(self):
        """Get multiple storage locations for trial data"""
        locations = []

        # Location 1: User home directory (hidden)
        home = Path.home()
        locations.append(home / TrialCrypto.obfuscate_filename(self.APP_NAME, self.machine_id))

        # Location 2: Temp directory
        temp = Path(os.environ.get('TEMP', '/tmp'))
        locations.append(temp / TrialCrypto.obfuscate_filename(f"{self.APP_NAME}_t", self.machine_id))

        # Location 3: AppData/Application Support
        if os.name == 'nt':  # Windows
            appdata = Path(os.environ.get('LOCALAPPDATA', home))
            locations.append(appdata / '.cache' / TrialCrypto.obfuscate_filename(self.APP_NAME, self.machine_id))
        else:  # Unix-like
            locations.append(home / '.local' / 'share' / TrialCrypto.obfuscate_filename(self.APP_NAME, self.machine_id))

        return locations

    def activate_trial(self):
        """
        Activate a new trial

        Returns:
            dict: Trial info or error
        """
        # Check if trial already exists
        existing_trial = self._load_trial_data()
        if existing_trial:
            return {
                'success': False,
                'error': 'Trial already activated on this machine',
                'trial_data': existing_trial
            }

        # Create new trial
        now = time.time()
        trial_data = {
            'machine_id': self.machine_id,
            'start_time': now,
            'expiry_time': now + (self.TRIAL_DAYS * 24 * 60 * 60),
            'app_name': self.APP_NAME,
            'version': '1.0',
            'checksum': self._generate_checksum(now)
        }

        # Save to multiple locations
        self._save_trial_data(trial_data)

        return {
            'success': True,
            'trial_data': trial_data,
            'days_remaining': self.TRIAL_DAYS
        }

    def check_trial_status(self):
        """
        Check current trial status

        Returns:
            dict: Status information
        """
        trial_data = self._load_trial_data()

        if not trial_data:
            return {
                'active': False,
                'status': 'not_activated',
                'message': 'No trial found. Start your free 3-day trial!',
                'can_activate': True
            }

        # Verify machine ID
        if trial_data.get('machine_id') != self.machine_id:
            return {
                'active': False,
                'status': 'invalid',
                'message': 'Trial is locked to a different machine',
                'can_activate': False
            }

        # Verify checksum (detect tampering)
        if not self._verify_checksum(trial_data):
            return {
                'active': False,
                'status': 'tampered',
                'message': 'Trial data has been tampered with',
                'can_activate': False
            }

        # Check expiration
        now = time.time()
        start_time = trial_data.get('start_time', 0)
        expiry_time = trial_data.get('expiry_time', 0)

        # Detect clock tampering (start time in future)
        if start_time > now + 3600:  # 1 hour tolerance
            return {
                'active': False,
                'status': 'clock_tampered',
                'message': 'System clock has been tampered with',
                'can_activate': False
            }

        if now >= expiry_time:
            days_expired = (now - expiry_time) / (24 * 60 * 60)
            return {
                'active': False,
                'status': 'expired',
                'message': f'Trial expired {int(days_expired)} days ago',
                'can_activate': False,
                'expired_date': datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M')
            }

        # Active trial
        time_remaining = expiry_time - now
        hours_remaining = time_remaining / 3600
        days_remaining = time_remaining / (24 * 60 * 60)

        return {
            'active': True,
            'status': 'active',
            'message': f'Trial active - {days_remaining:.1f} days remaining',
            'days_remaining': days_remaining,
            'hours_remaining': hours_remaining,
            'expiry_date': datetime.fromtimestamp(expiry_time).strftime('%Y-%m-%d %H:%M'),
            'start_date': datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M')
        }

    def is_trial_valid(self):
        """Quick check if trial is currently valid"""
        status = self.check_trial_status()
        return status.get('active', False)

    def _load_trial_data(self):
        """Load trial data from storage locations"""
        for path in self.storage_paths:
            if path.exists():
                try:
                    with open(path, 'rb') as f:
                        encrypted = f.read()

                    decrypted = TrialCrypto.decrypt_trial_data(encrypted, self.machine_id)
                    if decrypted:
                        return decrypted
                except:
                    continue

        return None

    def _save_trial_data(self, trial_data):
        """Save trial data to multiple locations"""
        encrypted = TrialCrypto.encrypt_trial_data(trial_data, self.machine_id)

        for path in self.storage_paths:
            try:
                # Create parent directories if needed
                path.parent.mkdir(parents=True, exist_ok=True)

                with open(path, 'wb') as f:
                    f.write(encrypted)

                # Hide file on Windows
                if os.name == 'nt':
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(str(path), 2)  # FILE_ATTRIBUTE_HIDDEN
                    except:
                        pass
            except:
                continue

    def _generate_checksum(self, timestamp):
        """Generate checksum for tampering detection"""
        import hashlib
        data = f"{self.machine_id}{timestamp}{self.APP_NAME}".encode()
        return hashlib.sha256(data).hexdigest()

    def _verify_checksum(self, trial_data):
        """Verify trial data hasn't been tampered with"""
        expected = self._generate_checksum(trial_data.get('start_time', 0))
        actual = trial_data.get('checksum', '')
        return expected == actual

    def get_purchase_url(self):
        """Get URL for purchasing full license"""
        return "mailto:jgreenia@jandraisolutions.com?subject=TicketZero License Purchase"


# Quick access functions
def check_trial():
    """Quick trial check"""
    manager = TrialManager()
    return manager.check_trial_status()


def is_valid():
    """Quick validity check"""
    manager = TrialManager()
    return manager.is_trial_valid()
