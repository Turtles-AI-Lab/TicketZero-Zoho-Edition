"""
Encryption utilities for trial data storage
Uses Fernet symmetric encryption with hardware-derived key
"""

import hashlib
import base64
import json
from cryptography.fernet import Fernet


class TrialCrypto:
    """Encrypt and decrypt trial data using hardware-derived key"""

    @staticmethod
    def _derive_key(machine_id, salt):
        """Derive encryption key from machine ID and salt"""
        key_material = f"{machine_id}{salt}".encode()
        key = hashlib.sha256(key_material).digest()
        return base64.urlsafe_b64encode(key)

    @staticmethod
    def encrypt_trial_data(data_dict, machine_id):
        """
        Encrypt trial data dictionary

        Args:
            data_dict: Dict containing trial data
            machine_id: Hardware machine ID

        Returns:
            Encrypted bytes
        """
        # Use machine ID as part of encryption key
        salt = "TurtlesAI2025"  # Static salt (change this)
        key = TrialCrypto._derive_key(machine_id, salt)

        cipher = Fernet(key)
        json_data = json.dumps(data_dict).encode()
        encrypted = cipher.encrypt(json_data)

        return encrypted

    @staticmethod
    def decrypt_trial_data(encrypted_bytes, machine_id):
        """
        Decrypt trial data

        Args:
            encrypted_bytes: Encrypted data
            machine_id: Hardware machine ID

        Returns:
            Decrypted dict or None if invalid
        """
        try:
            salt = "TurtlesAI2025"
            key = TrialCrypto._derive_key(machine_id, salt)

            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_bytes)
            data_dict = json.loads(decrypted.decode())

            return data_dict
        except Exception as e:
            return None

    @staticmethod
    def obfuscate_filename(base_name, machine_id):
        """Generate obfuscated filename based on machine ID"""
        name_hash = hashlib.md5(f"{base_name}{machine_id}".encode()).hexdigest()[:12]
        return f".{name_hash}.dat"


# Obfuscated aliases
_enc = TrialCrypto.encrypt_trial_data
_dec = TrialCrypto.decrypt_trial_data
_fname = TrialCrypto.obfuscate_filename
