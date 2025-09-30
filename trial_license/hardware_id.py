"""
Hardware fingerprinting for trial license binding
Generates unique machine identifier based on multiple hardware components
"""

import hashlib
import platform
import subprocess
import os


class HardwareFingerprint:
    """Generate unique hardware-based machine ID"""

    @staticmethod
    def get_machine_id():
        """
        Generate unique machine identifier from multiple hardware sources
        Returns consistent ID for the same machine
        """
        components = []

        # CPU info
        try:
            if platform.system() == "Windows":
                cpu = subprocess.check_output("wmic cpu get ProcessorId", shell=True).decode()
                components.append(cpu.strip().split('\n')[1] if len(cpu.strip().split('\n')) > 1 else "")
            elif platform.system() == "Linux":
                with open('/proc/cpuinfo', 'r') as f:
                    for line in f:
                        if 'Serial' in line:
                            components.append(line.split(':')[1].strip())
                            break
            elif platform.system() == "Darwin":  # macOS
                cpu = subprocess.check_output("sysctl -n machdep.cpu.brand_string", shell=True).decode()
                components.append(cpu.strip())
        except:
            pass

        # Disk serial
        try:
            if platform.system() == "Windows":
                disk = subprocess.check_output("wmic diskdrive get SerialNumber", shell=True).decode()
                components.append(disk.strip().split('\n')[1] if len(disk.strip().split('\n')) > 1 else "")
            elif platform.system() == "Linux":
                disk = subprocess.check_output("lsblk -o SERIAL -n", shell=True).decode()
                components.append(disk.strip().split('\n')[0])
            elif platform.system() == "Darwin":
                disk = subprocess.check_output("system_profiler SPSerialATADataType | grep 'Serial Number'", shell=True).decode()
                components.append(disk.strip())
        except:
            pass

        # MAC address
        try:
            if platform.system() == "Windows":
                mac = subprocess.check_output("getmac", shell=True).decode()
                components.append(mac.strip().split('\n')[3] if len(mac.strip().split('\n')) > 3 else "")
            else:
                import uuid
                components.append(':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                                           for elements in range(0,2*6,2)][::-1]))
        except:
            pass

        # System UUID (Windows)
        try:
            if platform.system() == "Windows":
                uuid_str = subprocess.check_output("wmic csproduct get UUID", shell=True).decode()
                components.append(uuid_str.strip().split('\n')[1] if len(uuid_str.strip().split('\n')) > 1 else "")
        except:
            pass

        # Motherboard serial
        try:
            if platform.system() == "Windows":
                mb = subprocess.check_output("wmic baseboard get SerialNumber", shell=True).decode()
                components.append(mb.strip().split('\n')[1] if len(mb.strip().split('\n')) > 1 else "")
        except:
            pass

        # Username + hostname as fallback
        components.append(os.getenv('USERNAME', os.getenv('USER', 'unknown')))
        components.append(platform.node())

        # Combine all components and hash
        combined = '|'.join([c for c in components if c])
        machine_id = hashlib.sha256(combined.encode()).hexdigest()

        return machine_id

    @staticmethod
    def verify_machine_id(stored_id):
        """Verify if current machine matches stored ID"""
        current_id = HardwareFingerprint.get_machine_id()
        return current_id == stored_id


# Obfuscated function names to make harder to find
_hwid = HardwareFingerprint.get_machine_id
_verify = HardwareFingerprint.verify_machine_id
