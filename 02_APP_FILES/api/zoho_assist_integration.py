"""
TicketZero AI - Zoho Assist Integration
Handles remote machine access and local operations
"""

import requests
import json
import logging
import time
from typing import Dict, Optional, List, Any
from datetime import datetime

logger = logging.getLogger("TicketZero.ZohoAssist")

class ZohoAssistClient:
    """
    Client for Zoho Assist API operations
    Handles remote access, command execution, and file transfers
    """

    def __init__(self, auth_token: str, organization_id: str):
        self.auth_token = auth_token
        self.organization_id = organization_id
        self.base_url = "https://assist.zoho.com/api/v2"
        self.headers = {
            'Authorization': f'Zoho-oauthtoken {auth_token}',
            'Content-Type': 'application/json'
        }

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """
        Make authenticated request to Zoho Assist API
        """
        url = f"{self.base_url}{endpoint}"

        try:
            if method == 'GET':
                response = requests.get(url, headers=self.headers)
            elif method == 'POST':
                response = requests.post(url, headers=self.headers, json=data)
            elif method == 'PUT':
                response = requests.put(url, headers=self.headers, json=data)
            elif method == 'DELETE':
                response = requests.delete(url, headers=self.headers)
            else:
                raise ValueError(f"Unsupported method: {method}")

            if response.status_code in [200, 201]:
                return response.json()
            else:
                logger.error(f"Zoho Assist API error: {response.status_code} - {response.text}")
                raise Exception(f"Zoho Assist API error: {response.status_code}")

        except Exception as e:
            logger.error(f"Request failed: {str(e)}")
            raise

    def get_unattended_computers(self) -> List[Dict]:
        """
        Get list of computers with unattended access configured
        """
        endpoint = f"/unattended/computers?organization_id={self.organization_id}"
        result = self._make_request('GET', endpoint)
        return result.get('computers', [])

    def find_computer_by_name(self, computer_name: str) -> Optional[Dict]:
        """
        Find computer by name or partial match
        """
        computers = self.get_unattended_computers()
        for computer in computers:
            if computer_name.lower() in computer.get('computer_name', '').lower():
                return computer
        return None

    def initiate_unattended_session(self, computer_id: str, reason: str = "Automated support") -> Dict:
        """
        Start an unattended remote session

        Args:
            computer_id: ID of the target computer
            reason: Reason for access (for audit trail)

        Returns:
            Session details including session_id
        """
        endpoint = "/sessions/unattended"
        data = {
            "computer_id": computer_id,
            "organization_id": self.organization_id,
            "reason": reason,
            "type": "unattended_access"
        }

        session = self._make_request('POST', endpoint, data)
        logger.info(f"Initiated unattended session: {session.get('session_id')}")
        return session

    def execute_command(self, session_id: str, command: str,
                       command_type: str = "powershell") -> Dict:
        """
        Execute command on remote machine

        Args:
            session_id: Active session ID
            command: Command to execute
            command_type: Type of command (powershell, cmd, bash)

        Returns:
            Command execution result
        """
        endpoint = f"/sessions/{session_id}/execute"
        data = {
            "command": command,
            "type": command_type,
            "wait_for_completion": True,
            "timeout": 300  # 5 minutes timeout
        }

        result = self._make_request('POST', endpoint, data)
        logger.info(f"Executed command in session {session_id}")
        return result

    def clean_disk_space(self, computer_name: str) -> Dict:
        """
        Clean disk space on remote computer
        """
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise Exception(f"Computer not found: {computer_name}")

        session = self.initiate_unattended_session(
            computer['computer_id'],
            "Automated disk cleanup requested via ticket"
        )

        commands = [
            # Clear Windows temp files
            "Remove-Item -Path $env:TEMP\\* -Recurse -Force -ErrorAction SilentlyContinue",
            # Clear recycle bin
            "Clear-RecycleBin -Force -ErrorAction SilentlyContinue",
            # Clear Windows update cache
            "Stop-Service -Name wuauserv",
            "Remove-Item -Path C:\\Windows\\SoftwareDistribution\\Download\\* -Recurse -Force",
            "Start-Service -Name wuauserv",
            # Get disk space after cleanup
            "Get-PSDrive C | Select-Object Used,Free"
        ]

        results = []
        for cmd in commands:
            try:
                result = self.execute_command(session['session_id'], cmd, 'powershell')
                results.append(result)
            except Exception as e:
                logger.error(f"Command failed: {cmd} - {str(e)}")

        self.end_session(session['session_id'])

        return {
            "success": True,
            "computer": computer_name,
            "session_id": session['session_id'],
            "operations_performed": len(commands),
            "results": results
        }

    def restart_service(self, computer_name: str, service_name: str) -> Dict:
        """
        Restart a Windows service on remote computer
        """
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise Exception(f"Computer not found: {computer_name}")

        session = self.initiate_unattended_session(
            computer['computer_id'],
            f"Restart service: {service_name}"
        )

        # PowerShell commands to restart service
        commands = [
            f"Get-Service -Name {service_name}",
            f"Stop-Service -Name {service_name} -Force",
            f"Start-Service -Name {service_name}",
            f"Get-Service -Name {service_name}"
        ]

        results = []
        for cmd in commands:
            result = self.execute_command(session['session_id'], cmd, 'powershell')
            results.append(result)

        self.end_session(session['session_id'])

        return {
            "success": True,
            "computer": computer_name,
            "service": service_name,
            "status": "restarted",
            "results": results
        }

    def install_software(self, computer_name: str, package_url: str,
                        silent_args: str = "/quiet") -> Dict:
        """
        Install software on remote computer

        Args:
            computer_name: Target computer name
            package_url: URL or path to installation package
            silent_args: Silent installation arguments
        """
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise Exception(f"Computer not found: {computer_name}")

        session = self.initiate_unattended_session(
            computer['computer_id'],
            f"Software installation from ticket"
        )

        # Download and install software
        install_script = f"""
        $url = '{package_url}'
        $output = '$env:TEMP\\installer.msi'
        Invoke-WebRequest -Uri $url -OutFile $output
        Start-Process msiexec.exe -ArgumentList '/i', $output, '{silent_args}' -Wait
        Remove-Item $output
        """

        result = self.execute_command(session['session_id'], install_script, 'powershell')
        self.end_session(session['session_id'])

        return {
            "success": True,
            "computer": computer_name,
            "package": package_url,
            "installation_result": result
        }

    def fix_printer_issues(self, computer_name: str) -> Dict:
        """
        Fix common printer issues on remote computer
        """
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise Exception(f"Computer not found: {computer_name}")

        session = self.initiate_unattended_session(
            computer['computer_id'],
            "Fix printer issues from ticket"
        )

        commands = [
            # Clear print queue
            "Stop-Service -Name Spooler -Force",
            "Remove-Item -Path C:\\Windows\\System32\\spool\\PRINTERS\\* -Force",
            "Start-Service -Name Spooler",
            # Restart print service
            "Restart-Service -Name Spooler",
            # Get printer status
            "Get-Printer | Select-Object Name, PrinterStatus"
        ]

        results = []
        for cmd in commands:
            result = self.execute_command(session['session_id'], cmd, 'powershell')
            results.append(result)

        self.end_session(session['session_id'])

        return {
            "success": True,
            "computer": computer_name,
            "actions": ["Cleared print queue", "Restarted spooler service"],
            "results": results
        }

    def get_system_info(self, computer_name: str) -> Dict:
        """
        Get system information from remote computer
        """
        computer = self.find_computer_by_name(computer_name)
        if not computer:
            raise Exception(f"Computer not found: {computer_name}")

        session = self.initiate_unattended_session(
            computer['computer_id'],
            "System diagnostics from ticket"
        )

        info_script = """
        $computerInfo = Get-ComputerInfo | Select-Object CsName, WindowsVersion, OsArchitecture, CsTotalPhysicalMemory
        $diskInfo = Get-PSDrive C | Select-Object Used, Free
        $processes = Get-Process | Sort-Object WS -Descending | Select-Object -First 5 Name, WS

        @{
            ComputerInfo = $computerInfo
            DiskInfo = $diskInfo
            TopProcesses = $processes
        } | ConvertTo-Json
        """

        result = self.execute_command(session['session_id'], info_script, 'powershell')
        self.end_session(session['session_id'])

        return {
            "success": True,
            "computer": computer_name,
            "system_info": json.loads(result.get('output', '{}'))
        }

    def end_session(self, session_id: str) -> bool:
        """
        End a remote session
        """
        endpoint = f"/sessions/{session_id}/end"
        try:
            self._make_request('POST', endpoint)
            logger.info(f"Ended session: {session_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to end session: {str(e)}")
            return False

    def transfer_file(self, session_id: str, local_path: str,
                     remote_path: str) -> bool:
        """
        Transfer file to remote computer
        """
        endpoint = f"/sessions/{session_id}/transfer"
        data = {
            "source": local_path,
            "destination": remote_path,
            "direction": "upload"
        }

        try:
            result = self._make_request('POST', endpoint, data)
            logger.info(f"File transferred: {local_path} -> {remote_path}")
            return True
        except Exception as e:
            logger.error(f"File transfer failed: {str(e)}")
            return False

    def get_session_recording(self, session_id: str) -> Optional[str]:
        """
        Get recording URL for audit purposes
        """
        endpoint = f"/sessions/{session_id}/recording"
        try:
            result = self._make_request('GET', endpoint)
            return result.get('recording_url')
        except:
            return None


# Example configuration
ZOHO_ASSIST_CONFIG = {
    "auth_token": "your-zoho-assist-token",
    "organization_id": "your-org-id"
}