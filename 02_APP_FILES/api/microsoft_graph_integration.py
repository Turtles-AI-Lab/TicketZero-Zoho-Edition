"""
TicketZero AI - Microsoft Graph API Integration
Handles Azure AD and Microsoft 365 operations
"""

import requests
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Optional, List

logger = logging.getLogger("TicketZero.MSGraph")

class MicrosoftGraphClient:
    """
    Client for Microsoft Graph API operations
    Handles authentication and common Azure AD tasks
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = "https://graph.microsoft.com/v1.0"
        self.token = None
        self.token_expiry = None

    def _get_access_token(self) -> str:
        """
        Get or refresh access token using client credentials flow
        """
        if self.token and self.token_expiry and datetime.now() < self.token_expiry:
            return self.token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default',
            'grant_type': 'client_credentials'
        }

        response = requests.post(token_url, data=data)
        if response.status_code == 200:
            token_data = response.json()
            self.token = token_data['access_token']
            expires_in = token_data.get('expires_in', 3600)
            self.token_expiry = datetime.now() + timedelta(seconds=expires_in - 60)
            logger.info("Successfully obtained Microsoft Graph access token")
            return self.token
        else:
            logger.error(f"Failed to get access token: {response.text}")
            raise Exception("Failed to authenticate with Microsoft Graph")

    def _make_request(self, method: str, endpoint: str, data: Dict = None) -> Dict:
        """
        Make authenticated request to Microsoft Graph API
        """
        token = self._get_access_token()
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        url = f"{self.base_url}{endpoint}"

        if method == 'GET':
            response = requests.get(url, headers=headers)
        elif method == 'POST':
            response = requests.post(url, headers=headers, json=data)
        elif method == 'PATCH':
            response = requests.patch(url, headers=headers, json=data)
        elif method == 'DELETE':
            response = requests.delete(url, headers=headers)
        else:
            raise ValueError(f"Unsupported method: {method}")

        if response.status_code in [200, 201, 204]:
            return response.json() if response.text else {}
        else:
            logger.error(f"API request failed: {response.status_code} - {response.text}")
            raise Exception(f"Microsoft Graph API error: {response.status_code}")

    def reset_user_password(self, user_email: str) -> Dict:
        """
        Reset user password in Azure AD

        Args:
            user_email: User's email address

        Returns:
            Dictionary with new temporary password
        """
        # First, get user ID from email
        user = self.get_user_by_email(user_email)
        if not user:
            raise Exception(f"User not found: {user_email}")

        user_id = user['id']

        # Generate temporary password
        import secrets
        import string
        temp_password = ''.join(secrets.choice(string.ascii_letters + string.digits + '!@#$') for _ in range(16))

        # Reset password
        endpoint = f"/users/{user_id}/authentication/passwordMethods/28c10230-6103-485e-b985-444c60001490/resetPassword"
        data = {
            "newPassword": temp_password,
            "requireChangeOnNextSignIn": True
        }

        try:
            self._make_request('POST', endpoint, data)
            logger.info(f"Successfully reset password for user: {user_email}")
            return {
                "success": True,
                "user_email": user_email,
                "temporary_password": temp_password,
                "require_change": True
            }
        except Exception as e:
            logger.error(f"Failed to reset password: {str(e)}")
            raise

    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """
        Get user details from Azure AD by email
        """
        endpoint = f"/users/{email}"
        try:
            user = self._make_request('GET', endpoint)
            return user
        except:
            # Try searching for user
            endpoint = f"/users?$filter=mail eq '{email}' or userPrincipalName eq '{email}'"
            result = self._make_request('GET', endpoint)
            if result.get('value'):
                return result['value'][0]
            return None

    def unlock_user_account(self, user_email: str) -> bool:
        """
        Unlock user account by enabling it
        """
        user = self.get_user_by_email(user_email)
        if not user:
            raise Exception(f"User not found: {user_email}")

        user_id = user['id']
        endpoint = f"/users/{user_id}"
        data = {
            "accountEnabled": True
        }

        try:
            self._make_request('PATCH', endpoint, data)
            logger.info(f"Successfully unlocked account: {user_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to unlock account: {str(e)}")
            return False

    def add_user_to_group(self, user_email: str, group_name: str) -> bool:
        """
        Add user to an Azure AD group
        """
        # Get user
        user = self.get_user_by_email(user_email)
        if not user:
            raise Exception(f"User not found: {user_email}")

        # Get group
        group_endpoint = f"/groups?$filter=displayName eq '{group_name}'"
        groups_result = self._make_request('GET', group_endpoint)

        if not groups_result.get('value'):
            raise Exception(f"Group not found: {group_name}")

        group_id = groups_result['value'][0]['id']
        user_id = user['id']

        # Add member to group
        endpoint = f"/groups/{group_id}/members/$ref"
        data = {
            "@odata.id": f"https://graph.microsoft.com/v1.0/directoryObjects/{user_id}"
        }

        try:
            self._make_request('POST', endpoint, data)
            logger.info(f"Successfully added {user_email} to group {group_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to add user to group: {str(e)}")
            return False

    def assign_license(self, user_email: str, sku_id: str) -> bool:
        """
        Assign Microsoft 365 license to user
        """
        user = self.get_user_by_email(user_email)
        if not user:
            raise Exception(f"User not found: {user_email}")

        user_id = user['id']
        endpoint = f"/users/{user_id}/assignLicense"

        data = {
            "addLicenses": [
                {
                    "skuId": sku_id
                }
            ],
            "removeLicenses": []
        }

        try:
            self._make_request('POST', endpoint, data)
            logger.info(f"Successfully assigned license to: {user_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to assign license: {str(e)}")
            return False

    def get_user_details(self, user_email: str) -> Optional[Dict]:
        """
        Get comprehensive user details including licenses and group memberships
        """
        user = self.get_user_by_email(user_email)
        if not user:
            return None

        user_id = user['id']

        # Get group memberships
        groups_endpoint = f"/users/{user_id}/memberOf"
        groups_result = self._make_request('GET', groups_endpoint)

        # Get assigned licenses
        licenses_endpoint = f"/users/{user_id}/licenseDetails"
        licenses_result = self._make_request('GET', licenses_endpoint)

        return {
            "user": user,
            "groups": groups_result.get('value', []),
            "licenses": licenses_result.get('value', [])
        }

    def disable_user_account(self, user_email: str) -> bool:
        """
        Disable user account (for security incidents)
        """
        user = self.get_user_by_email(user_email)
        if not user:
            raise Exception(f"User not found: {user_email}")

        user_id = user['id']
        endpoint = f"/users/{user_id}"
        data = {
            "accountEnabled": False
        }

        try:
            self._make_request('PATCH', endpoint, data)
            logger.info(f"Successfully disabled account: {user_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to disable account: {str(e)}")
            return False

    def revoke_user_sessions(self, user_email: str) -> bool:
        """
        Revoke all active sessions for a user (security response)
        """
        user = self.get_user_by_email(user_email)
        if not user:
            raise Exception(f"User not found: {user_email}")

        user_id = user['id']
        endpoint = f"/users/{user_id}/revokeSignInSessions"

        try:
            self._make_request('POST', endpoint)
            logger.info(f"Successfully revoked sessions for: {user_email}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke sessions: {str(e)}")
            return False


# WARNING: DO NOT hardcode credentials here!
# Use environment variables or secure configuration management
GRAPH_CONFIG = {
    "tenant_id": os.getenv("AZURE_TENANT_ID"),
    "client_id": os.getenv("AZURE_CLIENT_ID"),
    "client_secret": os.getenv("AZURE_CLIENT_SECRET")
}