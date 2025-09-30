"""
Trial Guard - Main interface for trial protection
Easy-to-use wrapper for trial management
"""

import sys
from .trial_manager import TrialManager


class TrialGuard:
    """
    Easy-to-use trial license guard

    Example:
        guard = TrialGuard(app_name="TicketZero AI")

        if not guard.require_valid_trial():
            sys.exit(1)

        # Your app code here...
    """

    def __init__(self, app_name="TicketZero"):
        """
        Initialize trial guard

        Args:
            app_name: Your application name
        """
        self.app_name = app_name
        self.manager = TrialManager(app_name)
        self.status = None

    def require_valid_trial(self, auto_exit=False):
        """
        Check if valid trial exists, exit if not (optional)

        Args:
            auto_exit: If True, exits program when trial invalid

        Returns:
            bool: True if trial valid, False otherwise
        """
        self.status = self.manager.check_trial_status()

        if not self.status.get('active', False):
            self.show_trial_message()

            if auto_exit:
                sys.exit(1)

            return False

        return True

    def show_trial_message(self):
        """Display trial status message"""
        if not self.status:
            self.status = self.manager.check_trial_status()

        print("\n" + "="*70)
        print(f"  {self.app_name} - TRIAL LICENSE")
        print("="*70)

        status_type = self.status.get('status')

        if status_type == 'not_activated':
            self._show_activation_prompt()
        elif status_type == 'active':
            self._show_active_message()
        elif status_type == 'expired':
            self._show_expired_message()
        elif status_type in ['invalid', 'tampered', 'clock_tampered']:
            self._show_error_message()

        print("="*70 + "\n")

    def _show_activation_prompt(self):
        """Show trial activation prompt"""
        print("\n  No trial license found.")
        print("\n  Start your FREE 3-DAY TRIAL now!")
        print("\n  Features:")
        print("    ✓ Full access to all features")
        print("    ✓ No credit card required")
        print("    ✓ No limitations")
        print("\n  Would you like to start your trial? (yes/no): ", end='')

        try:
            response = input().strip().lower()
            if response in ['yes', 'y']:
                result = self.manager.activate_trial()
                if result['success']:
                    print("\n  ✓ Trial activated successfully!")
                    print(f"  ✓ Your trial expires in {self.manager.TRIAL_DAYS} days")
                    print(f"  ✓ Expiry date: {result['trial_data']['expiry_time']}")
                    self.status = self.manager.check_trial_status()
                else:
                    print(f"\n  ✗ Error: {result['error']}")
            else:
                print("\n  Trial not activated. Exiting...")
        except:
            print("\n  Trial activation cancelled.")

    def _show_active_message(self):
        """Show active trial message"""
        days = self.status.get('days_remaining', 0)
        hours = self.status.get('hours_remaining', 0)

        print(f"\n  ✓ Trial Active")
        print(f"\n  Time Remaining: {days:.1f} days ({hours:.1f} hours)")
        print(f"  Expires: {self.status.get('expiry_date')}")

        if days < 1:
            print("\n  ⚠ TRIAL ENDING SOON!")
            print("     Purchase a license to continue using after trial expires.")

    def _show_expired_message(self):
        """Show trial expired message"""
        print(f"\n  ✗ Trial Expired")
        print(f"\n  Your trial expired on: {self.status.get('expired_date')}")
        print(f"\n  To continue using {self.app_name}, please purchase a license.")
        print(f"\n  Purchase Options:")
        print(f"    • Email: jgreenia@jandraisolutions.com")
        print(f"    • Subject: {self.app_name} License Purchase")
        print(f"\n  Why purchase?")
        print(f"    ✓ Unlimited usage")
        print(f"    ✓ Priority support")
        print(f"    ✓ Free updates")
        print(f"    ✓ Custom integrations available")

    def _show_error_message(self):
        """Show error message"""
        status_type = self.status.get('status')
        message = self.status.get('message')

        print(f"\n  ✗ Trial Error: {status_type}")
        print(f"\n  {message}")
        print(f"\n  Please contact support: jgreenia@jandraisolutions.com")

    def get_status(self):
        """Get current trial status"""
        if not self.status:
            self.status = self.manager.check_trial_status()
        return self.status

    def is_valid(self):
        """Check if trial is currently valid"""
        return self.manager.is_trial_valid()

    def days_remaining(self):
        """Get days remaining in trial"""
        status = self.get_status()
        return status.get('days_remaining', 0)

    def show_trial_info_banner(self):
        """Show brief trial info banner (non-intrusive)"""
        if not self.is_valid():
            return

        status = self.get_status()
        days = status.get('days_remaining', 0)

        if days < 2:  # Show reminder when < 2 days left
            print(f"\n⏰ Trial Info: {days:.1f} days remaining | Purchase: jgreenia@jandraisolutions.com\n")


# Decorator for protecting functions
def require_trial(app_name="TicketZero"):
    """
    Decorator to protect functions with trial check

    Example:
        @require_trial("MyApp")
        def main():
            # Your code here
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            guard = TrialGuard(app_name)
            if not guard.require_valid_trial():
                return None
            return func(*args, **kwargs)
        return wrapper
    return decorator
