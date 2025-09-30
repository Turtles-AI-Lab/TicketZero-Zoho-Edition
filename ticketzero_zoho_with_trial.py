"""
TicketZero AI - Zoho Edition with Trial License Protection
This example shows how to integrate the trial system into Zoho Desk widget
"""

import sys
import os

# Add trial license to path
sys.path.insert(0, os.path.dirname(__file__))

from trial_license import TrialGuard


class TicketZeroZohoWithTrial:
    """
    TicketZero Zoho Edition with trial protection

    Usage:
        app = TicketZeroZohoWithTrial()
        if app.check_license():
            app.run()
    """

    def __init__(self):
        """Initialize with trial guard"""
        self.guard = TrialGuard(app_name="TicketZero AI - Zoho Edition")
        self.trial_valid = False

    def check_license(self):
        """
        Check trial license validity

        Returns:
            bool: True if trial valid, False otherwise
        """
        if not self.guard.require_valid_trial():
            return False

        self.trial_valid = True
        return True

    def get_trial_status(self):
        """Get current trial status for display in UI"""
        status = self.guard.get_status()

        return {
            'active': status.get('active', False),
            'days_remaining': status.get('days_remaining', 0),
            'hours_remaining': status.get('hours_remaining', 0),
            'expiry_date': status.get('expiry_date', ''),
            'status': status.get('status', 'unknown'),
            'message': status.get('message', '')
        }

    def show_trial_banner(self):
        """Show trial info banner"""
        self.guard.show_trial_info_banner()

    def run(self):
        """Run TicketZero Zoho workflow"""
        if not self.trial_valid:
            print("❌ Cannot run - trial not valid")
            return

        print("="*70)
        print("  TicketZero AI - Zoho Desk Edition")
        print("  Automated Support Ticket Resolution")
        print("="*70)

        # Show trial status
        status = self.get_trial_status()
        if status['active']:
            print(f"\n  📅 Trial Status: {status['days_remaining']:.1f} days remaining")

        print("\n  Starting TicketZero Zoho workflow...")
        print("="*70 + "\n")

        # ===================================================================
        # YOUR TICKETZERO ZOHO CODE RUNS HERE
        # ===================================================================

        print("✅ TicketZero Zoho Edition is running with valid trial!\n")
        print("This is where your actual TicketZero workflow would execute:")
        print("  - Connect to Zoho Desk API")
        print("  - Fetch open tickets from widget")
        print("  - Analyze ticket with AI")
        print("  - Determine resolution action")
        print("  - Call Microsoft Graph API or Zoho Assist")
        print("  - Update ticket in Zoho Desk\n")


# Widget integration helper
def check_trial_for_widget():
    """
    Helper function for Zoho Desk widget integration
    Returns trial status for display in widget UI

    Returns:
        dict: Trial status information
    """
    guard = TrialGuard("TicketZero AI - Zoho Edition")
    return guard.get_status()


def widget_can_run():
    """
    Quick check if widget can run (for button enable/disable)

    Returns:
        bool: True if trial valid
    """
    guard = TrialGuard("TicketZero AI - Zoho Edition")
    return guard.is_valid()


# Main entry point
def main():
    """Main entry point with trial protection"""
    app = TicketZeroZohoWithTrial()

    if not app.check_license():
        print("\n❌ Cannot start TicketZero - trial not valid")
        print(f"\n📧 To purchase a license, email: jgreenia@jandraisolutions.com")
        print(f"   Subject: TicketZero Zoho Edition - License Purchase\n")
        sys.exit(1)

    # Show trial reminder if needed
    app.show_trial_banner()

    # Run the app
    app.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  TicketZero interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        sys.exit(1)
