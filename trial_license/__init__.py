"""
TicketZero Trial License System

A secure, local-only trial licensing system that:
- Binds trials to specific hardware
- Stores encrypted trial data
- Prevents common bypass attempts
- No hosting or external dependencies required

Usage:
    from trial_license import TrialGuard

    # Initialize
    guard = TrialGuard()

    # Check trial status
    if guard.require_valid_trial():
        # Run your app
        print("Trial is valid!")
    else:
        # Show trial expired message
        guard.show_trial_message()
"""

__version__ = "1.0.0"
__author__ = "Turtles AI Lab"

from .trial_guard import TrialGuard
from .trial_manager import TrialManager, check_trial, is_valid

__all__ = ['TrialGuard', 'TrialManager', 'check_trial', 'is_valid']
