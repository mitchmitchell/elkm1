# elkm1/elke27_lib/provisioning.py

"""
E27 Provisioning Coordinator (Phase 2)

Implements responsibilities defined in:
- DDR-0023: Provisioning Flow and Home Assistant Credential Exchange

This module:
- Holds credentials in memory temporarily
- Never persists credentials
- Allows Session to request provisioning via callbacks
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Callable


@dataclass
class Credentials:
    access_code: str
    pass_phrase: str


class ProvisioningManager:
    def __init__(self) -> None:
        self._creds: Optional[Credentials] = None

        # Caller (Home Assistant adapter or CLI) can hook this:
        self.on_credentials_required: Optional[Callable[[str], None]] = None

    def request_credentials(self, reason: str) -> None:
        """
        Signal that credentials are required.
        Home Assistant or CLI should respond by calling supply_credentials().
        """
        if self.on_credentials_required:
            self.on_credentials_required(reason)

    def supply_credentials(self, access_code: str, pass_phrase: str) -> None:
        self._creds = Credentials(access_code=access_code, pass_phrase=pass_phrase)

    def clear_credentials(self) -> None:
        self._creds = None

    def get_credentials(self) -> Optional[Tuple[str, str]]:
        if self._creds is None:
            return None
        return self._creds.access_code, self._creds.pass_phrase
