"""Errors whose message is written for the person using the app."""
from __future__ import annotations


class UserError(ValueError):
    """A ValueError raised by the app with a message that is safe to show as-is.

    Routes answer with ``user_message`` for these only; any other ValueError (one from a
    library, say) is logged and answered generically, so its text never reaches a client.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.user_message = message
