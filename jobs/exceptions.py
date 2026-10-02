"""Operator-safe discovery failures shared by the Nautobot boundaries."""


class InventoryError(ValueError):
    """The inventory cannot accept the proposed changes."""
