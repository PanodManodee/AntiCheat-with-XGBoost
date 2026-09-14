# net/replication/custom_delta/__init__.py
"""Custom delta property parsing registry."""
from net.replication.custom_delta.base import CustomDeltaRegistry

# from net.replication.custom_delta.inventory import DELTA_HANDLERS as _inventory
# CustomDeltaRegistry.register_all(_inventory)

# Public API — callers use CustomDeltaRegistry.receive(field_name, reader)
CustomDelta = CustomDeltaRegistry