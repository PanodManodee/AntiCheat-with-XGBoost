# net/rpc/__init__.py
"""RPC parsing registry."""
from net.rpc.base import RPCRegistry

RPCRegistry.register_all([])

# Public API — callers use RPCRegistry.parse(rpc_name, reader)
RPC = RPCRegistry
