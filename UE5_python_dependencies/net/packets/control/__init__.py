# net/packets/control/__init__.py
from __future__ import annotations
from enum import IntEnum


class NetControlMessageType(IntEnum):
    Hello = 0
    Welcome = 1
    Upgrade = 2
    Challenge = 3
    Netspeed = 4
    Login = 5
    Failure = 6
    Join = 9
    JoinSplit = 10
    Skip = 12
    Abort = 13
    PCSwap = 15
    ActorChannelFailure = 16
    DebugText = 17
    NetGUIDAssign = 18
    SecurityViolation = 19
    GameSpecific = 20
    EncryptionAck = 21
    DestructionInfo = 22
    CloseReason = 23
    NetPing = 24
    BeaconWelcome = 25
    BeaconJoin = 26
    BeaconAssignGUID = 27
    BeaconNetGUIDAck = 28
    IrisProtocolMismatch = 29
    IrisNetRefHandleError = 30
    JoinNoPawn = 31
    JoinNoPawnSplit = 32
    CloseChildConnection = 34


_nmt_modules_loaded = False

def _load_nmt_modules():
    global _nmt_modules_loaded
    if _nmt_modules_loaded:
        return
    from net.packets.control.hello import Hello
    from net.packets.control.login import Login
    from net.packets.control.welcome import Welcome
    from net.packets.control.join import Join
    from net.packets.control.netspeed import Netspeed
    from net.packets.control.failure import Failure
    from net.packets.control.closereason import CloseReason

    NMT.Hello = Hello
    NMT.Login = Login
    NMT.Welcome = Welcome
    NMT.Join = Join
    NMT.Netspeed = Netspeed
    NMT.Failure = Failure
    NMT.CloseReason = CloseReason
    _nmt_modules_loaded = True


class _NMTMeta(type):
    def __getattr__(cls, name):
        _load_nmt_modules()
        try:
            return type.__getattribute__(cls, name)
        except AttributeError:
            raise AttributeError(f"'{cls.__name__}' has no attribute '{name}'")


class NMT(metaclass=_NMTMeta):
    pass