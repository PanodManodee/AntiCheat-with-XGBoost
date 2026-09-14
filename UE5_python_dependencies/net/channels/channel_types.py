# net/channels/channel_types.py
from enum import IntEnum


class EChannelType(IntEnum):
    CHTYPE_None = 0
    CHTYPE_Control = 1
    CHTYPE_Actor = 2
    CHTYPE_File = 3
    CHTYPE_Voice = 4
    CHTYPE_BattlEye = 5
    CHTYPE_MAX = 8


class EChannelCloseReason(IntEnum):
    Destroyed = 0
    Dormancy = 1
    LevelUnloaded = 2
    Relevancy = 3
    TearOff = 4
    MAX = 15
