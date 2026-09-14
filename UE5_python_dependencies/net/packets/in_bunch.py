# net/packets/in_bunch.py
"""FInBunch - Incoming bunch."""
from __future__ import annotations
from serialization.bit_reader import FBitReader
from net.channels.channel_types import EChannelCloseReason, EChannelType
from core.names.ename import EName


class FInBunch(FBitReader):
    __slots__ = (
        'ChIndex', 'ChSequence', 'ChNameIndex', 'PacketId',
        'bOpen', 'bClose', 'bIsReplicationPaused', 'bReliable',
        'bPartial', 'bPartialInitial', 'bPartialFinal',
        'bPartialCustomExportsFinal', 'bHasPackageMapExports',
        'bHasMustBeMappedGUIDs', 'bDormant',
        'ChName', 'ChType', 'CloseReason',
        'ExportNetGUIDs', 'NetFieldExports',
    )

    def __init__(self, data: bytes = b"", bunch: FInBunch = None, copy_buffer: bool = True):
        if bunch is not None:
            if copy_buffer:
                super().__init__(bunch.get_buffer(), bunch.num_bits)
            else:
                super().__init__(b"", 0)

            self.ChIndex = bunch.ChIndex
            self.ChSequence = bunch.ChSequence
            self.ChNameIndex = bunch.ChNameIndex
            self.PacketId = bunch.PacketId

            self.bOpen = bunch.bOpen
            self.bClose = bunch.bClose
            self.bIsReplicationPaused = bunch.bIsReplicationPaused
            self.bReliable = bunch.bReliable
            self.bPartial = bunch.bPartial
            self.bPartialInitial = bunch.bPartialInitial
            self.bPartialFinal = bunch.bPartialFinal
            self.bPartialCustomExportsFinal = bunch.bPartialCustomExportsFinal
            self.bHasPackageMapExports = bunch.bHasPackageMapExports
            self.bHasMustBeMappedGUIDs = bunch.bHasMustBeMappedGUIDs
            self.bDormant = bunch.bDormant

            self.ChName = bunch.ChName
            self.ChType = bunch.ChType
            self.CloseReason = bunch.CloseReason

            self.ExportNetGUIDs = list(bunch.ExportNetGUIDs)
            self.NetFieldExports = list(bunch.NetFieldExports)
        else:
            super().__init__(data)

            self.ChIndex: int = 0
            self.ChSequence: int = 0
            self.ChNameIndex: int = 0
            self.PacketId: int = 0

            self.bOpen: bool = False
            self.bClose: bool = False
            self.bIsReplicationPaused: bool = False
            self.bReliable: bool = False
            self.bPartial: bool = False
            self.bPartialInitial: bool = False
            self.bPartialFinal: bool = False
            self.bPartialCustomExportsFinal: bool = False
            self.bHasPackageMapExports: bool = False
            self.bHasMustBeMappedGUIDs: bool = False
            self.bDormant: bool = False

            self.ChName: EName = EName.None_
            self.ChType: EChannelType = EChannelType.CHTYPE_None
            self.CloseReason: EChannelCloseReason = EChannelCloseReason.Destroyed

            self.ExportNetGUIDs: list = []
            self.NetFieldExports: list = []

    def set_data(self, data: bytes, num_bits: int) -> None:
        super().__init__(data, num_bits)
