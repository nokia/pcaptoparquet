# $Id: rtcp.py 23 2023-01-22 11:22:33Z pajarom $
# -*- coding: utf-8 -*-
# RFC3550 and RFC3611
"""RTP Control Protocol."""
import math
from typing import Any, Optional

import dpkt

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    RC   |   PT=SR=200   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         SSRC of sender                        |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# sender |              NTP timestamp, most significant word             |
# info   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |             NTP timestamp, least significant word             |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         RTP timestamp                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                     sender's packet count                     |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      sender's octet count                     |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_1 (SSRC of first source)                 |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   1    | fraction lost |       cumulative number of packets lost       |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |           extended highest sequence number received           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      interarrival jitter                      |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         last SR (LSR)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   delay since last SR (DLSR)                  |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_2 (SSRC of second source)                |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   2    :                               ...                             :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#        |                  profile-specific extensions                  |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class SRInfo(dpkt.Packet):  # type: ignore
    """RTCP Sender Info"""

    __hdr__ = (
        ("ssrc", "I", 0),
        ("ntp_ts_msw", "I", 0),
        ("ntp_ts_lsw", "I", 0),
        ("rtp_ts", "I", 0),
        ("pkts", "I", 0),
        ("octs", "I", 0),
    )

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the SRInfo object from a buffer.
        """
        dpkt.Packet.unpack(self, buf)
        self.data = b""


#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    RC   |   PT=RR=201   |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                     SSRC of packet sender                     |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_1 (SSRC of first source)                 |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   1    | fraction lost |       cumulative number of packets lost       |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |           extended highest sequence number received           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                      interarrival jitter                      |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                         last SR (LSR)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   delay since last SR (DLSR)                  |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# report |                 SSRC_2 (SSRC of second source)                |
# block  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   2    :                               ...                             :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
#        |                  profile-specific extensions                  |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class RRInfo(dpkt.Packet):  # type: ignore
    """RTCP Receiver Info"""

    __hdr__ = (("ssrc", "I", 0),)

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the RRInfo object from a buffer.
        """
        dpkt.Packet.unpack(self, buf)
        self.data = b""


class Report(dpkt.Packet):  # type: ignore
    """RTCP Report Sender"""

    __hdr__ = (
        ("ssrc", "I", 0),
        ("_lossfrac_losscumm", "I", 0),
        ("seq", "I", 0),
        ("jitter", "I", 0),
        ("lsr", "I", 0),
        ("dlsr", "I", 0),
    )
    __bit_fields__ = {
        "_lossfrac_losscumm": (
            ("lossfrac", 8),  # first byte
            ("losscumm", 24),  # lower 3 bytes
        ),
    }

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the Report object from a buffer.
        """
        dpkt.Packet.unpack(self, buf)
        self.data = b""

    def __bytes__(self) -> bytes:
        """
        Pack the Report object into a buffer.
        """
        return bytes(self.pack_hdr())


#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    SC   |  PT=SDES=202  |             length            |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# chunk  |                          SSRC/CSRC_1                          |
#   1    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SDES items                          |
#        |                              ...                              |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# chunk  |                          SSRC/CSRC_2                          |
#   2    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SDES items                          |
#        |                              ...                              |
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# header |V=2|P|    SC   |   PT=BYE=203  |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SSRC/CSRC                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        :                              ...                              :
#        +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
# (opt)  |     length    |               reason for leaving            ...
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#         0                   1                   2                   3
#         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# header +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |V=2|P| subtype |   PT=APP=204  |             length            |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                           SSRC/CSRC                           |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                          name (ASCII)                         |
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        |                   application-dependent data                ...
#        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |V=2|P|reserved |   PT=XR=207   |             length            |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                              SSRC                             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    :                         report blocks                         :
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

BT_LOSS = 1  # Loss RLE Report Block
BT_DUPL = 2  # Duplicate RLE Report Block
BT_RCVT = 3  # Packet Receipt Times Report Block
BT_RCVR = 4  # Receiver Reference Time Report Block
BT_DLRR = 5  # DLRR Report Block
BT_STAT = 6  # Statistics Summary Report Block
BT_VOIP = 7  # VoIP Metrics Report Block


class XBlockLoss(dpkt.Packet):  # type: ignore
    """RTCP Extended Loss RLE Report Block"""

    __hdr__ = (("ssrc", "I", 0),)
    # def unpack(self, buf):
    #     super(XBlockLoss, self).unpack(buf)
    #     self.data = buf[self.__hdr_len_:]


class XBlockDupl(dpkt.Packet):  # type: ignore
    """RTCP Extended Duplicate RLE Report Block"""

    __hdr__ = (("ssrc", "I", 0),)
    # def unpack(self, buf):
    #     super(XBlockDupl, self).unpack(buf)
    #     self.data = buf[self.__hdr_len_:]


class XBlockRcvt(dpkt.Packet):  # type: ignore
    """RTCP Extended Packet Receipt Times Report Block"""

    __hdr__ = (("ssrc", "I", 0),)
    # def unpack(self, buf):
    #     super(XBlockRcvt, self).unpack(buf)
    #     self.data = buf[self.__hdr_len_:]


class XBlockRcvr(dpkt.Packet):  # type: ignore
    """RTCP Extended Receiver Reference Time Report Block"""

    __hdr__ = (("ntp_ts_msw", "I", 0), ("ntp_ts_lsw", "I", 0))


class XBlockDlrr(dpkt.Packet):  # type: ignore
    """RTCP Extended DLRR Report Block"""

    __hdr__ = ()

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the XBlockDlrr object from a buffer.
        """
        self.data = buf


class XBlockStat(dpkt.Packet):  # type: ignore
    """RTCP Extended Statistics Summary Report Block"""

    __hdr__ = (
        ("ssrc", "I", 0),
        ("beg_seq", "H", 0),
        ("end_seq", "H", 0),
        ("loss", "I", 0),
        ("dupl", "I", 0),
        ("min_jitter", "I", 0),
        ("max_jitter", "I", 0),
        ("avg_jitter", "I", 0),
        ("dev_jitter", "I", 0),
        ("min_ttl_or_hl", "B", 0),
        ("max_ttl_or_hl", "B", 0),
        ("mean_ttl_or_hl", "B", 0),
        ("dev_ttl_or_hl", "B", 0),
    )


class XBlockVoip(dpkt.Packet):  # type: ignore
    """RTCP Extended Info"""

    __hdr__ = (
        ("ssrc", "I", 0),
        ("loss_rate", "B", 0),
        ("disc_rate", "B", 0),
        ("burst_density", "B", 0),
        ("gap_density", "B", 0),
        ("burst_duration", "H", 0),
        ("gap_duration", "H", 0),
        ("rtt", "H", 0),
        ("end_sys_delay", "H", 0),
        ("signal_level", "B", 0),
        ("noise_level", "B", 0),
        ("RERL", "B", 0),
        ("Gmin", "B", 0),
        ("RFactor", "B", 0),
        ("ext_RFactor", "B", 0),
        ("MOS_LQ", "B", 0),
        ("MOS_CQ", "B", 0),
        ("RX_config", "B", 0),
        ("reserved", "B", 0),
        ("nominal_jitter", "H", 0),
        ("max_jitter", "H", 0),
        ("abs_max_jitter", "H", 0),
    )


class XReportBlock(dpkt.Packet):  # type: ignore
    """RTCP Extended VoIP Metrics Report Block"""

    __hdr__ = (("type", "B", 0), ("spec", "B", 0), ("len", "H", 0))

    def set_block(self, block: Any) -> None:
        """
        Set the block object.
        """
        setattr(self, "block", block)
        if isinstance(block, XBlockLoss):
            setattr(self, "type", BT_LOSS)
        elif isinstance(block, XBlockDupl):
            setattr(self, "type", BT_DUPL)
        elif isinstance(block, XBlockRcvt):
            setattr(self, "type", BT_RCVT)
        elif isinstance(block, XBlockRcvr):
            setattr(self, "type", BT_RCVR)
        elif isinstance(block, XBlockDlrr):
            setattr(self, "type", BT_DLRR)
        elif isinstance(block, XBlockStat):
            setattr(self, "type", BT_STAT)
        elif isinstance(block, XBlockVoip):
            setattr(self, "type", BT_VOIP)
        else:
            raise ValueError("Invalid Block Type.")

        hdr_len = getattr(block, "__hdr_len__")
        data_len = len(getattr(block, "data"))
        setattr(self, "len", math.ceil((hdr_len + data_len) / 4))

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the XReportBlock object from a buffer.
        """
        super().unpack(buf)
        self.block = None
        buf = getattr(self, "data")
        self_type = getattr(self, "type")
        self_len = getattr(self, "len")
        if self_type == BT_LOSS:
            setattr(self, "block", XBlockLoss(buf[0 : self_len * 4]))
        elif self_type == BT_DUPL:
            setattr(self, "block", XBlockDupl(buf[0 : self_len * 4]))
        elif self_type == BT_RCVT:
            setattr(self, "block", XBlockRcvt(buf[0 : self_len * 4]))
        elif self_type == BT_RCVR:
            setattr(self, "block", XBlockRcvr(buf[0 : self_len * 4]))
        elif self_type == BT_DLRR:
            setattr(self, "block", XBlockDlrr(buf[0 : self_len * 4]))
        elif self_type == BT_STAT:
            setattr(self, "block", XBlockStat(buf[0 : self_len * 4]))
        elif self_type == BT_VOIP:
            setattr(self, "block", XBlockVoip(buf[0 : self_len * 4]))
        else:
            raise dpkt.UnpackError("Invalid Block Type.")
        self.data = b""


class XReport(dpkt.Packet):  # type: ignore
    """RTCP Extended Info"""

    __hdr__ = ()

    def __init__(self, *args, **kwargs) -> None:  # type: ignore
        """
        Initialize the XReport object.
        """
        setattr(self, "blocks", [])
        super().__init__(*args, **kwargs)

    def add_block(self, block: Any) -> None:
        """
        Add a block to the XReport object.
        """
        getattr(self, "blocks").append(block)

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the XReport object from a buffer.
        """
        super().unpack(buf)
        buf = getattr(self, "data")
        self.data = b""
        try:
            ll = 0
            while ll < len(buf):
                blck = XReportBlock(buf[ll:])
                ll = ll + getattr(blck, "__hdr_len__") + getattr(blck, "len") * 4
                getattr(self, "blocks").append(blck)
        except dpkt.UnpackError:
            pass

        if len(getattr(self, "blocks")) == 0:  # At least one block must be present...
            raise dpkt.UnpackError("Invalid Block Type.")

    def __len__(self) -> int:
        """
        Get the length of the XReport object.
        """
        ll = 0
        blocks = getattr(self, "blocks")
        numblk = len(blocks)
        for i in range(numblk):
            block = blocks[i]
            ll = ll + getattr(block, "__hdr_len__") + getattr(block, "len") * 4
        return ll

    def __bytes__(self) -> bytes:
        """
        Pack the XReport object into a buffer.
        """
        bb = b""  # No data at this level by default
        blocks = getattr(self, "blocks")
        numblk = len(blocks)
        for i in range(numblk):
            block = blocks[i]
            bb = (
                bb
                + block.pack_hdr()
                + getattr(block, "block").pack_hdr()
                + getattr(block, "block").data
            )
        return bb


VERSION = 2

PT_SR = 200
PT_RR = 201
PT_SDES = 202
PT_BYE = 203
PT_APP = 204
PT_XR = 207

# START TODO...
SDES_CNAME = 1
SDES_NAME = 2
SDES_EMAIL = 3
SDES_PHONE = 4
SDES_LOC = 5
SDES_TOOL = 6
SDES_NOTE = 7
SDES_PRIV = 8
# END TODO...


class RTCP(dpkt.Packet):  # type: ignore
    """Real-Time Transport Protocol.

    TODO: Longer class information....

    Attributes:
        __hdr__: Header fields of RTCP.
        TODO.
    """

    __hdr__ = (("_version_p_cc_pt", "H", 0x8000), ("len", "H", 0))

    __bit_fields__ = {
        "_version_p_cc_pt": (
            ("version", 2),  # version 1100 0000 0000 0000 ! 0xC000  14
            ("p", 1),  # p       0010 0000 0000 0000 ! 0x2000  13
            ("cc", 5),  # cc      0001 1111 0000 0000 ! 0x1F00   8
            ("pt", 8),  # pt      0000 0000 1111 1111 ! 0x00FF   0
        ),
    }

    def add_info(self, info: Any) -> None:
        """
        Add info to the RTCP object.
        """
        if not getattr(self, "pt") in (PT_SR, PT_RR, PT_XR):
            raise ValueError("Info property not supported.")
        self.info = info
        ll = (
            getattr(self, "__hdr_len__")
            + getattr(info, "__hdr_len__")
            + len(getattr(self, "data"))
        )

        # Only valid for PT_SR and PT_RR
        if len(getattr(self, "reports")) > 0:
            if getattr(self, "pt") in (PT_SR, PT_RR):
                ll = ll + 24 * getattr(self, "cc")
            else:
                ll = ll + len(getattr(self, "reports")[0])

        setattr(self, "len", math.ceil((ll - 4) / 4))

    def add_report(self, report: Any) -> None:
        """
        Add a report to the RTCP object.
        """
        if not getattr(self, "pt") in (PT_SR, PT_RR, PT_XR):
            raise ValueError("Report property not supported.")
        getattr(self, "reports").append(report)
        setattr(self, "cc", len(getattr(self, "reports")))
        ll = getattr(self, "__hdr_len__") + len(getattr(self, "data"))
        info = getattr(self, "info")
        if info:
            ll = ll + getattr(info, "__hdr_len__")
        # Only valid for PT_SR and PT_RR
        if getattr(self, "pt") in (PT_SR, PT_RR):
            ll = ll + 24 * getattr(self, "cc")
        else:
            ll = ll + len(getattr(self, "reports")[0])
        setattr(self, "len", math.ceil((ll - 4) / 4))

    def add_data(self, data: bytes) -> None:
        """
        Add data to the RTCP object.
        """
        if getattr(self, "pt") in (PT_RR, PT_XR):
            raise ValueError("Data property not supported.")
        setattr(self, "data", data)
        ll = getattr(self, "__hdr_len__") + len(data)
        info = getattr(self, "info")
        if info:
            ll = ll + getattr(info, "__hdr_len__")
        if getattr(self, "pt") in (PT_SR, PT_RR):
            # Only valid for PT_SR and PT_RR
            ll = ll + 24 * getattr(self, "cc")
        setattr(self, "len", math.ceil((ll - 4) / 4))

    def unpack(self, buf: bytes) -> None:
        """
        Unpack the RTCP object from a buffer.
        """
        super().unpack(buf)
        if not getattr(self, "version") == VERSION or not getattr(self, "p") == 0:
            raise dpkt.UnpackError(f"invalid {self.__class__.__name__}: {str(buf)}")
        # self.csrc = buf[getattr(self, "__hdr_len__"):getattr(self, "__hdr_len__") + 4]
        buf = getattr(self, "data")
        if getattr(self, "pt") == PT_SR:
            info = SRInfo(buf)
            setattr(self, "info", info)
            buf = buf[getattr(info, "__hdr_len__") :]
            for _ in range(getattr(self, "cc")):
                sr = Report(buf)
                buf = buf[getattr(sr, "__hdr_len__") :]
                getattr(self, "reports").append(sr)
            self.data = buf[
                0 : (
                    len(self)
                    - getattr(self, "__hdr_len__")
                    - getattr(info, "__hdr_len__")
                    - getattr(self, "cc") * 24
                )
            ]
        elif getattr(self, "pt") == PT_RR:
            info = RRInfo(buf)
            setattr(self, "info", info)
            buf = buf[getattr(info, "__hdr_len__") :]
            setattr(self, "reports", [])
            for _ in range(getattr(self, "cc")):
                rr = Report(buf)
                buf = buf[getattr(rr, "__hdr_len__") :]
                getattr(self, "reports").append(rr)
            self.data = b""
        elif getattr(self, "pt") == PT_SDES:
            # TODO
            self.data = buf[0 : len(self) - getattr(self, "__hdr_len__")]
        elif getattr(self, "pt") == PT_BYE:
            # TODO
            self.data = buf[0 : len(self) - getattr(self, "__hdr_len__")]
        elif getattr(self, "pt") == PT_APP:
            # TODO
            self.data = buf[0 : len(self) - getattr(self, "__hdr_len__")]
        elif getattr(self, "pt") == PT_XR:
            info = RRInfo(buf)  # Only cssr in info...
            setattr(self, "info", info)
            buf = buf[getattr(info, "__hdr_len__") :]
            # Limiting buffer length is important in this
            # case to determine the number of blocks.
            xr = XReport(buf[0 : len(self) - getattr(info, "__hdr_len__")])
            getattr(self, "reports").append(xr)
            self.data = b""
        else:
            raise dpkt.UnpackError(f"invalid {self.__class__.__name__}: {str(buf)}")

    def __init__(self, *args, **kwargs):  # type: ignore
        """
        Initialize the RTCP object.
        """
        self.info = None
        self.reports = []
        self.data = b""
        super().__init__(*args, **kwargs)

    def __len__(self) -> int:
        """
        Get the length of the RTCP object.
        """
        return int(getattr(self, "len")) * 4 + 4

    def __bytes__(self) -> bytes:
        """
        Pack the RTCP object into a buffer.
        """
        bb = self.pack_hdr()
        if self.info:
            bb = bb + self.info.pack_hdr()
        if len(self.reports) > 0:
            for _ in range(getattr(self, "cc")):
                bb = bb + bytes(self.reports[_])
        return bytes(bb + self.data)


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the RTP protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Try to decode the application layer as RTP.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        RTCP data dpkt object.
    """
    rtcp = None

    if not isinstance(transport, dpkt.udp.UDP):
        return None

    ll = 0

    while ll < len(app):
        try:
            rtcp = RTCP(app[ll:])  # type: ignore
        except dpkt.UnpackError:
            # do nothing...
            rtcp = None
            break

        if (
            getattr(rtcp, "version") == 2
            and getattr(rtcp, "p") == 0
            and getattr(rtcp, "pt")
            in (
                PT_SR,
                PT_RR,
                PT_SDES,
                PT_BYE,
                PT_APP,
                PT_XR,
            )
        ):
            setattr(packet, "app_type", "RTCP")
            if getattr(rtcp, "pt") == PT_SDES:
                setattr(packet, "app_session", str(rtcp.data))
            elif getattr(rtcp, "pt") == PT_SR:
                setattr(packet, "app_request", repr(rtcp))
            else:
                # For now to simplify
                # json convertion...
                setattr(packet, "app_response", repr(rtcp))
            ll = ll + len(rtcp)
        else:
            rtcp = None
            ll = len(app)

    if rtcp is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(getattr(rtcp, "data")) if rtcp else None
