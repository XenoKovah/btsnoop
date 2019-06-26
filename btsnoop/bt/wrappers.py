"""
This module contains a number of data classes that are intended to
make unpacking snooped packet information easy and portable.
"""

from . import hci

from dataclasses import dataclass
from bitstring import BitStream, BitArray

"""
--------------------------------------------------------------------------------
                             HCI Command Packets
--------------------------------------------------------------------------------
"""

@dataclass
class CommandDisconnect:
    hdl: bytes # 2
    reason: bytes #1
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 3)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.reason = hci.ERROR_CODES[self.reason]
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)

@dataclass
class CommandLESetRandomAddress:
    addr: str # 6
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 6)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)

@dataclass
class CommandLECreateConnection:
    scan_interval: bytes # 2
    scan_window: bytes # 2
    init_filter_policy: bytes # 1
    peer_addr_type: bytes # 1
    peer_addr: bytes # 6
    own_addr_type: bytes # 1
    conn_interval_min: bytes # 2
    conn_interval_max: bytes # 2
    conn_latency: bytes # 2
    supervision_timeout: bytes # 2
    min_ce_len: bytes # 2
    max_ce_len: bytes # 2
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 25)
        self.peer_addr_type = self.peeraddrtype2str()
        self.peer_addr = hci.pkt_bytes_to_bdaddr(self.peer_addr)
        self.own_addr_type = self.ownaddrtype2str()
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)

    def peeraddrtype2str(self):
        code = f' ({hci.i2h(self.peer_addr_type)})'
        if self.peer_addr_type == 0x00:
            return f'Public{code}'
        elif self.peer_addr_type == 0x01:
            return f'Random{code}'
        elif self.peer_addr_type == 0x02:
            return f'Public Identity Address (Resolvable){code}'
        elif self.peer_addr_type == 0x03:
            return f'Random (Static) Identity Address (Resolvable){code}'
        else:
            return f'Reserved for future use'

    def ownaddrtype2str(self):
        code = f' ({hci.i2h(self.own_addr_type)})'
        if self.own_addr_type == 0x00:
            return f'Public{code}'
        elif self.own_addr_type == 0x01:
            return f'Random{code}'
        elif self.own_addr_type == 0x02:
            return f'Controller-Generated Resolvable Address (Based on local IRK; default: use Public Addr){code}'
        elif self.own_addr_type == 0x03:
            return f'Controller-Generated Resolvable Address (Based on local IRK; default: use Random Addr){code}'
        else:
            return f'Reserved for future use'

@dataclass
class CommandLEConnectionUpdate:
    hdl: bytes # 2
    conn_interval_min: bytes # 2
    conn_interval_max: bytes # 2
    conn_latency: bytes # 2
    supervision_timeout: bytes # 2
    min_ce_len: bytes # 2
    max_ce_len: bytes # 2
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 14)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)


"""
--------------------------------------------------------------------------------
                               HCI Event Packets
--------------------------------------------------------------------------------
"""


@dataclass
class EventLEConnectionComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 929
    """
    status: bytes
    hdl: str
    role: bytes
    addr_type: bytes
    addr: str
    conn_interval: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    master_clk_acc: bytes
    rawbytes: str
    addr_type_str: str = ''
    role_str: str = ''

    def __post_init__(self):
        assert(len(self.rawbytes) == 18)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.addr_type_str = self.addrtype2str()
        self.role_str = self.role2str()
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)

    def addrtype2str(self):
        """
        BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 930
        """
        if self.addr_type == 0x00:
            return f'Public' #f'Peer is using a Public Device Address'
        elif self.addr_type == 0x01:
            return r'Random' #f'Peer is using a Random Device Address'
        else:
            return f'Reserved for future use'

    def role2str(self):
        """
        BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 930
        """
        if self.addr_type == 0x00:
            return f'Master' #f'Connection is master'
        elif self.addr_type == 0x01:
            return r'Slave' #f'Connection is slave'
        else:
            return f'Reserved for future use'

@dataclass
class EventLEAdvertisingReport:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 932
    """
    num_reports: bytes
    evt_type: bytes
    addr_type: bytes
    addr: str # initially bytes, but shortly converted to str
    adv_dlen: bytes
    adv_data: bytes
    rssi: int
    rawbytes: str

    def __post_init__(self):
        assert(self.num_reports == 1) # FIXME LATER: just checking - the controller can cache reports & send multiple at one time, but I haven't seen this in practice yet....
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rssi = hci.b2si(self.rssi) # convert signed-integer to correct value
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)

@dataclass
class EventLEConnectionUpdateComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 934
    """
    status: bytes
    hdl: str
    conn_interval: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 8)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)

@dataclass
class EventLEReadRemoteUsedFeaturesComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 936
    """
    status: bytes
    hdl: str
    le_features: bytes
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 11)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.bytes2hexstr(self.rawbytes)
        # Also show LE Features as a bit string
        a = BitArray(bytes=self.le_features)
        self.le_features = a.bin[0:8] # bits 8-64 are RFU


"""
--------------------------------------------------------------------------------
                                 L2CAP Packets
--------------------------------------------------------------------------------
"""


@dataclass
class L2CAPConnectionRequest:
    code: str # 1
    id: str # 1
    psm: str # 2
    cid: str # 2

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.psm = hci.pkt_bytes_to_l2cap_psm(self.psm)
        self.cid = hci.pkt_bytes_to_l2cap_cid(self.cid)

@dataclass
class L2CAPConnectionResponse:
    code: str # 1
    id: str # 1
    dcid: str # 2
    scid: str # 2
    result: str # 2
    status: str # 2

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)
        self.result = hci.i2h(self.result, nbytes=2)
        self.status = hci.i2h(self.status, nbytes=2)

@dataclass
class L2CAPDisconnectionRequest:
    code: str # 1
    id: str # 1
    dcid: str # 2
    scid: str # 2

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)

@dataclass
class L2CAPDisconnectionResponse:
    code: str # 1
    id: str # 1
    dcid: str # 2
    scid: str # 2

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)

@dataclass
class L2CAPCreateChannelRequest:
    code: str # 1
    id: str # 1
    psm: str # 2
    cid: str # 2
    ctrlid: str

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.psm = hci.pkt_bytes_to_l2cap_psm(self.psm)
        self.cid = hci.pkt_bytes_to_l2cap_cid(self.cid)
        self.ctrlid = hci.i2h(self.ctrlid)

@dataclass
class L2CAPCreateChannelResponse:
    code: str # 1
    id: str # 1
    dcid: str # 2
    scid: str # 2
    result: str # 2
    status: str # 2

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)
        self.result = hci.i2h(self.result, nbytes=2)
        self.status = hci.i2h(self.status, nbytes=2)
