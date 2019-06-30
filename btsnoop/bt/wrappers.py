"""
This module contains a number of data classes that are intended to
make unpacking snooped packet information easy and portable.
"""

from dataclasses import dataclass
from bitstring import BitStream, BitArray

from . import hci
from . import hci_cmd
# from . import hci_evt
from . import l2cap
from . import att
from . import smp


"""
--------------------------------------------------------------------------------
                             HCI Command Packets
--------------------------------------------------------------------------------
"""

@dataclass
class CommandCreateConnection:
    addr: str # 6
    pkt_type: str
    mode: str
    reserved: str
    clk_offset: str
    allow_role_switch: str
    rawbytes: str

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class CommandDisconnect:
    hdl: bytes # 2
    reason: bytes #1
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 3)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.reason = hci.ERROR_CODES[self.reason]
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class CommandAcceptConnectionRequest:
    addr: str # 6
    role: str
    rawbytes: str

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class CommandLESetRandomAddress:
    addr: str # 6
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 6)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes)

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
        self.rawbytes = hci.b2h(self.rawbytes)

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
        self.rawbytes = hci.b2h(self.rawbytes)


@dataclass
class CommandSwitchRole:
    addr: str
    role: str
    rawbytes: str

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.role = self.role2str()
        self.rawbytes = hci.b2h(self.rawbytes)

    def role2str(self):
        code = f' ({hci.i2h(self.role)})'
        if self.role == 0x00:
            return f'Change Own Role to Master{code}'
        elif self.role == 0x01:
            return f'Change Own Role to Slave{code}'
        else:
            return f'Unknown Role Change{code}'


"""
--------------------------------------------------------------------------------
                               HCI Event Packets
--------------------------------------------------------------------------------
"""

@dataclass
class EventConnectionComplete:
    """
    """
    status: str
    hdl: str
    addr: str
    lt: str
    enc_enabled: bool
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 11)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.lt = hci.i2h(self.lt)
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class EventConnectionRequest:
    """
    """
    addr: str
    cod: str
    lt: str
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) == 10)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.cod = hci.pkt_bytes_to_cod(self.cod)
        self.lt = hci.i2h(self.lt)
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class EventDisconnectionComplete:
    """
    """
    status: str
    hdl: str
    reason: str
    rawbytes: str

    def __post_init__(self):
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.reason = hci.ERROR_CODES[self.reason]
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class EventCommandComplete:
    rescode: str
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) > 2)
        self.rescode = hci.pkt_bytes_to_hci_opcode(self.rescode)
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class EventCommandStatus:
    status: str
    num_cmd_pkts: str
    opcode: str
    rawbytes: str

    def __post_init__(self):
        assert(len(self.rawbytes) > 2)
        self.status = hci.i2h(self.status, nbytes=1)
        self.num_cmd_pkts = hci.i2h(self.num_cmd_pkts, nbytes=1)
        self.opcode = hci.pkt_bytes_to_hci_opcode(self.opcode).lower()
        opcode_str = hci_cmd.HCI_COMMANDS[hci.h2i(self.opcode)]
        self.opcode = f'{opcode_str} ({self.opcode})'
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class EventRoleChange:
    status: str
    addr: str
    role: str
    rawbytes: str

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.role = self.role2str()
        self.rawbytes = hci.b2h(self.rawbytes)

    def role2str(self):
        code = f' ({hci.i2h(self.role)})'
        if self.role == 0x00:
            return f'New Role: Master{code}'
        elif self.role == 0x01:
            return f'New Role: Slave{code}'
        else:
            return f'Unknown Role Change{code}'


@dataclass
class EventLogicalLinkComplete:
    status: str
    llhdl: str # logical link handle
    plhdl: str # physical link handle
    txflowID: str
    rawbytes: str

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.llhdl = hci.pkt_bytes_to_conn_hdl(self.llhdl)
        self.rawbytes = hci.b2h(self.rawbytes)

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
        self.addr_type_str = self.addrtype2str()
        self.role_str = self.role2str()
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.role = hci.i2h(self.role)
        self.addr_type = hci.i2h(self.addr_type)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.conn_interval = hci.i2h(self.conn_interval)
        self.conn_latency = hci.i2h(self.conn_latency)
        # self.supervision_timeout = hci.i2h(self.supervision_timeout)
        self.master_clk_acc = hci.i2h(self.master_clk_acc)
        self.rawbytes = hci.b2h(self.rawbytes)

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
class EventLEEnhancedConnectionComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 944
    """
    status: bytes
    hdl: str
    role: bytes
    addr_type: bytes
    addr: str
    local_resolvable_addr: str
    peer_resolvable_addr: str
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
        self.local_resolvable_addr = hci.pkt_bytes_to_bdaddr(self.local_resolvable_addr)
        self.peer_resolvable_addr = hci.pkt_bytes_to_bdaddr(self.peer_resolvable_addr)
        self.addr_type_str = self.addrtype2str()
        self.role_str = self.role2str()
        self.rawbytes = hci.b2h(self.rawbytes)

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
        if self.role == 0x00:
            return f'Master' #f'Connection is master'
        elif self.role == 0x01:
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
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class EventLEDirectAdvertisingReport:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 948
    """
    num_reports: bytes
    evt_type: bytes
    addr_type: bytes
    addr: bytes
    dir_addr_type: bytes
    dir_addr: bytes
    rssi: int
    rawbytes: str

    def __post_init__(self):
        assert(self.num_reports == 1) # FIXME LATER: just checking - the controller can cache reports & send multiple at one time, but I haven't seen this in practice yet....
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.dir_addr = hci.pkt_bytes_to_bdaddr(self.dir_addr)
        self.rssi = hci.b2si(self.rssi) # convert signed-integer to correct value
        self.rawbytes = hci.b2h(self.rawbytes)

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
        assert(len(self.rawbytes) == 9)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.b2h(self.rawbytes)

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
        self.rawbytes = hci.b2h(self.rawbytes)
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
    scid: str # 2

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.psm = hci.pkt_bytes_to_l2cap_psm(self.psm)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)

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
    scid: str # 2
    ctrlid: str

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.psm = hci.pkt_bytes_to_l2cap_psm(self.psm)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)
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

"""
--------------------------------------------------------------------------------
                          ATT/SMP/SCH Packets
--------------------------------------------------------------------------------
"""

@dataclass
class ATT:
    opcode: str
    hndl: str
    payload: str
    data: str
    opcodestr: str = None

    def __post_init__(self):
        self.opcodestr = att.opcode_to_str(self.opcode, verbose=True)

@dataclass
class SMP:
    code: str
    data: str
    codestr: str = None

    def __post_init__(self):
        self.codestr = smp.code_to_str(self.code, verbose=True)

@dataclass
class SCH:
    code: str
    id: str
    len: str
    data: str
    codestr: str = None
    l2cap_sch_evt: str = None

    def __post_init__(self):
        self.codestr = l2cap.sch_code_to_str(self.code, verbose=True)
        self.l2cap_sch_evt = l2cap.parse_sch_data(self.code, self.id, self.data)
