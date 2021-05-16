"""
This module contains a number of data classes that are intended to
make unpacking snooped packet information easy and portable.
"""

from dataclasses import dataclass
from bitstring import BitStream, BitArray
import copy
import struct

from . import hci
from . import hci_cmd
# from . import hci_evt
from . import l2cap
from . import att
from . import smp

"""
--------------------------------------------------------------------------------
                                  Helpers
--------------------------------------------------------------------------------
"""

def addrtype2str(type_):
    code = f' ({hci.i2h(type_)})'
    if type_ == 0x00:
        return f'Public{code}'
    elif type_ == 0x01:
        return f'Random{code}'
    elif type_ == 0x02:
        return f'Resolvable{code}'
    elif type_ == 0x03:
        return f'Resolvable (Rand. Default){code}'
    else:
        return f'Reserved for future use{code}'

def role2str(role):
    """
    E.g., See: BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 930
    """
    code = f' ({hci.i2h(role)})'
    if role == 0x00:
        return f'Master{code}'
    elif role == 0x01:
        return f'Slave{code}'
    else:
        return f'Unknown Role {code}'

"""
--------------------------------------------------------------------------------
                             HCI Command Packets
--------------------------------------------------------------------------------
"""

@dataclass
class CommandCreateConnection:
    addr: bytes
    pkt_type: bytes
    mode: bytes
    reserved: bytes
    clk_offset: bytes
    allow_role_switch: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.pkt_type = hci.b2h(self.pkt_type).lower()
        self.mode = hci.i2h(self.mode).lower()
        self.clk_offset = hci.b2h(self.clk_offset).lower()
        self.allow_role_switch = hci.i2h(self.allow_role_switch).lower()
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandDisconnect:
    hdl: bytes
    reason: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 3)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.reason = hci.ERROR_CODES[self.reason]
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandAcceptConnectionRequest:
    addr: bytes
    role: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandSwitchRole:
    addr: bytes
    role: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.role = role2str(self.role)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandRejectConnectionRequest:
    pass

@dataclass
class CommandLESetRandomAddress:
    addr: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 6)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLECreateConnection:
    scan_interval: bytes
    scan_window: bytes
    init_filter_policy: bytes
    peer_addr_type: bytes
    peer_addr: bytes
    own_addr_type: bytes
    conn_interval_min: bytes
    conn_interval_max: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    min_ce_len: bytes
    max_ce_len: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 25)
        self.peer_addr_type = addrtype2str(self.peer_addr_type)
        self.peer_addr = hci.pkt_bytes_to_bdaddr(self.peer_addr)
        self.own_addr_type = addrtype2str(self.own_addr_type)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLECreateConnectionCancel:
    rawbytes: bytes

    def __post_init__(self):
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLEConnectionUpdate:
    hdl: bytes
    conn_interval_min: bytes
    conn_interval_max: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    min_ce_len: bytes
    max_ce_len: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 14)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandInquiry:
    lap: bytes
    inquiry_len: bytes
    num_responses: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.lap = hci.b2h(self.lap).lower()
        self.inquiry_len = hci.i2h(self.inquiry_len).lower()
        self.num_responses = hci.i2h(self.num_responses).lower()
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandReadRemoteVersionInformation:
    hdl: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandSetEventFilter:
    filter_type: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.filter_type = hci.i2h(self.filter_type).lower()
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLinkKeyRequestReply:
    addr: bytes
    link_key: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.link_key = hci.b2h(self.link_key).lower()
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandDeleteStoredLinkKey:
    addr: bytes
    delete_all_flag: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.delete_all_flag = hci.i2h(self.delete_all_flag).lower()
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLESetScanParameters:
    scan_type: bytes
    scan_interval: bytes
    scan_window: bytes
    own_addr_type: bytes
    filter_policy: bytes
    rawbytes: bytes
    def __post_init__(self):
        hex_scan_type = hci.i2h(self.scan_type).lower()
        self.scan_type = f'Passive Scan ({hex_scan_type})' if self.scan_type == 0x00 else f'Active Scan ({hex_scan_type})'
        self.scan_interval = hci.b2h(self.scan_interval).lower()
        self.scan_window = hci.b2h(self.scan_window).lower()
        self.own_addr_type = addrtype2str(self.own_addr_type)
        if  self.filter_policy == 0x00:
            self.filter_policy = 'Accept All (0x00)' # except directed adv. pkts not addressed to this device
        elif self.filter_policy == 0x01:
            self.filter_policy = 'Accept Only (0x01)' # white-listed devices
        elif self.filter_policy == 0x02:
            self.filter_policy = 'Accept All (0x02)' # undirected adv. pkts; directed adv. pkts where initiator addr is a resolvable private address; directed adv. pkts to this device.
        elif self.filter_policy == 0x03:
            self.filter_policy = 'Accept All (0x03)' # adv. addr in white-list; directed adv. pkts where initiator addr is a resolvable private address; directed adv. pkts to this device.
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLESetScanEnable:
    enable: bytes
    filter_duplicates: bytes
    rawbytes: bytes
    def __post_init__(self):
        hex_enable = hci.i2h(self.enable).lower()
        self.enable = f'Scan Disabled ({hex_enable})' if self.enable == 0x00 else f'Scan Enabled ({hex_enable})'
        hex_filter_duplicates = hci.i2h(self.filter_duplicates).lower()
        self.filter_duplicates = f'Dup. Filter Disabled ({hex_filter_duplicates})' if self.filter_duplicates == 0x00 else f'Dup. Filter Enabled ({hex_filter_duplicates})'
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLEAddDeviceToWhiteList:
    addr_type: bytes
    addr: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr_type = addrtype2str(self.addr_type)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLERemoveDeviceFromWhiteList:
    addr_type: bytes
    addr: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr_type = addrtype2str(self.addr_type)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLEEncrypt:
    pass

@dataclass
class CommandLEStartEncryption:
    hdl: bytes
    rand_num: bytes
    enc_div: bytes
    long_term_key: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rand_num = hci.b2h(self.rand_num).lower()
        self.enc_div = hci.b2h(self.enc_div).lower()
        self.long_term_key = hci.b2h(self.long_term_key).lower()
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class CommandLELongTermKeyRequestReply:
    pass

@dataclass
class CommandLEAddDeviceToResolvingList:
    pass

@dataclass
class CommandLERemoveDeviceFromResolvingList:
    pass

@dataclass
class CommandLEClearResolvingList:
    pass

@dataclass
class CommandLEReadPeerResolvableAddress:
    pass

@dataclass
class CommandLEReadLocalResolvableAddress:
    pass

"""
--------------------------------------------------------------------------------
                               HCI Event Packets
--------------------------------------------------------------------------------
"""

@dataclass
class EventInquiryResult:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 844
    """
    num_responses: bytes
    responses: bytes # should be a list of responses
    rawbytes: bytes

    def __post_init__(self):
        self.num_responses = hci.i2h(self.num_responses)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventInquiryResultWithRSSI:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 886
    """
    num_responses: bytes
    responses: bytes # should be a list of responses
    rawbytes: bytes

    def __post_init__(self):
        self.num_responses = hci.i2h(self.num_responses)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventExtendedInquiryResult:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 896
    """
    num_responses: bytes
    responses: bytes # should be a list of responses
    rawbytes: bytes

    def __post_init__(self):
        self.num_responses = hci.i2h(self.num_responses)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventConnectionComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 846
    """
    status: bytes
    hdl: bytes
    addr: bytes
    lt: bytes # lt = 0x01 = ACL (others should be investigated...)
    enc_enabled: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 11)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.lt = hci.i2h(self.lt)
        self.enc_enabled = hci.i2h(self.enc_enabled)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventConnectionRequest:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 848
    """
    addr: bytes
    cod: bytes
    lt: bytes # lt = 0x01 = ACL (others should be investigated...)
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 10)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.cod = hci.pkt_bytes_to_cod(self.cod)
        self.lt = hci.i2h(self.lt)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventDisconnectionComplete:
    """
    """
    status: bytes
    hdl: bytes
    reason: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.reason = hci.ERROR_CODES[self.reason]
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventRemoteNameRequestComplete:
    status: bytes
    addr: bytes
    name: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.name = self.name.decode("utf-8").replace('\x00', '')
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventReadRemoteVersionInformationComplete:
    status: bytes
    hdl: bytes
    version: bytes
    manufacturer_name: bytes
    subversion: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.status = hci.i2h(self.status, nbytes=1)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.version = hci.i2h(self.status, nbytes=1)
        self.subversion = hci.i2h(self.status, nbytes=2)
        # see: https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/
        self.manufacturer_name = hci.b2h(struct.unpack("<BB", self.manufacturer_name), delim='', reverse=True, leading0x=True)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventCommandComplete:
    num_cmd_pkts: bytes
    rescode: bytes
    return_params: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.num_cmd_pkts = hci.i2h(self.num_cmd_pkts)
        self.rescode = hci.pkt_bytes_to_hci_opcode(self.rescode).lower()
        self.cmdopcode = hci.h2i(self.rescode)
        self.rescode = hci_cmd.cmd_to_str(hci.h2i(self.rescode))
        status = self.return_params[0]
        self.return_params = f'({hci.ERROR_CODES[status]} = {hci.i2h(status)}) {hci.b2h(self.return_params).lower()}'
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventCommandStatus:
    status: bytes
    num_cmd_pkts: bytes
    opcode: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) > 2)
        self.status = hci.i2h(self.status, nbytes=1)
        self.num_cmd_pkts = hci.i2h(self.num_cmd_pkts, nbytes=1)
        self.opcode = hci_cmd.cmd_to_str(hci.h2i(hci.pkt_bytes_to_hci_opcode(self.opcode).lower()))
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventRoleChange:
    status: bytes
    addr: bytes
    role: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.role = role2str(self.role)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventLogicalLinkComplete:
    status: bytes
    llhdl: bytes # logical link handle
    plhdl: bytes # physical link handle
    txflowID: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.llhdl = hci.pkt_bytes_to_conn_hdl(self.llhdl)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventNumberOfCompletedPackets:
    num_hdls: bytes
    hdls_npkts: bytes
    data: bytes

    def __post_init__(self):
        self.num_hdls = hci.i2h(self.num_hdls)
        self.data = hci.b2h(self.data).lower()

@dataclass
class EventLEConnectionComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 929
    """
    status: bytes
    hdl: bytes
    role: bytes
    addr_type: bytes
    addr: bytes
    conn_interval: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    master_clk_acc: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 18)
        self.addr_type = addrtype2str(self.addr_type)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.role = role2str(self.role)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.conn_interval = hci.i2h(self.conn_interval)
        self.conn_latency = hci.i2h(self.conn_latency)
        # self.supervision_timeout = hci.i2h(self.supervision_timeout)
        self.master_clk_acc = hci.i2h(self.master_clk_acc)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventLEEnhancedConnectionComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 944
    """
    status: bytes
    hdl: bytes
    role: bytes
    addr_type: bytes
    addr: bytes
    local_resolvable_addr: bytes
    peer_resolvable_addr: bytes
    conn_interval: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    master_clk_acc: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 18)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.local_resolvable_addr = hci.pkt_bytes_to_bdaddr(self.local_resolvable_addr)
        self.peer_resolvable_addr = hci.pkt_bytes_to_bdaddr(self.peer_resolvable_addr)
        self.addr_type = addrtype2str(self.addr_type)
        self.role = role2str(self.role)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventLEAdvertisingReport:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 932
    """
    num_reports: bytes
    evt_type: bytes
    addr_type: bytes
    addr: bytes
    adv_dlen: bytes
    adv_data: bytes
    rssi: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(self.num_reports == 1) # FIXME LATER: just checking - the controller can cache reports & send multiple at one time, but I haven't seen this in practice yet....
        self.num_reports = hci.i2h(self.num_reports)

        evt_type = hci.i2h(self.evt_type)
        if self.evt_type == 0x00:
            self.evt_type = f'ADV_IND ({evt_type})'
        elif self.evt_type == 0x01:
            self.evt_type = f'ADV_DIRECT_IND ({evt_type})'
        elif self.evt_type == 0x02:
            self.evt_type = f'ADV_SCAN_IND ({evt_type})'
        elif self.evt_type == 0x03:
            self.evt_type = f'ADV_NONCONN_IND ({evt_type})'
        elif self.evt_type == 0x04:
            self.evt_type = f'SCAN_RSP ({evt_type})'
        else:
            self.evt_type = f'Reserved ({evt_type})'

        self.adv_dlen = hci.i2h(self.adv_dlen).lower()
        adv_data = f'{hci.b2h(self.adv_data).lower()}'
        try:
            adv_data += f' ({self.adv_data.decode("utf-8")})'
        except:
            adv_data += f' ({repr(self.adv_data)})'
        self.adv_data = adv_data

        self.addr_type = addrtype2str(self.addr_type)
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.rssi = f'{hci.b2si(self.rssi)} dbm' # convert signed-integer to correct value
        self.rawbytes = hci.b2h(self.rawbytes).lower()

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
    rssi: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(self.num_reports == 1) # FIXME LATER: just checking - the controller can cache reports & send multiple at one time, but I haven't seen this in practice yet....
        self.addr = hci.pkt_bytes_to_bdaddr(self.addr)
        self.dir_addr = hci.pkt_bytes_to_bdaddr(self.dir_addr)
        self.rssi = hci.b2si(self.rssi) # convert signed-integer to correct value
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventLEConnectionUpdateComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 934
    """
    status: bytes
    hdl: bytes
    conn_interval: bytes
    conn_latency: bytes
    supervision_timeout: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 9)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.b2h(self.rawbytes).lower()

@dataclass
class EventLEReadRemoteUsedFeaturesComplete:
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part E] page 936
    """
    status: bytes
    hdl: bytes
    le_features: bytes
    rawbytes: bytes

    def __post_init__(self):
        assert(len(self.rawbytes) == 11)
        self.hdl = hci.pkt_bytes_to_conn_hdl(self.hdl)
        self.rawbytes = hci.b2h(self.rawbytes).lower()
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
    code: bytes
    id: bytes
    psm: bytes
    scid: bytes

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.psm = hci.pkt_bytes_to_l2cap_psm(self.psm)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)

@dataclass
class L2CAPConnectionResponse:
    code: bytes
    id: bytes
    dcid: bytes
    scid: bytes
    result: bytes
    status: bytes

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)
        self.result = hci.i2h(self.result, nbytes=2)
        self.status = hci.i2h(self.status, nbytes=2)

@dataclass
class L2CAPDisconnectionRequest:
    code: bytes
    id: bytes
    dcid: bytes
    scid: bytes

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)

@dataclass
class L2CAPDisconnectionResponse:
    code: bytes
    id: bytes
    dcid: bytes
    scid: bytes

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.dcid = hci.pkt_bytes_to_l2cap_cid(self.dcid)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)

@dataclass
class L2CAPCreateChannelRequest:
    code: bytes
    id: bytes
    psm: bytes
    scid: bytes
    ctrlid: bytes

    def __post_init__(self):
        self.code = hci.i2h(self.code)
        self.id = hci.i2h(self.id)
        self.psm = hci.pkt_bytes_to_l2cap_psm(self.psm)
        self.scid = hci.pkt_bytes_to_l2cap_cid(self.scid)
        self.ctrlid = hci.i2h(self.ctrlid)

@dataclass
class L2CAPCreateChannelResponse:
    code: bytes
    id: bytes
    dcid: bytes
    scid: bytes
    result: bytes
    status: bytes

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

def hexstr_from_bytes(data_bit_array, nbytes=2, doswap=True):
    # data = BitArray(data)[8:24] # select 1st two bytes (=16 bits)
    data = data_bit_array
    if doswap:
        data.byteswap([0,2], repeat=False) # need to swap first two bytes
    data = hci.i2h(hci.h2i( data.hex ), nbytes=nbytes, leading0x=True)
    return data

@dataclass
class ATT:
    l2cap_data: bytes

    def __post_init__(self):
        # The att_opcode = the 1st byte of the l2cap payload
        # The att_data = the 2nd byte and everything beyond.
        att_opcode, att_data = att.parse(self.l2cap_data)

        self.att_opcode = att_opcode
        self.att_data = hci.b2h(att_data)
        self.att_data_raw = att_data

        self.opcode2str = att.opcode_to_str(att_opcode, att_data)
        nbits2bytes = 8

        # ======================================================================
        # MTU Exchange =========================================================
        # ======================================================================

        if att_opcode == 0x02: # Exchange MTU Request
            self.client_rx_mtu = hexstr_from_bytes(BitArray(att_data)[0:16])
        if att_opcode == 0x03: # Exchange MTU Response
            self.server_rx_mtu = hexstr_from_bytes(BitArray(att_data)[0:16])

        # ======================================================================
        # Find Info ============================================================
        # ======================================================================

        if att_opcode == 0x04: # Find Information Request
            self.start_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.end_hdl = hexstr_from_bytes(BitArray(att_data)[16:])
        if att_opcode == 0x05: # Find Information Response
            format = att_data[0] # format of information data
            self.info_format = hci.i2h(format)
            if format == 0x01: # Handle(s) and 16-bit UUID(s)
                self.hdl = hexstr_from_bytes(BitArray(att_data)[8:24])
                self.uuid = hexstr_from_bytes(BitArray(att_data)[24:])
            elif format == 0x02: # Handle(s) and 128-bit UUID(s)
                self.hdl = hexstr_from_bytes(BitArray(att_data)[8:24])
                self.uuid = hexstr_from_bytes(BitArray(att_data)[24:])
            else:
                raise Exception(f'Unsupported Format Type (0x{self.info_format:02x})')

        if att_opcode == 0x06: # Find By Type Value Request
            self.start_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.end_hdl = hexstr_from_bytes(BitArray(att_data)[16:32])
            self.att_type = hexstr_from_bytes(BitArray(att_data)[32:48])
            self.att_value = hexstr_from_bytes(BitArray(att_data)[48:])

        if att_opcode == 0x07: # Find By Type Value Response
            hdls_info_list = self.hdls_info_list = BitArray(att_data)[0:]
            self.npairs = int(len(self.hdls_info_list) / 4 / nbits2bytes)
            hdllen = self.hdllen = 2

            self.found_att_hdl_and_end_group_hdl_pairs = []
            for i in range(self.npairs):
                hdl1_index = (hdllen*nbits2bytes)
                hdl2_index = (hdl1_index) + (hdllen*nbits2bytes)
                # extract handles
                hdl1 = hexstr_from_bytes( BitArray(hdls_info_list)[0:hdl1_index] )
                hdl2 = hexstr_from_bytes( BitArray(hdls_info_list)[hdl1_index:hdl2_index] )
                # shift info list to extract next pair
                hdls_info_list = BitArray(att_data)[hdl2_index:]
                # build list of handle/value tuples
                self.found_att_hdl_and_end_group_hdl_pairs.append( (hdl1, hdl2) )

        # ======================================================================
        # ATT Reads ============================================================
        # ======================================================================

        if att_opcode == 0x08: # Read By Type Request
            self.start_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.end_hdl = hexstr_from_bytes(BitArray(att_data)[16:32])
            self.att_type = hexstr_from_bytes(BitArray(att_data)[32:])

        if att_opcode == 0x09: # Read By Type Response
            # NOTE: SAME CODE AS Read Multiple Response below (att_opcode == 0x11)
            length = BitArray(att_data)[0:8] # the size of one attribute handle-value pair
            self.length = hexstr_from_bytes(BitArray(att_data)[0:8], nbytes=1)
            att_data_list = self.att_data_list = BitArray(att_data)[8:]
            self.npairs = int(len(self.att_data_list) / length.int / nbits2bytes)

            hdllen = self.hdllen = 2
            vallen = self.vallen = (length.int - hdllen)

            self.hdl_val_pairs = []
            for i in range(self.npairs):
                i = (hdllen * nbits2bytes)
                j = (hdllen*nbits2bytes) + (vallen*nbits2bytes)
                # extract handle
                hdl = hexstr_from_bytes( BitArray(att_data_list)[0:i] )
                # extract value
                val = hexstr_from_bytes( BitArray(att_data_list)[i:j], doswap=False )
                # shift data list to extract next handl/value pair
                att_data_list = BitArray(att_data)[(hdllen*nbits2bytes) + (vallen*nbits2bytes):]
                # build list of handle/value tuples
                self.hdl_val_pairs.append( (hdl, val) )

        if att_opcode == 0x0a: # Read Request
            self.att_read_req_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
        if att_opcode == 0x0b: # Read Response
            self.att_read_rsp_val = hexstr_from_bytes(BitArray(att_data)[0:], nbytes=1, doswap=False)

        if att_opcode == 0x0c: # Read Blob Request
            self.att_read_blob_req_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.att_read_blob_req_offset = hexstr_from_bytes(BitArray(att_data)[16:])
            # raise Exception("Haven't seen this yet...") # NOTE: BlueBorne trips this att condition
        if att_opcode == 0x0d: # Read Blob Response
            self.att_read_blob_rsp_val = hexstr_from_bytes(BitArray(att_data)[0:], nbytes=1, doswap=False)
            # raise Exception("Haven't seen this yet...") # NOTE: BlueBorne trips this att condition

        if att_opcode == 0x0e: # Read Multiple Request
            self.att_read_mult_req_hdls = hexstr_from_bytes(BitArray(att_data)[0:])
        if att_opcode == 0x0f: # Read Multiple Response
            self.att_read_mult_rsp_vals = hexstr_from_bytes(BitArray(att_data)[0:], nbytes=1, doswap=False)

        if att_opcode == 0x10: # Read Multiple Request
            self.start_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.end_hdl = hexstr_from_bytes(BitArray(att_data)[16:32])
            self.att_group_type = hexstr_from_bytes(BitArray(att_data)[32:])
        if att_opcode == 0x11: # Read Multiple Response
            # NOTE: SAME CODE AS Read By Type Response above (att_opcode == 0x09)
            length = BitArray(att_data)[0:8] # the size of one attribute handle-value pair
            self.length = hexstr_from_bytes(BitArray(att_data)[0:8], nbytes=1)
            att_data_list = self.att_data_list = BitArray(att_data)[8:]
            self.npairs = int(len(self.att_data_list) / length.int / nbits2bytes)

            hdllen = self.hdllen = 2
            vallen = self.vallen = (length.int - hdllen)

            self.hdl_val_pairs = []
            for i in range(self.npairs):
                i = (hdllen * nbits2bytes)
                j = (hdllen*nbits2bytes) + (vallen*nbits2bytes)
                # extract handle
                hdl = hexstr_from_bytes( BitArray(att_data_list)[0:i] )
                # extract value
                val = hexstr_from_bytes( BitArray(att_data_list)[i:j], doswap=False )
                # shift data list to extract next handl/value pair
                att_data_list = BitArray(att_data)[(hdllen*nbits2bytes) + (vallen*nbits2bytes):]
                # build list of handle/value tuples
                self.hdl_val_pairs.append( (hdl, val) )

        # ======================================================================
        # ATT Writes ===========================================================
        # ======================================================================

        if att_opcode == 0x12: # Write Request
            self.att_write_req_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.att_write_req_val = hexstr_from_bytes(BitArray(att_data)[16:])
        if att_opcode == 0x13: # Write Response
            pass # a 'write request' ACK (if received, the write was successful)

        if att_opcode == 0x52: # Write Command (No ACK)
            # typically used to write into a control point on the ATT server.
            self.att_write_cmd_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.att_write_cmd_val = hexstr_from_bytes(BitArray(att_data)[16:])

        if att_opcode == 0xd2: # Signed Write Command (No ACK)
            # typically used to write into a control point on the ATT server; includes authentication signature
            self.att_write_cmd_signed_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.att_write_cmd_signed_val = hexstr_from_bytes(BitArray(att_data)[16:-12])
            self.att_write_cmd_signed_sig = hexstr_from_bytes(BitArray(att_data)[-12:])
            raise Exception("Haven't seen this yet...")

        ### Queued Writes ###
        if att_opcode == 0x16: # Prepare Write Request
            raise Exception("Haven't seen this yet...")
        if att_opcode == 0x17: # Prepare Write Response
            raise Exception("Haven't seen this yet...")
        if att_opcode == 0x18: # Execute Write Request
            raise Exception("Haven't seen this yet...")
        if att_opcode == 0x19: # Execute Write Response
            raise Exception("Haven't seen this yet...")

        # ======================================================================
        # Server Initiated =====================================================
        # ======================================================================

        if att_opcode == 0x1B: # Notification (Notify)
            self.att_notification_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.att_notification_val = hexstr_from_bytes(BitArray(att_data)[16:], doswap=False)
        if att_opcode == 0x1D: # Indication
            self.att_indication_hdl = hexstr_from_bytes(BitArray(att_data)[0:16])
            self.att_indication_val = hexstr_from_bytes(BitArray(att_data)[16:], doswap=False)
        if att_opcode == 0x1C: # Confirmation
            pass # an ACK for an Indication (confirms that the client has received an indication of the given attribute)

        self.l2cap_data = hci.b2h(self.l2cap_data)
        return self

    def __str__(self):
        # collect all non-None params to print
        params = [f'{k}={v}' for k, v in self.__dict__.items() if v is not None]
        return f'ATT({", ".join(params)})'


# @dataclass
# class ATT:
#     opcode_byte_binary: bytes
#     opcode: bytes
#     cmd_flag: bytes
#     auth_flag: bytes
#     hdl: bytes
#     payload: bytes
#     data: bytes
#     rawbytes: bytes
#
#     def __post_init__(self):
#         self.opcode = att.opcode_to_str(self.opcode, self.data)
#         self.data = hci.b2h(self.data)
#         self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class SMP:
    code: bytes
    data: bytes
    rawbytes: bytes

    def __post_init__(self):
        self.code = smp.code_to_str(self.code, verbose=True)
        self.data = hci.b2h(self.data)
        self.rawbytes = hci.b2h(self.rawbytes)

@dataclass
class SCH:
    code: bytes
    id: bytes
    len: bytes
    data: bytes
    rawbytes: bytes
    l2cap_sch_evt: bytes = None

    def __post_init__(self):
        self.code = l2cap.sch_code_to_str(self.code, verbose=True)
        self.id = hci.i2h(self.id)
        self.len = hci.i2h(self.len, nbytes=2)
        self.data = hci.b2h(self.data)
        self.rawbytes = hci.b2h(self.rawbytes)
        self.l2cap_sch_evt = l2cap.parse_sch_data(self.code, self.id, self.data)
