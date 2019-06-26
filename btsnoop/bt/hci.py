"""
Parse HCI packet information from binary string.
"""
import sys
import struct

from . import hci_uart
from . import hci_cmd
from . import hci_evt
from . import hci_acl
from . import hci_sco

from dataclasses import dataclass
from bitstring import BitStream, BitArray

PKT_TYPE_PARSERS = {hci_uart.HCI_CMD  : hci_cmd.parse,
                    hci_uart.ACL_DATA : hci_acl.parse,
                    hci_uart.SCO_DATA : hci_sco.parse,
                    hci_uart.HCI_EVT  : hci_evt.parse}


def parse(hci_pkt_type, data):
    """
    Convenience method for switching between parsing methods based on type
    """
    parser = PKT_TYPE_PARSERS[hci_pkt_type]
    if parser is None:
        raise ValueError("Illegal HCI packet type")
    return parser(data)

"""
HCI Parsing Utilities.

Extract fields from packet bytes.

- BD_ADDR
- Connection Handle
- Channel ID
- Protocol/Service Multiplexer (PSM)
- Class of Device
- OpCode
"""

def bytes2hexstr(bstr, spaced=True, delim=None):
    """
    Convery a sequency of bytes to its hex-formatted string representation.
    """
    if type(bstr) != bytes: # if bstr is not a collection of 'bytes' simply return the input
        return bstr
    if not delim:
        delim = " " if spaced else ""
    return delim.join("{:02x}".format(b) for b in bstr)

# def i2h(data):
#     """Pretty print int as hex."""
#     if data:
#         return f'0x{data:02x}'
def i2h(val, leading0x=True, nbytes=1):
    """
    Pretty print int as hex.
    @leading0x sets whether a leading '0x' will be included in the formated hex string
    @nbytes sets the number of (zero-padded) bytes to use in the formated hex string
    """
    if val is not None:
        if type(val) == bytes:
            val = BitArray(val)
            val = val.int
            # try:
            #     val = val.int
            # except:
            #     print('VALERROR???', val)
            #     val = 0
        hexstr = f'0x{val:0>{nbytes*2}x}' # 1byte = XX, 2bytes = XX XX, etc.
        if leading0x:
            return hexstr
        return hexstr[2:]

def b2si(byte):
    """Byte to Signed Integer."""
    if byte > 127:
        return (256-byte) * (-1)
    else:
        return byte

def pkt_bytes_to_bdaddr(addr_bytes):
    """
    Bluetooth Device Address (BD_ADDR) = 0xXXXXXXXXXXXX (6 octets)
    """
    if type(addr_bytes) != bytes: # if addr_bytes is not a collection of 'bytes' simply return the input
        return addr_bytes

    # extract the BD_ADDR
    bdaddr = struct.unpack("<6B", addr_bytes)
    # convert to hex-encoded string;
    bdaddr = "".join("{:02X}".format(b) for b in bdaddr)
    # reverse bytes (for some reason, this is how it is formatted...)
    bdaddr = ":".join(reversed([bdaddr[i:i+2] for i in range(0, len(bdaddr), 2)]))
    return bdaddr

def pkt_bytes_to_conn_hdl(conn_hdl_bytes):
    """
    HCI Connection Handle (HCI Conn_Hdl) = 0xXXXX (2 octets / 12 meaningful bits) Range: 0x0000-0x0EFF
    """
    assert(type(conn_hdl_bytes) == bytes)
    connhdl = struct.unpack("<BB", conn_hdl_bytes)
    connhdl = "".join("{:02X}".format(b) for b in connhdl)
    connhdl = "".join(reversed([connhdl[i:i+2] for i in range(0, len(connhdl), 2)]))
    return f'0x{connhdl}'

def pkt_bytes_to_l2cap_cid(l2cap_cid_bytes):
    """
    L2CAP Channel ID (L2CAP CID) = 0xXXXX (2 octets)
    """
    assert(type(l2cap_cid_bytes) == bytes)
    l2capcid = struct.unpack("<BB", l2cap_cid_bytes)
    l2capcid = "".join("{:02X}".format(b) for b in l2capcid)
    l2capcid = "".join(reversed([l2capcid[i:i+2] for i in range(0, len(l2capcid), 2)]))
    return f'0x{l2capcid}'

def pkt_bytes_to_l2cap_psm(l2cap_psm_bytes):
    """
    Protocol/Service Multiplexer (PSM) = 0xXXXX (2 octets)
    """
    assert(type(l2cap_psm_bytes) == bytes)
    psm = struct.unpack("<BB", l2cap_psm_bytes)
    psm = "".join("{:02X}".format(b) for b in psm)
    psm = "".join(reversed([psm[i:i+2] for i in range(0, len(psm), 2)]))
    return f'0x{psm}'

def pkt_bytes_to_cod(cod_bytes):
    """
    Class of Device = 0xXXXXXX (3 octets = 24 bits)

        Bits 0-1: Format Type
        Bits 2-7: Minor Device Class
        Bits 8-12: Major Device Class
        Bits 13-23: Major Service Class
    =>
        1100 0000 0000 0000 0000 0000
      = c    0    0    0    0    0

        0011 1111 0000 0000 0000 0000
      = 3    f    0    0    0    0

        0000 0000 1111 1000 0000 0000
      = 0    0    f    8    0    0

        0000 0000 0000 0111 1111 1111
      = 0    0    0    7    f    f
    """
    cod = struct.unpack("<BBB", cod_bytes)
    cod = " ".join("{:02X}".format(b) for b in cod)
    return cod
    # # cp.dev_class[0] = cls & 0xff;
    # c0 = cls & 0xff
    # # cp.dev_class[1] = (cls >> 8) & 0xff;
    # c1 = (cls >> 8) & 0xff;
    # # cp.dev_class[2] = (cls >> 16) & 0xff;
    # c2 = (cls >> 16) & 0xff;
    # return (c0, c1, c2)

def pkt_bytes_to_hci_opcode(opcode_bytes):
    """
    OpCode = 0xXXXX (2 octets)

    NOTE: OpCode ould be from an HCI COMMAND or HCI EVENT
    (i.e., a reference to the HCI COMMAND that warranted some HCI EVENT, where the EVENT is a response to the COMMAND)
    """
    opcode = struct.unpack("<BB", opcode_bytes)
    opcode = "".join("{:02X}".format(b) for b in opcode)
    opcode = "".join(reversed([opcode[i:i+2] for i in range(0, len(opcode), 2)]))
    return f'0x{opcode}'

"""
Error Codes

BLUETOOTH SPECIFICATION Version 4.2 [Vol 2, Part D] page 374
"""

# Error Code: Name
ERROR_CODES = {
    0x00: "Success",
    0x01: "Unknown HCI Command",
    0x02: "Unknown Connection Identifier",
    0x03: "Hardware Failure",
    0x04: "Page Timeout",
    0x05: "Authentication Failure",
    0x06: "PIN or Key Missing",
    0x07: "Memory Capacity Exceeded",
    0x08: "Connection Timeout",
    0x09: "Connection Limit Exceeded",
    0x0A: "Synchronous Connection Limit To A Device Exceeded",
    0x0B: "ACL Connection Already Exists",
    0x0C: "Command Disallowed",
    0x0D: "Connection Rejected due to Limited Resources",
    0x0E: "Connection Rejected Due To Security Reasons",
    0x0F: "Connection Rejected due to Unacceptable BD_ADDR",
    0x10: "Connection Accept Timeout Exceeded",
    0x11: "Unsupported Feature or Parameter Value",
    0x12: "Invalid HCI Command Parameters",
    0x13: "Remote User Terminated Connection",
    0x14: "Remote Device Terminated Connection due to Low Resources",
    0x15: "Remote Device Terminated Connection due to Power Off",
    0x16: "Connection Terminated By Local Host",
    0x17: "Repeated Attempts",
    0x18: "Pairing Not Allowed",
    0x19: "Unknown LMP PDU",
    0x1A: "Unsupported Remote Feature / Unsupported LMP Feature",
    0x1B: "SCO Offset Rejected",
    0x1C: "SCO Interval Rejected",
    0x1D: "SCO Air Mode Rejected",
    0x1E: "Invalid LMP Parameters / Invalid LL Parameters",
    0x1F: "Unspecified Error",
    0x20: "Unsupported LMP Parameter Value / Unsupported LL Parameter Value",
    0x21: "Role Change Not Allowed",
    0x22: "LMP Response Timeout / LL Response Timeout",
    0x23: "LMP Error Transaction Collision",
    0x24: "LMP PDU Not Allowed",
    0x25: "Encryption Mode Not Acceptable",
    0x26: "Link Key cannot be Changed",
    0x27: "Requested QoS Not Supported",
    0x28: "Instant Passed",
    0x29: "Pairing With Unit Key Not Supported",
    0x2A: "Different Transaction Collision",
    0x2B: "Reserved",
    0x2C: "QoS Unacceptable Parameter",
    0x2D: "QoS Rejected",
    0x2E: "Channel Classification Not Supported",
    0x2F: "Insufficient Security",
    0x30: "Parameter Out Of Mandatory Range",
    0x31: "Reserved",
    0x32: "Role Switch Pending",
    0x33: "Reserved",
    0x34: "Reserved Slot Violation",
    0x35: "Role Switch Failed",
    0x36: "Extended Inquiry Response Too Large",
    0x37: "Secure Simple Pairing Not Supported By Host",
    0x38: "Host Busy - Pairing",
    0x39: "Connection Rejected due to No Suitable Channel Found",
    0x3A: "Controller Busy",
    0x3B: "Unacceptable Connection Parameters",
    0x3C: "Directed Advertising Timeout",
    0x3D: "Connection Terminated due to MIC Failure",
    0x3E: "Connection Failed to be Established",
    0x3F: "MAC Connection Failed",
    0x40: "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging"
}
