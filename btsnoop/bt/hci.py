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

def i2h(data):
    """Pretty print int as hex."""
    if data:
        return f'0x{data:02x}'


def pkt_bytes_to_bdaddr(addr_bytes):
    """
    Bluetooth Device Address (BD_ADDR) = 0xXXXXXXXXXXXX (6 octets)
    """
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
    pass

def pkt_bytes_to_l2cap_cid(l2cap_cid_bytes):
    """
    L2CAP Channel ID (L2CAP CID) = 0xXXXX (2 octets)
    """
    pass

def pkt_bytes_to_l2cap_psm(l2cap_psm_bytes):
    """
    Protocol/Service Multiplexer (PSM) = 0xXXXX (2 octets)
    """
    pass

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
