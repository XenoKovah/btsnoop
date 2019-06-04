"""
  Parse hci packet information from binary string
"""
import sys
import struct

from . import hci_uart
from . import hci_cmd
from . import hci_evt
from . import hci_acl
from . import hci_sco

"""
BD_ADDR = 0xXXXXXXXXXXXX (6 octets)

Connection_Handle = 0xXXXX (2 octets / 12 meaningful bits) Range: 0x0000-0x0EFF

Class_of_Device = 0xXXXXXX (3 octets)


"""

PKT_TYPE_PARSERS = {hci_uart.HCI_CMD : hci_cmd.parse,
                    hci_uart.ACL_DATA : hci_acl.parse,
                    hci_uart.SCO_DATA : hci_sco.parse,
                    hci_uart.HCI_EVT : hci_evt.parse}


def parse(hci_pkt_type, data):
    """
    Convenience method for switching between parsing methods based on type
    """
    parser = PKT_TYPE_PARSERS[hci_pkt_type]
    if parser is None:
        raise ValueError("Illegal HCI packet type")
    return parser(data)
