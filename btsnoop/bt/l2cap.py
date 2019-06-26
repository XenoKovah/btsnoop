"""
Parse L2CAP packets
"""
import struct
from dataclasses import dataclass
from bitstring import BitStream, BitArray

from . import hci
from . import hci_acl
from . import att

from . import wrappers as pkts

"""
Fixed Channel IDs (CIDs) for L2CAP packets

References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications
     Core specification 4.1 [vol 3] Part A (Section 2.1) - Channel identifiers

Dynamically Allocated Channels should be in the range:
    0x0040-0xFFFF

Dynamically Allocated BLE Channels should be in the range:
    0x0040-0x007F
"""

L2CAP_CID_NUL          = 0x0000  # null channel
L2CAP_CID_SCH          = 0x0001  # signalling channel                     <<< L2CAP signalling channel
L2CAP_CID_CONNLESS     = 0x0002  # connectionless channel
L2CAP_CID_AMP_MGR      = 0x0003  # AMP manager protocol
L2CAP_CID_LE_ATT       = 0x0004  # LE attribute protocol
L2CAP_CID_LE_SCH       = 0x0005  # LE signaling channeling                <<< LE L2CAP signalling channel
L2CAP_CID_LE_SMP       = 0x0006  # LE security manager channel/protocol
L2CAP_CID_SMP          = 0x0007  # BR/EDR security manager channel
# 0x0008-0x001F reserved
# 0x0020-0x003E Assigned Numbers
L2CAP_CID_AMP_TEST_MGR = 0x003F  # AMP Test Manager protocol
# 0x0040-0x007F dynamically allocated (BLE?) CIDs
# 0x0080-0xFFFF reserved

L2CAP_CHANNEL_IDS = {
    L2CAP_CID_NUL       : "L2CAP CID_NUL",
    L2CAP_CID_SCH       : "L2CAP CID_SCH",
    L2CAP_CID_CONNLESS  : "L2CAP CID_CONNECTIONLESS",
    L2CAP_CID_AMP_MGR   : "L2CAP L2CAP_CID_AMP_MGR",
    L2CAP_CID_LE_ATT    : "L2CAP CID_ATT",
    L2CAP_CID_LE_SCH    : "L2CAP CID_LE_SCH",
    L2CAP_CID_LE_SMP    : "L2CAP CID_LE_SMP",
    L2CAP_CID_SMP       : "L2CAP CID_SMP"
}

def cid_to_str(cid):
    """
    Return a string representing the L2CAP channel id
    """
    return L2CAP_CHANNEL_IDS[cid]

"""
Assigned Numbers are used in the Logical Link Control for protocol/service multiplexers.
    https://www.bluetooth.com/specifications/assigned-numbers/logical-link-control/

The predefined L2CAP Channel Identifiers can be found within the Bluetooth® Core Specification,
    in Volume 3, Part A – Logical Link Control and Adaptation Protocol Specification
"""

L2CAP_PSM_SDP              = 0x0001
L2CAP_PSM_RFCOMM           = 0x0003
L2CAP_PSM_TCS_BIN          = 0x0005
L2CAP_PSM_TCS_BIN_CORDLESS = 0x0007
L2CAP_PSM_BNEP             = 0x000F
L2CAP_PSM_HID_CONTROL      = 0x0011
L2CAP_PSM_HID_INTERRUPT    = 0x0013
L2CAP_PSM_UPNP             = 0x0015
L2CAP_PSM_AVCTP            = 0x0017
L2CAP_PSM_AVDTP            = 0x0019
L2CAP_PSM_AVCTP_BROWSING   = 0x001B
L2CAP_PSM_UDI_CPLANE       = 0x001D
L2CAP_PSM_ATT              = 0x001F
L2CAP_PSM_3DSP             = 0x0021
L2CAP_PSM_LE_PSM_IPSP      = 0x0023
L2CAP_PSM_OTS              = 0x0025

def parse_hdr(data):
    """
    Parse L2CAP packet

     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    -----------------------------------------------------------------
    |            length             |          channel id           | -> data .....
    -----------------------------------------------------------------

    L2CAP is packet-based but follows a communication model based on channels.
    A channel represents a data flow between L2CAP entities in remote devices.
    Channels may be connection-oriented or connectionless. Fixed channels
    other than the L2CAP connectionless channel (CID 0x0002) and the two L2CAP
    signaling channels (CIDs 0x0001 and 0x0005) are considered connection-oriented.

    All L2CAP layer packet fields shall use Little Endian byte order with the exception of the
    information payload field. The endian-ness of higher layer protocols encapsulated within
    L2CAP information payload is protocol-specific

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part A (Section 3) - Data Packet Format

    Returns a tuple of (length, cid, data)
    """
    length, cid = struct.unpack("<HH", data[:4])
    data = data[4:]
    return length, cid, data


"""
Codes and names for L2CAP Signaling Protocol

DCID = Destination CID
SCID = Source CID
"""
L2CAP_SCH_PDUS = {
        0x01 : "SCH Command_Reject",
        0x02 : "SCH Connection_Request",  # PSM, SCID (device sending request)
        0x03 : "SCH Connection_Response", # DCID (device sending response), SCID (device that sent request), Result (success, pending, refused, etc.), Status
        0x04 : "SCH Configure_Request",
        0x05 : "SCH Configure_Response",
        0x06 : "SCH Disconnection_Request", # DCID (device receiving the request), SCID (device sending the request)
        0x07 : "SCH Disconnection_Response", # DCID (device sending the response), SCID (device receiving the reponse)
        0x08 : "SCH Echo_Request",
        0x09 : "SCH Echo_Response",
        0x0a : "SCH Information_Request",
        0x0b : "SCH Information_Response",
        0x0c : "SCH Create_Channel_Request", # PSM, SCID (device sending request), Controller ID (ID for controller physical link)
        0x0d : "SCH Create_Channel_Response", # DCID (device sending this response), SCID (device that sent initial request)
        0x0e : "SCH Move_Channel_Request",
        0x0f : "SCH Move_Channel_Response",
        0x10 : "SCH Move_Channel_Confirmation",
        0x11 : "SCH Move_Channel_Confirmation response",
        0x12 : "SCH Connection_Parameter_Update_Request",
        0x13 : "SCH Connection_Parameter_Update_Response",
        0x14 : "LE SCH LE_Credit_Based_Connection_Request",
        0x15 : "LE SCH LE_Credit_Based_Connection_Response",
        0x16 : "LE SCH LE_Flow_Control_Credit"
    }
INV_L2CAP_SCH_PDUS = dict(map(reversed, L2CAP_SCH_PDUS.items()))

def sch_code_to_str(code, verbose=False):
    """
    Return a string representing the signaling channel PDU
    """
    if code in L2CAP_SCH_PDUS:
        opstr = f' [code={hci.i2h(code)} ({code})]' if verbose else ''
        return f'{L2CAP_SCH_PDUS[code]}{opstr}'
    else:
        return f"UNKNOWN CODE ({code})"

def parse_sch_data(code, id, data):
    """
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part A] page 57
    """
    if code == INV_L2CAP_SCH_PDUS["SCH Connection_Request"]:
        return L2CAPConnectionRequest(code, id, data[0:2], data[2:4])
    elif code == INV_L2CAP_SCH_PDUS["SCH Connection_Response"]:
        return L2CAPConnectionResponse(code, id, data[0:2], data[2:4], data[4:6], data[6:8])

    elif code == INV_L2CAP_SCH_PDUS["SCH Disconnection_Request"]:
        return L2CAPDisconnectionRequest(code, id, data[0:2], data[2:4])
    elif code == INV_L2CAP_SCH_PDUS["SCH Disconnection_Response"]:
        return L2CAPDisconnectionResponse(code, id, data[0:2], data[2:4])

    elif code == INV_L2CAP_SCH_PDUS["SCH Create_Channel_Request"]:
        return L2CAPCreateChannelRequest(code, id, data[0:2], data[2:4], data[4])
    elif code == INV_L2CAP_SCH_PDUS["SCH Create_Channel_Response"]:
        return L2CAPCreateChannelResponse(code, id, data[0:2], data[2:4], data[4:6], data[6:8])

def parse_sch(l2cap_data):
    """
    Parse the signaling channel data.

    The signaling channel is a L2CAP packet with channel id 0x0001 (L2CAP CID_SCH)
    or 0x0005 (L2CAP_CID_LE_SCH)

     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    -----------------------------------------------------------------
    |      code     |        id     |             length            |
    -----------------------------------------------------------------

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part A (Section 4) - Signaling Packet Formats

    Returns a tuple of (code, id, length, data)
    """
    code, id, length = struct.unpack("<BBH", l2cap_data[:4])
    return (code, id, length, l2cap_data[4:])


PKT_TYPE_PARSERS = { hci_acl.PB_START_NON_AUTO_L2CAP_PDU : parse_hdr,
                     hci_acl.PB_CONT_FRAG_MSG : parse_hdr,
                     hci_acl.PB_START_AUTO_L2CAP_PDU : parse_hdr,
                     hci_acl.PB_COMPLETE_L2CAP_PDU : parse_hdr }

def parse_l2cap_data(l2cap_len, l2cap_cid, l2cap_data):

    if l2cap_cid == L2CAP_CID_LE_ATT:
        att_opcode, att_data = att.parse(l2cap_data)
        att_handle = BitArray(att_data)[0:16] # select 1st two bytes (=16 bits)
        att_handle.byteswap([0,2], repeat=False) # need to swap first two bytes
        att_payload = BitArray(att_data)[16:] # leave byte-order alone in payload?
        return pkts.ATT(att_opcode, att_handle, att_payload, att_data)

    elif l2cap_cid == L2CAP_CID_SMP:
        smp_code, smp_data = smp.parse(l2cap_data)
        return pkts.SMP(smp_code, smp_data)

    elif l2cap_cid == L2CAP_CID_SCH or l2cap_cid == L2CAP_CID_LE_SCH:
        sch_code, sch_id, sch_length, sch_data = parse_sch(l2cap_data)
        return pkts.SCH(sch_code, sch_id, sch_length, sch_data)

# def parse(data):
def parse(l2cap_pkt_type, data):
    """
    Convenience method for switching between parsing methods based on type

    NOTE: Currently this only suports ACL related parsing....
    """
    # l2cap_pkt_type = struct.unpack("<B", data[:1])[0]
    # print(l2cap_pkt_type, data)
    # length, cid, l2cap_pkt_data = parse_hdr(data)

    assert(l2cap_pkt_type == 0)

    parser = PKT_TYPE_PARSERS[l2cap_pkt_type]
    if parser is None:
        raise ValueError("Illegal L2CAP packet type")
    return parser(data)
