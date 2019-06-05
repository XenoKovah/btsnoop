"""
Parse HCI Events
"""
import sys
import struct
import ctypes
# from ctypes import c_uint#, c_uint8, c_uint16, c_ulong
from ctypes import *

from . import hci

###
### Helper Structures
###

"""
Event Code (evtcode) is 1 byte.
Length (in bytes) of remaining parameters is 1 byte.

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
-------------------------------------------------
|   evtcode     |    length     | ...parameters...
-------------------------------------------------

If evtcode == 0x3e, the event is an HCI_LE_META_EVENT and there is a subevt code
in the first byte after the length:

                                -----------------
                                |  subevtcode   | ...parameters...
                                -----------------
"""

class EVT_HEADER_BITS( ctypes.LittleEndianStructure ):
    _fields_ = [("evtcode",  c_uint,  8),
                ("length",   c_uint,  8)]

class EVT_HEADER( ctypes.Union ):
    _fields_ = [("b", EVT_HEADER_BITS),
                ("asbyte", c_uint)]

# class EVT_DATA_LE_CONNECTION_COMPLETE_BITS( ctypes.LittleEndianStructure ):
#     _fields_ = [("status",  c_uint8),
#                 ("conn_hdl",  c_uint8*2),
#                 ("role",  c_uint8),
#                 ("peer_addr_type",  c_uint8),
#                 ("peer_addr",  c_uint8*6),
#                 ("conn_interval",  c_uint8*2),
#                 ("conn_latency",  c_uint8*2),
#                 ("timeout",  c_uint8*2),
#                 ("master_clk_acc",  c_uint8)]
#
#
# class EVT_LE_DATA( ctypes.Union ):
#     _fields_ = [("b", EVT_DATA_LE_CONNECTION_COMPLETE_BITS),
#                 ("asbyte", c_uint)]


"""
Event codes and names for HCI events

Event code is 1 byte.

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
---------------------------------
|   event code  |    length     |
---------------------------------

However, LE Meta events adds additional data that needs to be handled.

LE_META_EVENT:

 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
-------------------------------------------------
|   event code  |    length     | subevent code |
-------------------------------------------------
"""


"""
The HCI LE Meta Event is used to encapsulate all LE Controller specific events.
The Event Code of all LE Meta Events shall be 0x3E. The Subevent_Code is
the first octet of the event parameters. The Subevent_Code shall be set to one
of the valid Subevent_Codes from an LE specific event
"""
HCI_LE_META_EVENT = 0x3e;


"""
HCI LE Meta events

References can be found here:
* https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
** [vol 2] Part E (Section 7.7.65) - Le Meta Event
"""
HCI_LE_META_EVENTS = {  # Subevent Codes
        0x01 : "EVENT LE_Connection_Complete", # Status (1), Connection_Handle (12 bits), Role (1), Peer_Address_Type (1), Peer_Address (6), Conn_Interval (2), Conn_Latency (2), Supervision_Timeout (2), Master_Clock_Accuracy (1)
        0x02 : "EVENT LE_Advertising_Report",
        0x03 : "EVENT LE_Connection_Update_Complete",
        0x04 : "EVENT LE_Read_Remote_Used_Features_Complete",
        0x05 : "EVENT LE_Long_Term_Key_Request",
        0x06 : "EVENT LE_Remote_Connection_Parameter_Request"
    }
INV_HCI_LE_META_EVENTS_LOOKUP = dict(map(reversed, HCI_LE_META_EVENTS.items()))


"""
HCI Event codes

References can be found here:
* https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
** [vol 2] Part E (Section 7.7) - Events
"""
HCI_EVENTS = {
        0x01 : "EVENT Inquiry_Complete",
        0x02 : "EVENT Inquiry_Result",
        0x03 : "EVENT Connection_Complete",    # 1, Connection_Handle (12 bits), BD_ADDR (6), Link_Type (1), Encryption_Enabled (1)
        0x04 : "EVENT Connection_Request",     # BD_ADDR (6), Class_of_Device (3), Link_Type (1)
        0x05 : "EVENT Disconnection_Complete", # 1, Connection_Handle (12 bits), reason (1)
        0x06 : "EVENT Authentication_Complete",
        0x07 : "EVENT Remote_Name_Request_Complete",
        0x08 : "EVENT Encryption_Change",
        0x09 : "EVENT Change_Connection_Link_Key_Complete",
        0x0a : "EVENT Master_Link_Key_Complete",
        0x0b : "EVENT Read_Remote_Supported_Features_Complete",
        0x0c : "EVENT Read_Remote_Version_Information_Complete",
        0x0d : "EVENT QoS_Setup_Complete",
        0x0e : "EVENT Command_Complete",
        0x0f : "EVENT Command_Status",
        0x10 : "EVENT Hardware_Error",
        0x11 : "EVENT Flush_Occurred",
        0x12 : "EVENT Role_Change",
        0x13 : "EVENT Number_Of_Completed_Packets",
        0x14 : "EVENT Mode_Change",
        0x15 : "EVENT Return_Link_Keys",
        0x16 : "EVENT PIN_Code_Request",
        0x17 : "EVENT Link_Key_Request",
        0x18 : "EVENT Link_Key_Notification",
        0x19 : "EVENT Loopback_Command",
        0x1a : "EVENT Data_Buffer_Overflow",
        0x1b : "EVENT Max_Slots_Change",
        0x1c : "EVENT Read_Clock_Offset_Complete",
        0x1d : "EVENT Connection_Packet_Type_Changed",
        0x1e : "EVENT QoS_Violation",
        0x20 : "EVENT Page_Scan_Repetition_Mode_Change",
        0x21 : "EVENT Flow_Specification_Complete",
        0x22 : "EVENT Inquiry_Result_with_RSSI",
        0x23 : "EVENT Read_Remote_Extended_Features_Complete",
        0x2c : "EVENT Synchronous_Connection_Complete",
        0x2d : "EVENT Synchronous_Connection_Changed",
        0x2e : "EVENT Sniff_Subrating",
        0x2f : "EVENT Extended_Inquiry_Result",
        0x30 : "EVENT Encryption_Key_Refresh_Complete",
        0x31 : "EVENT IO_Capability_Request",
        0x32 : "EVENT IO_Capability_Response",
        0x33 : "EVENT User_Confirmation_Request",
        0x34 : "EVENT User_Passkey_Request",
        0x35 : "EVENT Remote_OOB_Data_Request",
        0x36 : "EVENT Simple_Pairing_Complete",
        0x38 : "EVENT Link_Supervision_Timeout_Changed",
        0x39 : "EVENT Enhanced_Flush_Complete",
        0x3b : "EVENT User_Passkey_Notification",
        0x3c : "EVENT Keypress_Notification",
        0x3d : "EVENT Remote_Host_Supported_Features_Notification",
        HCI_LE_META_EVENT : "EVENT LE_Meta_Event",
        0x40 : "EVENT Physical_Link_Complete",
        0x41 : "EVENT Channel_Selected",
        0x42 : "EVENT Disconnection_Physical_Link_Complete",
        0x43 : "EVENT Physical_Link_Loss_Early_Warning",
        0x44 : "EVENT Physical_Link_Recovery",
        0x45 : "EVENT Logical_Link_Complete",
        0x46 : "EVENT Disconnection_Logical_Link_Complete",
        0x47 : "EVENT Flow_Spec_Modify_Complete",
        0x48 : "EVENT Number_Of_Completed_Data_Blocks",
        0x4c : "EVENT Short_Range_Mode_Change_Complete",
        0x4d : "EVENT AMP_Status_Change",
        0x49 : "EVENT AMP_Start_Test",
        0x4a : "EVENT AMP_Test_End",
        0x4b : "EVENT AMP_Receiver_Report",
        0x4e : "EVENT Triggered_Clock_Capture",
        0x4f : "EVENT Synchronization_Train_Complete",
        0x50 : "EVENT Synchronization_Train_Received",
        0x51 : "EVENT Connectionless_Slave_Broadcast_Receive",
        0x52 : "EVENT Connectionless_Slave_Broadcast_Timeout",
        0x53 : "EVENT Truncated_Page_Complete",
        0x54 : "EVENT Slave_Page_Response_Timeout",
        0x55 : "EVENT Connectionless_Slave_Broadcast_Channel_Map_Change",
        0x56 : "EVENT Inquiry_Response_Notification",
        0x57 : "EVENT Authenticated_Payload_Timeout_Expired",
    }
INV_HCI_EVENTS_LOOKUP = dict(map(reversed, HCI_EVENTS.items()))

"""
Links creation (observed over HCI) will be of a speicifc type.
"""
LINK_TYPES = {
        0x00 : "LINK-TYPE SCO Connection requested",
        0x01 : "LINK-TYPE ACL Connection requested",
        0x02 : "LINK-TYPE eSCO Connection requested",
    } # 0x03-0xFF Reserved for future use.


def evt_to_str(evtcode):
    """
    Return a string representing the event code
    """
    if evtcode not in HCI_EVENTS:
        return None # if evtcode is None or not in HCI_EVENTS, make this (effectively) a NOP
    return HCI_EVENTS[evtcode]


def subevt_to_str(subevtcode):
    """
    Return a string representing the subevent code (for LE events)
    """
    if subevtcode not in HCI_LE_META_EVENTS:
        return None # if subevtcode is None or not in HCI_LE_META_EVENTS, make this (effectively) a NOP
    return HCI_LE_META_EVENTS[subevtcode]


"""
Specific Parsing Routines.

This code is primarily interested in extracting information from within HCI Event packets.
-> Information provided from the CONTROLLER (or remote peer device) to the HOST.

This is a work in progress.
"""

def parse_evt_data(hci_evt_evtcode, hci_evt_subevtcode, data):
    """
    Parse HCI Event Data.
    """
    assert(hci_evt_evtcode in HCI_EVENTS)

    #########
    # DEBUG #
    #########

    prefix = str(sys._getframe().f_code.co_name).upper()
    hci_evt_info    = f'{hci.i2h(hci_evt_evtcode)}, {evt_to_str(hci_evt_evtcode)}' if hci_evt_evtcode else '' # Only report evt info if available...
    hci_le_evt_info = f' / {hci.i2h(hci_evt_subevtcode)}, {subevt_to_str(hci_evt_subevtcode)}' if hci_evt_subevtcode else '' # Only report subevt info if available...
    # print(f'{prefix}:: {hci_evt_info}{hci_le_evt_info}, len(data)={len(data)}, data={data}')

    ###
    ### Parse LE Events
    ###

    if hci_evt_evtcode == INV_HCI_EVENTS_LOOKUP["EVENT LE_Meta_Event"]:
        assert(hci_evt_subevtcode in HCI_LE_META_EVENTS)

        if hci_evt_subevtcode == INV_HCI_LE_META_EVENTS_LOOKUP["EVENT LE_Connection_Complete"]:
            assert(len(data) == 18)
            bdaddr = hci.pkt_bytes_to_bdaddr(data[5:11])
            # print(f'{prefix}:: le_bdaddr=[{bdaddr}]')
            return bdaddr

            # Status (1), Connection_Handle (12 bits), Role (1), Peer_Address_Type (1), Peer_Address (6), Conn_Interval (2), Conn_Latency (2), Supervision_Timeout (2), Master_Clock_Accuracy (1)
                 # :1                      :3             :4                     :5                 5:11

            # ledata = EVT_LE_DATA()
            # # ledata.asbyte = struct.unpack("<18B", data)[0]
            # ledata.asbyte = struct.unpack("<BHBB6BHHHB", data)[0]
            #
            # status = ledata.b.status
            # conn_hdl = ledata.b.conn_hdl
            # role = ledata.b.role
            # peer_addr_type = ledata.b.peer_addr_type
            # peer_addr = ledata.b.peer_addr #''.join(map(chr, ledata.b.peer_addr))
            # conn_interval = ledata.b.conn_interval
            # conn_latency = ledata.b.conn_latency
            # timeout = ledata.b.timeout
            # master_clk_acc = ledata.b.master_clk_acc
            #
            # print(
            #     f"status={status} "
            #     f"conn_hdl={conn_hdl} "
            #     f"role={role} "
            #     f"peer_addr_type={peer_addr_type} "
            #     f"peer_addr={peer_addr} "
            #     f"conn_interval={conn_interval} "
            #     f"conn_latency={conn_latency} "
            #     f"timeout={timeout} "
            #     f"master_clk_acc={master_clk_acc} "
            # )

        elif hci_evt_subevtcode == INV_HCI_LE_META_EVENTS_LOOKUP["EVENT LE_Advertising_Report"]:
            pass
        elif hci_evt_subevtcode == INV_HCI_LE_META_EVENTS_LOOKUP["EVENT LE_Connection_Update_Complete"]:
            pass
        elif hci_evt_subevtcode == INV_HCI_LE_META_EVENTS_LOOKUP["EVENT LE_Read_Remote_Used_Features_Complete"]:
            pass
        elif hci_evt_subevtcode == INV_HCI_LE_META_EVENTS_LOOKUP["EVENT LE_Long_Term_Key_Request"]:
            pass
        elif hci_evt_subevtcode == INV_HCI_LE_META_EVENTS_LOOKUP["EVENT LE_Remote_Connection_Parameter_Request"]:
            pass

    ###
    ### Parse Non-LE Events
    ###

    elif hci_evt_evtcode == INV_HCI_EVENTS_LOOKUP["EVENT Connection_Complete"]:
        # -> status (1), connection handle (2), BD_ADDR (6), link type (1), encrytion enabled (1)
        assert(len(data) == 11)

    elif hci_evt_evtcode == INV_HCI_EVENTS_LOOKUP["EVENT Connection_Request"]:
         # -> Connection_Request -> BD_ADDR (6), CoD (3), link type (1)
        assert(len(data) == 10)
        bdaddr = hci.pkt_bytes_to_bdaddr(data[:6])
        cod = hci.pkt_bytes_to_cod(data[6:9])
        lt = struct.unpack("<B", data[9:])[0]
        return (bdaddr, cod, lt)

    elif hci_evt_evtcode == INV_HCI_EVENTS_LOOKUP["EVENT Command_Complete"]:
        response_opcode = hci.pkt_bytes_to_hci_opcode(data[1:3])
        return response_opcode #, response_opcode_str


def parse(data):
    """
    Parse HCI event

    References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 2] Part E (Section 5) - HCI Data Formats
    ** [vol 2] Part E (Section 5.4) - Exchange of HCI-specific information
    ** [vol 2] Part E (Section 7.7) - Events
    ** [vol 2] Part E (Section 7.7.65) - Le Meta Event

    All integer values are stored in "little-endian" order.

    Returns a tuple of (evtcode, length, subevtcode, data);
        subevtcode is None if not an LE_Meta_Event.
    """
    hdr = EVT_HEADER()
    hdr.asbyte = struct.unpack("<H", data[:2])[0]
    evtcode = int(hdr.b.evtcode)
    length = int(hdr.b.length)

    # evtcode, length = struct.unpack("<BB", data[:2])
    # print(f'EVT::{struct.unpack("<H", data[:2])}', evtcode, length)

    if evtcode != HCI_LE_META_EVENT: ## Non-LE
        return (evtcode, length, None, data[2:])
    else: ## LE
        subevtcode = struct.unpack("<B", data[2:3])[0]
        length -= 1 # Subtrackt length of SubEvent code
        return (evtcode, length, subevtcode, data[3:])
