"""
Parse ATT packets
"""
import struct

from . import hci

"""
GATT Profile Attribute Types
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part G] page 543

To see how ATT protocol opcodes map to GATT procedures, see:
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part G] page 569
"""
GATT_TYPES = {
    0x2800: "GATT Primary Service", #Primary Service Declaration
    0x2801: "GATT Secondary Service", #Secondary Service Declaration
    0x2802: "GATT Include", #Include Declaration
    0x2803: "GATT Characteristic", #Characteristic Declaration
    0x2900: "GATT Characteristic Extended Properties", #Characteristic Extended Properties
    0x2901: "GATT Characteristic User Description", #Characteristic User Description Descriptor
    0x2902: "GATT Client Characteristic Configuration", #Client Characteristic Configuration Descriptor
    0x2903: "GATT Server Characteristic Configuration", #Server Characteristic Configuration Descriptor
    0x2904: "GATT Characteristic Format", #Characteristic Format Descriptor
    0x2905: "GATT Characteristic Aggregate Format" #Characteristic Aggregate Format Descriptor
}

"""
TODO: Add ATT Error Codes
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part F] page 481
"""

"""
ATT PDUs

References can be found here:
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part F] page 509

For information about ATTRIBUTE TYPES, specifically w/ reference to GATT, see:
    BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part G] page 543
"""
ATT_PDUS = {
        0x01 : "ATT Error_Response",
        0x02 : "ATT Exchange_MTU_Request",
        0x03 : "ATT Exchange_MTU_Response",
        0x04 : "ATT Find_Information_Request",
        0x05 : "ATT Find_Information_Response",
        0x06 : "ATT Find_By_Type_Value_Request",
        0x07 : "ATT Find_By_Type_Value_Response",
        0x08 : "ATT Read_By_Type_Request", # read a range of attributes looking for a specific type
        0x09 : "ATT Read_By_Type_Response",
        0x0A : "ATT Read_Request", # request: read a specific attribute by specifying its handle
        0x0B : "ATT Read_Response",
        0x0C : "ATT Read_Blob_Request", # request: read PART OF a specific attribute
        0x0D : "ATT Read_Blob_Response",
        0x0E : "ATT Read_Multiple_Request", # similar to 0x0A; fixed-size attribute values only
        0x0F : "ATT Read_Multiple_Response",
        0x10 : "ATT Read_By_Group_Type_Request", # ATT type is known
        0x11 : "ATT Read_By_Group_Type_Response",
        0x12 : "ATT Write_Request", # write and request ACK
        0x13 : "ATT Write_Response",
        0x52 : "ATT Write_Command", # write (no response, no ACK, no nothing!)
        0xD2 : "ATT Signed_Write_Command", # write, but need valid auth. signature
        0x16 : "ATT Prepare_Write_Request",
        0x17 : "ATT Prepare_Write_Response",
        0x18 : "ATT Execute_Write_Request",
        0x19 : "ATT Execute_Write_Response",
        0x1B : "ATT Handle_Value_Notification", # notify client (no ACK) - unsolicited PDUs sent to client by the server
        0x1D : "ATT Handle_Value_Indication", # notify with required ACK from client - unsolicited PDUs sent to the client by the server AND invoke confirmations
        0x1E : "ATT Handle_Value_Confirmation" # sent in response to an indication - PDUs sent to a server to confirm receipt of an indication by a client
    }
iATT_PDUS = dict(map(reversed, ATT_PDUS.items()))

"""
ATT Error Responses

BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part F] page 481

     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
    --------------------------------------------------------------------------------
    |  opcode=0x01  |  req. opcode  |          att handle           |  error code  |
    --------------------------------------------------------------------------------

"""
ATT_ERRORS = {
        0x01 : "ATT_Error Invalid_Handle",
        0x02 : "ATT_Error Read Not Permitted",
        0x03 : "ATT_Error Write Not Permitted",
        0x04 : "ATT_Error Invalid PDU",
        0x05 : "ATT_Error Insufficient Authentication",
        0x06 : "ATT_Error Request Not Supported",
        0x07 : "ATT_Error Invalid Offset",
        0x08 : "ATT_Error Insufficient Authorization",
        0x09 : "ATT_Error Prepare Queue Full",
        0x0a : "ATT_Error Attribute Not Found",
        0x0b : "ATT_Error Attribute Not Long",
        0x0c : "ATT_Error Insufficient Encryption Key Size",
        0x0d : "ATT_Error Invalid Attribute Value Length",
        0x0e : "ATT_Error Unlikely Error",
        0x0f : "ATT_Error Insufficient Encryption",
        0x10 : "ATT_Error Unsupported Group Type",
        0x11 : "ATT_Error Insufficient Resources"
        # 0x12 - 0x7f : RFU
        # 0x80 - 0x9f : Application error code defined by higher-layer spec.
        # 0xa0 - 0xdf : RFU
        # 0xe0 - 0xff : Common profile and service error codes
}
iATT_ERRORS = dict(map(reversed, ATT_ERRORS.items()))

def parse(data):
    """
    Attribute opcode is the first octet of the PDU

     0 1 2 3 4 5 6 7
    -----------------
    |   att opcode  |
    -----------------
    |     a     |b|c|
    -----------------
    a - method
    b - command flag
    c - authentication signature flag

    References can be found here:
        * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
        ** [vol 3] Part F (Section 3.3) - Attribute PDU

    Return a tuple (opcode, data)
    """
    opcode = struct.unpack("<B", data[:1])[0]
    return (opcode, data[1:])

def opcode_to_str(opcode, data):
    """
    Return a string representing the ATT PDU opcode
    """
    if opcode in ATT_PDUS:
        opstr = f' ({hci.i2h(opcode)})'

        # special formatting for errors
        if opcode == iATT_PDUS["ATT Error_Response"]:
            errcode = data[-1]
            if errcode in ATT_ERRORS:
                opstr += f' {ATT_ERRORS[errcode]} ({hci.i2h(errcode)})'
            else:
                opstr += f' Unsupported Error Code ({hci.i2h(errcode)})'

        return f'{ATT_PDUS[opcode]}{opstr}'
    else:
        return f"UNKNOWN OPCODE ({opcode})"
