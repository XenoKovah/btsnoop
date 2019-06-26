"""
Parse SMP packets
"""
import struct


"""
SMP PDUs

References can be found here:
    * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
    ** [vol 3] Part H (Section 3.3) - Command Format
"""
SMP_PDUS = {
        0x01 : "SMP Pairing_Request",
        0x02 : "SMP Pairing_Response",
        0x03 : "SMP Pairing_Confirm",
        0x04 : "SMP Pairing_Random",
        0x05 : "SMP Pairing_Failed",
        0x06 : "SMP Encryption_Information",
        0x07 : "SMP Master_Identification",
        0x08 : "SMP Identity_Information",
        0x09 : "SMP Identity_Address Information",
        0x0a : "SMP Signing_Information",
        0x0b : "SMP Security_Request"
    }

def parse(data):
    """
    SMP code is the first octet of the PDU

     0 1 2 3 4 5 6 7
    -----------------
    |      code     |
    -----------------

    References can be found here:
        * https://www.bluetooth.org/en-us/specification/adopted-specifications - Core specification 4.1
        ** [vol 3] Part H (Section 3.3) - Command Format

    Return a tuple (code, data)
    """
    code = struct.unpack("<B", data[:1])[0]
    return (code, data[1:])

def opcode_to_str(code, verbose=False):
    """
    Return a string representing the SMP code
    """
    if code in SMP_PDUS:
        opstr = f' [code={hci.i2h(code)} ({code})]' if verbose else ''
        return f'{SMP_PDUS[code]}{opstr}'
    else:
        return f"UNKNOWN CODE ({code})"
