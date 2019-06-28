"""
Parse SMP packets
"""
import struct


"""
SMP PDUs

BLUETOOTH SPECIFICATION Version 4.2 [Vol 3, Part H] page 634

NOTES:
- EDIV and Rand are used by the slave device to establish a previously shared LTK in order to start an encrypted connection with a previously paired master device.
- EDIV and Rand are used by the responding device to identify an initiator and recover LTK.
- Diversifier Hiding Key (DHK)
"""
SMP_PDUS = {
        0x01 : "SMP Pairing_Request",
        0x02 : "SMP Pairing_Response",
        0x03 : "SMP Pairing_Confirm", # confirmation value(s) - 16 bytes
        0x04 : "SMP Pairing_Random", # generate and send a random number to calc. confirm value.
        0x05 : "SMP Pairing_Failed",
        0x06 : "SMP Encryption_Information", # used to transfer LTK (sent on encrypted channel only; encrypted using STK)
        0x07 : "SMP Master_Identification", # distribute EDIV and Rand (sent on encrypted channel only; encrypted using STK)
        0x08 : "SMP Identity_Information", # distribute IRK (sent on encrypted channel only)
        0x09 : "SMP Identity_Address_Information", # distribute its public device address or static random address.
        0x0a : "SMP Signing_Information", # distribute the CSRK which a device uses to sign data.
        0x0b : "SMP Security_Request", # request issued by the slave to request that the master initiates security with the requested security properties
        0x0c : "SMP Pairing_Public_Key", # transfer public key (X,Y coordinates)) to the remote device; only for secure connections
        0x0d : "SMP Pairing_DHKey_Check", # transmit 128-bit DHKey
        0x0e : "SMP Pairing_Keypress_Notification"
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

def code_to_str(code, verbose=False):
    """
    Return a string representing the SMP code
    """
    if code in SMP_PDUS:
        opstr = f' [code={hci.i2h(code)} ({code})]' if verbose else ''
        return f'{SMP_PDUS[code]}{opstr}'
    else:
        return f"UNKNOWN CODE ({code})"
