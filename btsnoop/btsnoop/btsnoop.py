"""
Parse btsnoop_hci.log binary data (similar to wireshark)
usage:
    ./btsnoop.py <filename>

References:
    bluez/src/shared/btsnoop.h
    bluez/src/shared/btsnoop.c
    bluez/android/bluetoothd-snoop.c

NOTE: As of bluez v5.50, the "android/blutoothd-snoop.c" code indicates a different btsnoop format (BTSNOOP_FORMAT_HCI).
NOTE: When using btmon to capture a btsnoop file, it too uses a different format (appears to be BTSNOOP_FORMAT_MONITOR).
--> Need to add support for these in the future...
"""


import dataclasses
import datetime
import enum
import typing

import sys
import struct


"""
From bluez/src/shared/btsnoop.h (v5.50), btsnoop format values:
"""
BTSNOOP_FORMAT_INVALID   = 0
BTSNOOP_FORMAT_HCI       = 1001
BTSNOOP_FORMAT_UART      = 1002  # << this module currently only supports this format, also known as H4
BTSNOOP_FORMAT_BCSP      = 1003
BTSNOOP_FORMAT_3WIRE     = 1004
BTSNOOP_FORMAT_MONITOR   = 2001  # << also supported
BTSNOOP_FORMAT_SIMULATOR = 2002


class BTSnoopOpcode(enum.Enum):
    NEW_INDEX = 0
    DEL_INDEX = 1
    COMMAND_PKT = 2
    EVENT_PKT = 3
    ACL_TX_PKT = 4
    ACL_RX_PKT = 5
    SCO_TX_PKT = 6
    SCO_RX_PKT = 7
    OPEN_INDEX = 8
    CLOSE_INDEX = 9
    INDEX_INFO = 10
    VENDOR_DIAG = 11
    SYSTEM_NOTE = 12
    USER_LOGGING = 13
    CTRL_OPEN = 14
    CTRL_CLOSE = 15
    CTRL_COMMAND = 16
    CTRL_EVENT = 17
    ISO_TX_PKT = 18
    ISO_RX_PKT = 19

"""
Record flags conform to:
    - bit 0         0 = sent, 1 = received
    - bit 1         0 = data, 1 = command/event
    - bit 2-31      reserved

Direction is relative to host / DTE. i.e. for Bluetooth controllers,
Send is Host->Controller, Receive is Controller->Host
"""
BTSNOOP_FLAGS = {
        0 : ("host", "controller", "data"),
        1 : ("controller", "host", "data"),
        2 : ("host", "controller", "command"),
        3 : ("controller", "host", "event")
    }


@dataclasses.dataclass
class BTSnoopRecord:
    """
    Friendly access to individual records
    apple packet logger uses this natively...
    """
    seq: int
    length: int
    flags: int
    drops: typing.Optional[int]
    ts: datetime.datetime
    data: bytearray

    def __repr__(self):
        # lets us humanize flags
        return f"BTSnoopRecord<seq={self.seq}, length={self.length}, flags={self.flags} ({flags_to_str(self.flags)}), " \
            f"drops={self.drops}, ts={self.ts}, data={self.data}>"


def flags_to_str(flags):
    """
    Returns a tuple of (src, dst, type)
    """
    assert flags in [0,1,2,3]
    return BTSNOOP_FLAGS[flags]


def flags_to_direction(flags):
    """
    Returns a str indicating the direction of the packet (H2C or C2H)
    """
    assert flags in [0,1,2,3]
    if flags in [0,2]:
        return ">" # host->controller (or h2d?)
    elif flags in [1, 3]:
        return "<" # controller->host (or d2h?)


def h2d(flags):
    assert flags in [0,1,2,3]
    if flags in [0,2]:
        return 1
    elif flags in [1, 3]: # device-to-host (i.e., controller-to-host)
        return 0
    raise BaseException('h2d error')


def _parse_time(time):
    """
    Record time is a 64-bit signed integer representing the time of packet arrival,
    in microseconds since midnight, January 1st, 0 AD nominal Gregorian.

    In order to avoid leap-day ambiguity in calculations, note that an equivalent
    epoch may be used of midnight, January 1st 2000 AD, which is represented in
    this field as 0x00E03AB44A676000.
    """
    time_betw_0_and_2000_ad = int("0x00E03AB44A676000", 16)
    time_since_2000_epoch = datetime.timedelta(microseconds=time) - datetime.timedelta(microseconds=time_betw_0_and_2000_ad)
    return datetime.datetime(2000, 1, 1) + time_since_2000_epoch


def parse(filename, verbose=True, zero_based_index=False):
    """
    Parse a Btsnoop packet capture file.

    Btsnoop packet capture file is structured as:

    -----------------------
    | header              |
    -----------------------
    | packet record nbr 1 |
    -----------------------
    | packet record nbr 2 |
    -----------------------
    | ...                 |
    -----------------------
    | packet record nbr n |
    -----------------------

    References can be found here:

    "Snoop Version 2 Packet Capture File Format"
    * http://tools.ietf.org/html/rfc1761

    "BTSnoop File Format"
    * http://www.fte.com/webhelp/SD/Content/Technical_Information/BT_Snoop_File_Format.htm

    Return a list of records, each holding a tuple of:
    * sequence nbr
    * record length (in bytes)
    * flags
    * timestamp
    * data
    """
    with open(filename, "rb") as f:
        # Validate file header
        (identification, version, type) = _read_file_header(f)

        # is this a btsnoop file?
        identification = identification.decode('utf-8')
        if (identification == "btsnoop\0"):

            _validate_btsnoop_file_header(identification, version, type, verbose)
            return [r for r in _read_btsnoop_packet_records(f, type, zero_based_index)]

        else:  # nope.... try Apple PacketLogger Format?
            pklg_version2 = (identification[1] == 0x01)

            # Validate and rewind because PacketLogger files have no file header
            _validate_packetlogger_file(identification)
            f.seek(0)
            return [r for r in _read_packetlogger_records(f, pklg_version2)]


def _read_file_header(f):
    """
    Header should conform to the following format

    ----------------------------------------
    | identification pattern|
    | 8 bytes                              |
    ----------------------------------------
    | version number                       |
    | 4 bytes                              |
    ----------------------------------------
    | data link type = HCI UART (H4)       |
    | 4 bytes                              |
    ----------------------------------------

    All integer values are stored in "big-endian" order, with the high-order bits first.
    """
    ident = f.read(8)
    version, data_link_type = struct.unpack( ">II", f.read(4 + 4) )
    return (ident, version, data_link_type)


def _validate_btsnoop_file_header(identification, version, data_link_type, verbose):
    """
    The identification pattern should be:
        'btsnoop\0'

    The version number should be:
        1

    The data link type should be: (see other formats noted above; TODO: add support for more formats)
        - HCI UART (H4)	1002

    For SWAP, data link type should be:
        HCI UART (H4)	1002
    """
    assert identification == "btsnoop\0"
    assert version == 1
    assert data_link_type in [BTSNOOP_FORMAT_UART, BTSNOOP_FORMAT_MONITOR]
    if verbose:
        print(f'btsnoop capture file version {version}, type {data_link_type}')


def _validate_packetlogger_file(identification):
    """
    Check for Apple PacketLoger format
    Adopted from https://github.com/regnirof/hciparse/blob/8a5575b8f74462bd7d5a342885b458e212a77d76/hciparse/logparse/logparse.py
    """
    assert (identification[0] != 0x00 or (identification[1] != 0x00 and identification[1] != 0x01))


def _btmon2h4(flags: int):
    """Turns a btmon opcode into a hci-h4 uart opcode/flags pair"""
    op = BTSnoopOpcode(flags)
    if op == BTSnoopOpcode.COMMAND_PKT:
        return 1, 2
    if op == BTSnoopOpcode.ACL_RX_PKT:
        return 2, 1
    if op == BTSnoopOpcode.ACL_TX_PKT:
        return 2, 0
    if op == BTSnoopOpcode.SCO_RX_PKT:
        return 3, 1
    if op == BTSnoopOpcode.SCO_TX_PKT:
        return 3, 0
    if op == BTSnoopOpcode.EVENT_PKT:
        return 4, 3
    return None


def _read_btsnoop_packet_records(f, type, zero_based_index=False):
    """
    A record should confirm to the following format

    --------------------------
    | original length        |
    | 4 bytes
    --------------------------
    | included length        |
    | 4 bytes
    --------------------------
    | packet flags           |
    | 4 bytes
    --------------------------
    | cumulative drops       |
    | 4 bytes
    --------------------------
    | timestamp microseconds |
    | 8 bytes
    --------------------------
    | packet data            |
    --------------------------

    All integer values are stored in "big-endian" order, with the high-order bits first.
    """
    seq_nbr = 1
    if zero_based_index:
        seq_nbr = 0

    while True:
        pkt_hdr = f.read(4 + 4 + 4 + 4 + 8)
        if not pkt_hdr or len(pkt_hdr) != 24:
            # EOF
            break

        orig_len, inc_len, flags, drops, time64 = struct.unpack( ">IIIIq", pkt_hdr)
        assert orig_len == inc_len
        # Skip some known-invalid values that can happen because of truncated files
        if(inc_len == 0 or time64 == 0):
            continue
        try:
            data = f.read(inc_len)
            assert len(data) == inc_len
        except Exception as e:
            print(f"Probable truncated file encountered")
            break
        try:
            ts = _parse_time(time64)
            # XXX we're explicitly ignoring the "orig_length" field!
            if type == BTSNOOP_FORMAT_MONITOR:
                # ok, we're cheating hard here, and rewriting flags to make monitor records
                # look like H4/UART records, much as we do for apple packet logger
                adapter = flags >> 16  # we're going to just ignore this right now...
                flags = flags & 0xffff
                ut_flags = _btmon2h4(flags)
                if ut_flags:
                    data = struct.pack('B', ut_flags[0]) + data
                    flags = ut_flags[1]
                else:
                    #print(f"Ooops, unsupported btmon opcode: {flags}")
                    continue

            yield BTSnoopRecord(seq=seq_nbr, length=inc_len, flags=flags, drops=drops, ts=ts, data=data)
        except Exception as e:
            print(f"Encountered unknown exception. Investigate: {e}")
            break
        seq_nbr += 1


def _read_packetlogger_records(f, pklg_version2, zero_based_index=False):
    """
    Adopted from https://github.com/regnirof/hciparse/blob/8a5575b8f74462bd7d5a342885b458e212a77d76/hciparse/logparse/logparse.py
    """

    seq_nbr = 1
    if zero_based_index:
        seq_nbr = 0

    while True:
        # PacketLogger packet should be 4 byte len, 8 byte timestamp, 1 byte type
        pkt = f.read(4 + 8 + 1)
        if len(pkt) != 13:
            break
        # PKLGv2 files are little endian
        if pklg_version2:
            length, timestamp, pkt_type = struct.unpack("<IqB", pkt)
        else:
            length, timestamp, pkt_type = struct.unpack(">IqB", pkt)

        data = f.read(length - (13 - 4))

        # This is not very clear, but the PacketLogger flags are different so we
        # translate them to the btsnoop flags. Also there are some special types
        # we don't care about so we drop those packets. To complicate things
        # further, it seems that PacketLogger doesn't specify the UART type but
        # this library depends on it, so we forge that

        # CMD
        if pkt_type == 0x00:
            pkt_type = 0x02
            uart_type = 0x01
        # EVT
        elif pkt_type == 0x01:
            pkt_type = 0x03
            uart_type = 0x04
        # ACL TX
        elif pkt_type == 0x02:
            pkt_type = 0x00
            uart_type = 0x02
        #ACL RX
        elif pkt_type == 0x03:
            pkt_type = 0x01
            uart_type = 0x02
        else:
            continue

        data = struct.pack('B',uart_type) + data

        secs = timestamp >> 32
        usecs = timestamp & 0xffffffff
        timestamp = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=secs, microseconds=usecs)
        yield BTSnoopRecord(seq=seq_nbr, length=length, flags=pkt_type, drops=None, ts=timestamp, data=data)
        seq_nbr += 1


def print_hdr():
    print("""
##############################
#                            #
#    btsnoop parser v0.1     #
#                            #
##############################
""")


def main(filename):
    records = parse(filename)
    for record in records:
        print(record)
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    print_hdr()
    sys.exit(main(sys.argv[1]))
