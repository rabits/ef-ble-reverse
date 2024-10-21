#!/usr/bin/env python3
# Script to parse / decrypt wireshark captured packets in json format

import time
import struct
import asyncio

import sys,json
from google.protobuf.json_format import MessageToJson

import hashlib
import ecdsa
from fastcrc import crc16, crc8
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import pd303_pb2
import utc_sys_pb2_v4 as utc_sys_pb2

SESSION_KEY = bytes.fromhex('2f c6 e4 ed 3b b6 40 09 93 cf b9 55 55 14 77 22')
SESSION_IV = bytes.fromhex('9d d1 8e e6 5e 40 44 05 52 e3 78 7f 7f 4b 6a 2e')

_pkt_lst = []
_pkt_ids = []

class Packet:
    PREFIX = b'\xAA'

    NET_BLE_COMMAND_CMD_CHECK_RET_TIME = 0x53
    NET_BLE_COMMAND_CMD_SET_RET_TIME = 0x52

    NET_BLE_COMMAND_VERSION = 0x03;
    NET_BLE_COMMAND_IF_TYPE_WIFI_AP = 0x00
    NET_BLE_COMMAND_IF_TYPE_WIFI_STATION = 0x01
    NET_BLE_COMMAND_IF_TYPE_ETH_WAN = 0x10
    NET_BLE_COMMAND_IF_TYPE_ETH_LAN = 0x12
    NET_BLE_COMMAND_IF_TYPE_TELECOMM_4G = 0x20
    NET_BLE_COMMAND_IF_TYPE_MAC_INFO = 0xf0
    NET_BLE_COMMAND_IF_TYPE_UNKNOW = 0xff

    def __init__(self, src, dst, cmd_set, cmd_id, payload = b'', dsrc = 1, ddst = 1, version = 3, seq = 0, product_id = 0):
        self._src        = src
        self._dst        = dst
        self._cmd_set    = cmd_set
        self._cmd_id     = cmd_id
        self._payload    = payload
        self._dsrc       = dsrc
        self._ddst       = ddst
        self._version    = version
        self._seq        = seq
        self._product_id = product_id

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @property
    def cmdSet(self):
        return self._cmd_set

    @property
    def cmdId(self):
        return self._cmd_id

    @property
    def payload(self):
        return self._payload

    @property
    def dsrc(self):
        return self._dsrc

    @property
    def ddst(self):
        return self._ddst

    @property
    def version(self):
        return self._version

    @property
    def seq(self):
        return self._seq

    @property
    def productId(self):
        return self._product_id

    @staticmethod
    def fromBytes(data):
        '''Deserializes bytes stream into internal data'''
        if len(data) < 20:
            print("ERROR: Unable to parse packet - too small: " + " ".join("{:02x}".format(c) for c in data))
            return None

        if not data.startswith(Packet.PREFIX):
            print("ERROR: Unable to parse packet - prefix is incorrect: " + " ".join("{:02x}".format(c) for c in data))
            return None

        version = data[1]
        payload_length = struct.unpack('<H', data[2:4])[0]

        if version == 3:
            # Check whole packet CRC16
            if crc16.arc(data[:-2]) != struct.unpack('<H', data[-2:])[0]:
                print("ERROR: Unable to parse packet - incorrect CRC16: " + " ".join("{:02x}".format(c) for c in data))
                return None

        # Check header CRC8
        if crc8.smbus(data[:4]) != data[4]:
            print("ERROR: Unable to parse packet - incorrect header CRC8: " + " ".join("{:02x}".format(c) for c in data))
            return None

        #data[4] # crc8 of header
        #product_id = data[5] # We can't determine the product id from the bytestream

        seq = struct.unpack('<L', data[6:10])[0]
        # data[10:12] # static zeroes
        src = data[12]
        dst = data[13]
        dsrc = data[14]
        ddst = data[15]
        cmd_set = data[16]
        cmd_id = data[17]

        payload = b''
        if payload_length > 0:
            payload = data[18:18+payload_length]

        if version == 19 and payload[-2:] == b'\xbb\xbb':
            payload = payload[:-2]

        return Packet(src, dst, cmd_set, cmd_id, payload, dsrc, ddst, version, seq)

    def toBytes(self):
        '''Will serialize the internal data to bytes stream'''
        # Header
        data = Packet.PREFIX
        data += struct.pack('<B', self._version) + struct.pack('<H', len(self._payload))
        # Header crc
        data += struct.pack('<B', crc8.smbus(data))
        # Additional data
        data += self.productByte() + struct.pack('<L', self._seq)
        data += b'\x00\x00' # Unknown static zeroes, no strings attached right now
        data += struct.pack('<B', self._src) + struct.pack('<B', self._dst)
        data += struct.pack('<B', self._dsrc) + struct.pack('<B', self._ddst)
        data += struct.pack('<B', self._cmd_set) + struct.pack('<B', self._cmd_id)
        # Payload
        data += self._payload
        # Packet crc
        data += struct.pack('<H', crc16.arc(data))

        return data

    def productByte(self):
        '''Returns magics depends on product id'''
        if self._product_id >= 0:
            return b'\x0d'
        else:
            return b'\x0c'

    def __repr__(self):
        return "Packet(0x{_src:02X}, 0x{_dst:02X}, 0x{_cmd_set:02X}, 0x{_cmd_id:02X}, {_payload}, 0x{_dsrc:02X}, 0x{_ddst:02X}, 0x{_version:02X}, 0x{_seq:08X}, 0x{_product_id:02X})".format(**vars(self))

def decrypt(data):
    if len(data) < 8:
        return None, data
    header = data[:6]
    payload_length = struct.unpack('<H', header[4:6])[0]
    if len(data) < payload_length+6:
        return None, data
    payload = data[6:6+payload_length-2]
    crc = data[6+payload_length-2:6+payload_length]

    try:
        cipher = AES.new(SESSION_KEY, AES.MODE_CBC, SESSION_IV)
        dec = unpad(cipher.decrypt(payload), AES.block_size)

        data = data[6+payload_length:]
        return dec, data
    except Exception as e:
        print("WARN: Unable to decrypt:", payload_length, "".join("{:02x}".format(c) for c in payload))

    return None, data

async def main():
    json_data = []
    with open(sys.argv[1], 'rb') as f:
        json_data = json.load(f)
    print("Parsing packets:", len(json_data))

    rest_data = dict()
    for i, packet in enumerate(json_data):
        src = packet['_source']['layers']['bthci_acl']['bthci_acl.src.name']
        dst = packet['_source']['layers']['bthci_acl']['bthci_acl.dst.name']
        t = float(packet['_source']['layers']['frame']['frame.time_relative'])

        try:
            packet_bytes = bytes.fromhex(packet['_source']['layers']['btatt']['btatt.value'].replace(':', ''))
        except:
            print("WARN: Have no btatt.value:", packet)
            continue
        if src not in rest_data:
            rest_data[src] = b''
        rest_data[src] += packet_bytes

        while True:
            (dec, rest_data[src]) = decrypt(rest_data[src])
            if dec is None:
                break

            pkt = Packet.fromBytes(dec)
            print()
            print("%03d %.4f %s --> %s : %s" % (i, t, src, dst, pkt))
            try:
                if pkt.src == 0x21 and pkt.cmdSet == 0x35 and pkt.cmdId == 0x89:
                    print("Sending auth status request")
                elif pkt.src == 0x35 and pkt.cmdSet == 0x35 and pkt.cmdId == 0x89:
                    print("Received auth status")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x35 and pkt.cmdId == 0x86:
                    print("Sending auto auth md5(user ID + device SN)")
                elif pkt.src == 0x35 and pkt.cmdSet == 0x35 and pkt.cmdId == 0x86:
                    print("Received auto auth response")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x0C and pkt.cmdId == 0x21:
                    print("Sending enableConfigData request")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x0C and pkt.cmdId == Packet.NET_BLE_COMMAND_CMD_SET_RET_TIME:
                    print("Sending sendRTCRespond")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x01 and pkt.cmdId == Packet.NET_BLE_COMMAND_CMD_CHECK_RET_TIME:
                    print("Sending sendRTCCheck")
                elif pkt.src == 0x35 and pkt.cmdSet == 0x01 and pkt.cmdId == Packet.NET_BLE_COMMAND_CMD_CHECK_RET_TIME:
                    print("Respond to sendRTCCheck")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x0C and pkt.cmdId == 0x20:
                    pkt_id = None
                    try:
                        p = pd303_pb2.ProtoPushAndSet()
                        p.ParseFromString(pkt.payload)
                        msg = MessageToJson(p, indent=0).replace('\n', '')
                        lst_i = _pkt_lst.index(msg)
                        _pkt_lst.pop(lst_i)
                        pkt_id = _pkt_ids.pop(lst_i)
                    except:
                        pass
                    print("Sending back backupIncreInfo from:", pkt_id)
                elif pkt.src == 0x21 and pkt.cmdSet == 0x0C and pkt.cmdId == 0x01:
                    pkt_id = None
                    try:
                        p = pd303_pb2.ProtoTime()
                        p.ParseFromString(pkt.payload)
                        msg = MessageToJson(p, indent=0).replace('\n', '')
                        lst_i = _pkt_lst.index(msg)
                        _pkt_lst.pop(lst_i)
                        pkt_id = _pkt_ids.pop(lst_i)
                    except:
                        pass
                    print("Sending back masterInfo from:", pkt_id)
                elif pkt.src == 0x0B and pkt.cmdSet == 0x0C:
                    p = None
                    if pkt.cmdId == 0x01:
                        p = pd303_pb2.ProtoTime()
                    elif pkt.cmdId == 0x20:
                        p = pd303_pb2.ProtoPushAndSet()
                    elif pkt.cmdId == 0x21:
                        p = pd303_pb2.ProtoPushAndSet()
                    else:
                        print("WARN: Unknown cmdId: {:02x}".format(pkt.cmdId))

                    if p != None:
                        p.ParseFromString(pkt.payload)
                        msg = MessageToJson(p, indent=0).replace('\n', '')
                        _pkt_lst.append(msg)
                        _pkt_ids.append(i)
                        print("PB:", msg)
                elif pkt.src == 0x35 and pkt.cmdSet == 0x01 and pkt.cmdId == Packet.NET_BLE_COMMAND_CMD_SET_RET_TIME:
                    print("Device requesting RTC")
                elif pkt.src == 0x0B and pkt.cmdSet == 0x01 and pkt.cmdId == 0x55:
                    print("Device online")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x01 and pkt.cmdId == 0x52:
                    print("Sending RTC data with TZ")
                elif pkt.src == 0x21 and pkt.cmdSet == 0x01 and pkt.cmdId == 0x55:
                    print("Sending UTC time through PB")
                elif pkt.src == 0x35 and pkt.cmdSet == 0x35 and pkt.cmdId == 0x20:
                    print("Received ping from device?")
                else:
                    print("WARN: Unknown pkt: {:02x} {:02x} {:02x}".format(pkt.src, pkt.cmdSet, pkt.cmdId))
            except Exception as e:
                print("WARN: Unable to parse protobuf:", e)


if __name__ == "__main__":
    asyncio.run(main())
