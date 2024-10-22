#!/usr/bin/env python3

import time
import struct
import asyncio

from bleak import BleakError, BleakScanner
from bleak.backends.scanner import AdvertisementData
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak_retry_connector import (
    MAX_CONNECT_ATTEMPTS,
    BleakClientWithServiceCache,
    BLEDevice,
    establish_connection,
)

import hashlib
import ecdsa
from fastcrc import crc16, crc8
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import utc_sys_pb2_v4 as utc_sys_pb2
import yj751_sys_pb2_v4 as yj751_sys_pb2
import pd303_pb2_v4 as pd303_pb2

# When you device is bond to your account - it's storing the user_id,
# which is on of the keys in auth procedure, so UserID need to be extracted.
# Two options:
# * If you have root on your device with ef app: from `mmkv` db. Look at the file
#   `/data/data/com.ecoflow/files/mmkv/mmkv.default` - binary, but you can find `user_id` field
# * By log in to ecoflow site: go to https://us.ecoflow.com/ , open dev console and switch to
#   "Network" tab. Then login and find POST to https://api-a.ecoflow.com/auth/login - the response
#   contains json, which have data.user.userId field string.
#USER_ID = "1234567890123456789"
USER_ID = None

# BT Address to connect to - otherwise will just print the found devices and bail
#ADDRESS = "A1:B2:C3:D4:E5:F6"
ADDRESS = None

_login_key = b''
with open('login_key.bin', 'rb') as file:
    _login_key = file.read()

# Storing the found devices here
located_devices = dict()

def discoveryCallback(device: BLEDevice, advertisement_data: AdvertisementData):
    if device.address not in located_devices:
        dev = Device.New(device, advertisement_data)
        if dev != None:
            located_devices[device.address] = dev

def getEcdhTypeSize(curve_num: int):
    '''Returns size of ecdh based on type'''
    match curve_num:
        case 1:
            return 52
        case 2:
            return 56
        case 3,4:
            return 64
        case _:
            return 40

class Device:
    MANUFACTURER_KEY = 0xb5b5
    SUPPORTED_DEVICES = (
        b'HD31', # Smart Home Panel 2
        b'Y711', # Delta Pro Ultra
    )

    @staticmethod
    def New(ble_dev, adv_data):
        '''Returns Device if ble dev fits the requirements otherwise None'''
        if not (hasattr(adv_data, "manufacturer_data") and Device.MANUFACTURER_KEY in adv_data.manufacturer_data):
            return None

        print("%s: New Device: %r" % (ble_dev.address, adv_data))
        return Device(ble_dev, adv_data)

    def __init__(self, ble_dev, adv_data):
        self._ble_dev = ble_dev
        self._address = ble_dev.address
        self._name = adv_data.local_name
        self._sn = None
        self._conn = None

        # Looking for device SN
        man_data = adv_data.manufacturer_data[Device.MANUFACTURER_KEY]
        sn = man_data[1:17]
        if sn[0:4] in Device.SUPPORTED_DEVICES:
            self._sn = sn.decode('ASCII')
            print("%s: Parsed SN: %s" % (self._address, self._sn))
        else:
            print("%s: Unknown SN: %s" % (self._address, sn))

    def isValid(self):
        return self._sn != None

    async def connect(self):
        if self._conn == None:
            self._conn = Connection(self._ble_dev, self._sn)
            await self._conn.connect()

    async def waitDisconnect(self):
        if self._conn == None:
            print("%s: Device is not connected" % (self._address,))
            return

        await self._conn.waitDisconnect()

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

    def __init__(self, src, dst, cmd_set, cmd_id, payload = b'', dsrc = 1, ddst = 1, version = 3, seq = None, product_id = 0):
        self._src        = src
        self._dst        = dst
        self._cmd_set    = cmd_set
        self._cmd_id     = cmd_id
        self._payload    = payload
        self._dsrc       = dsrc
        self._ddst       = ddst
        self._version    = version
        self._seq        = seq if seq != None else b'\x00\x00\x00\x00'
        self._product_id = product_id

        # For representation
        self._payload_hex = bytearray(self._payload).hex()

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
    def payloadHex(self):
        return self._payload_hex

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
    def fromBytes(data, is_xor = False):
        '''Deserializes bytes stream into internal data'''
        if len(data) < 20:
            print("ERROR: Unable to parse packet - too small: " + bytearray(data).hex())
            return None

        if not data.startswith(Packet.PREFIX):
            print("ERROR: Unable to parse packet - prefix is incorrect: " + bytearray(data).hex())
            return None

        version = data[1]
        payload_length = struct.unpack('<H', data[2:4])[0]

        if version == 3:
            # Check whole packet CRC16
            if crc16.arc(data[:-2]) != struct.unpack('<H', data[-2:])[0]:
                print("ERROR: Unable to parse packet - incorrect CRC16: " + bytearray(data).hex())
                return None

        # Check header CRC8
        if crc8.smbus(data[:4]) != data[4]:
            print("ERROR: Unable to parse packet - incorrect header CRC8: " + bytearray(data).hex())
            return None

        #data[4] # crc8 of header
        #product_id = data[5] # We can't determine the product id from the bytestream

        seq = data[6:10]
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

            # If first byte of seq is set - we need to xor payload with it to get the real data
            if is_xor == True and seq[0] != b'\x00':
                payload = bytes([c ^ seq[0] for c in payload])

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
        data += self.productByte() + self._seq
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
        return "Packet(0x{_src:02X}, 0x{_dst:02X}, 0x{_cmd_set:02X}, 0x{_cmd_id:02X}, bytes.fromhex('{_payload_hex}'), 0x{_dsrc:02X}, 0x{_ddst:02X}, 0x{_version:02X}, {_seq}, 0x{_product_id:02X})".format(**vars(self))

class EncPacket:
    PREFIX = b'\x5A\x5A'

    FRAME_TYPE_COMMAND = 0x00
    FRAME_TYPE_PROTOCOL = 0x01
    FRAME_TYPE_PROTOCOL_INT = 0x10

    PAYLOAD_TYPE_VX_PROTOCOL = 0x00
    PAYLOAD_TYPE_ODM_PROTOCOL = 0x04

    def __init__(self, frame_type, payload_type, payload, cmd_id = 0, version = 0, enc_key = None, iv = None):
        self._frame_type   = frame_type
        self._payload_type = payload_type
        self._payload      = payload
        self._cmd_id       = cmd_id
        self._version      = version
        self._enc_key      = enc_key
        self._iv           = iv

    def encryptPayload(self):
        if self._enc_key == None and self._iv == None:
            return self._payload # Not encrypted

        engine = AES.new(self._enc_key, AES.MODE_CBC, self._iv)
        return engine.encrypt(pad(self._payload, AES.block_size))

    def toBytes(self):
        '''Will serialize the internal data to bytes stream'''
        payload = self.encryptPayload()

        data = EncPacket.PREFIX + struct.pack('<B', self._frame_type << 4) + b'\x01'  # Unknown byte
        data += struct.pack('<H', len(payload)+2)  # +2 here is len(crc16)
        data += payload
        data += struct.pack('<H', crc16.arc(data))

        return data

class Connection:
    NOTIFY_CHARACTERISTIC = "00000003-0000-1000-8000-00805f9b34fb"
    WRITE_CHARACTERISTIC = "00000002-0000-1000-8000-00805f9b34fb"

    def __init__(self, ble_dev, dev_sn):
        self._ble_dev = ble_dev
        self._address = ble_dev.address
        self._dev_sn = dev_sn

        self._retry_on_disconnect = True
        self._disconnected = asyncio.Event()
        self._client = None
        self._enc_packet_buffer = b''

    async def shutdown(self):
        self._retry_on_disconnect = False
        if self._client != None:
            await self._client.disconnect()
        self._done.set()

    async def waitDisconnect(self):
        await self._disconnected.wait()

    # En/Decrypt functions must create AES object every time, because
    # it saves the internal state after encryption and become useless
    async def decryptShared(self, encrypted_payload: str):
        aes_shared = AES.new(self._shared_key, AES.MODE_CBC, self._iv)
        return unpad(aes_shared.decrypt(encrypted_payload), AES.block_size)

    async def decryptSession(self, encrypted_payload: str):
        aes_session = AES.new(self._session_key, AES.MODE_CBC, self._iv)
        return unpad(aes_session.decrypt(encrypted_payload), AES.block_size)

    async def encryptSession(self, payload: str):
        aes_session = AES.new(self._session_key, AES.MODE_CBC, self._iv)
        return aes_session.encrypt(pad(payload, AES.block_size))

    async def genSessionKey(self, seed: bytes, srand: bytes):
        '''Implements the necessary part of the logic, rest is skipped'''
        data_num = [0, 0, 0, 0]

        # Using seed and predefined key to get first 2 numbers
        pos = seed[0] * 0x10 + ((seed[1] - 1) & 0xff) * 0x100
        data_num[0] = struct.unpack('<Q', _login_key[pos:pos+8])[0]
        pos += 8
        data_num[1] = struct.unpack('<Q', _login_key[pos:pos+8])[0]

        # Getting the last 2 numbers from srand
        srand_len = len(srand)
        lower_srand_len = srand_len & 0xffffffff
        if srand_len < 0x20:
            srand_len = 0
        else:
            raise Exception("Not implemented")

        # Just putting srand in there byte-by-byte
        data_num[2] = struct.unpack('<Q', srand[0:8])[0]
        data_num[3] = struct.unpack('<Q', srand[8:16])[0]

        # Converting data numbers to 32 bytes
        data = b''
        data += struct.pack('<Q', data_num[0])
        data += struct.pack('<Q', data_num[1])
        data += struct.pack('<Q', data_num[2])
        data += struct.pack('<Q', data_num[3])

        # Hashing data to get the session key
        session_key = hashlib.md5(data).digest()

        return session_key

    async def parseSimple(self, data: str):
        '''Deserializes bytes stream into the simple bytes'''
        print("%s: ParseSimple: %r" % (self._address, bytearray(data).hex()))

        header = data[0:6]
        data_end = 6 + struct.unpack('<H', header[4:6])[0]
        payload_data = data[6:data_end-2]
        payload_crc = data[data_end-2:data_end]

        # Check the payload CRC16
        if crc16.arc(header+payload_data) != struct.unpack('<H', payload_crc)[0]:
            print("%s: ERROR: Unable to parse simple packet - incorrect CRC16: %r", (self._address, bytearray(data[:6+payload_length]).hex()))
            return None

        return payload_data

    async def parseEncPackets(self, data: str):
        '''Deserializes bytes stream into a list of Packets'''
        # In case there are leftovers from previous processing - adding them to current data
        if self._enc_packet_buffer:
            data = self._enc_packet_buffer + data
            self._enc_packet_buffer = b''

        print("%s: ParseEncPackets: %r" % (self._address, bytearray(data).hex()))
        if len(data) < 8:
            print("%s: ERROR: Unable to parse encrypted packet - too small: %r" % (self._address, bytearray(data).hex()))
            return None

        # Data can contain multiple EncPackets and even incomplete ones, so walking through
        packets = list()
        while data:
            if not data.startswith(EncPacket.PREFIX):
                print("%s: ERROR: Unable to parse encrypted packet - prefix is incorrect: %r" %(self._address, bytearray(data).hex()))
                return packets

            header = data[0:6]
            data_end = 6 + struct.unpack('<H', header[4:6])[0]
            if data_end > len(data):
                self._enc_packet_buffer += data
                break

            payload_data = data[6:data_end-2]
            payload_crc = data[data_end-2:data_end]

            # Move to next data packet
            data = data[data_end:]

            # Check the packet CRC16
            if crc16.arc(header+payload_data) != struct.unpack('<H', payload_crc)[0]:
                print("%s: ERROR: Unable to parse encrypted packet - incorrect CRC16: %r" % (self._address, bytearray(data[:6+payload_length]).hex()))
                continue

            # Decrypt the payload packet
            payload = await self.decryptSession(payload_data)
            print("%s: ParseEncPackets: decrypted payload: %r" % (self._address, bytearray(payload).hex()))

            # Parse packet - Y needs xor
            packet = Packet.fromBytes(payload, self._dev_sn.startswith('Y711'))
            if packet != None:
                packets.append(packet)

        return packets

    async def printServices(self):
        print("%s: INFO: Service scan started..." % (self._address,))
        for service in self._client.services:
            print("  [Service] %s" % (service,))
            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        value = await self._client.read_gatt_char(char.uuid)
                        extra = f", Value: {value}"
                    except Exception as e:
                        extra = f", Error: {e}"
                else:
                    extra = ""

                if "write-without-response" in char.properties:
                    extra += f", Max write w/o rsp size: {char.max_write_without_response_size}"

                print("  [Characteristic] %s (%s)%s" % (char, ",".join(char.properties), extra))

                for descriptor in char.descriptors:
                    try:
                        value = await self._client.read_gatt_descriptor(descriptor.handle)
                        print("    [Descriptor] %s, Value: %r" % (descriptor, value))
                    except Exception as e:
                        print("    [Descriptor] %s, Error: %s" % (descriptor, e))

    def ble_device_callback(self) -> BLEDevice:
        return self._ble_dev

    async def connect(self, max_attempts: int = MAX_CONNECT_ATTEMPTS):
        self._retry_on_disconnect = True
        try:
            if self._client != None:
                if self._client.is_connected:
                    print("%s: INFO: is already connected" % (self._address,))
                    return
                await self._client.connect()
            else:
                self._client = await establish_connection(
                    BleakClientWithServiceCache,
                    self.ble_device_callback(),
                    self._ble_dev.name,
                    disconnected_callback=self.disconnected,
                    ble_device_callback=self.ble_device_callback,
                    max_attempts=max_attempts,
                )
        except (asyncio.TimeoutError, BleakError) as err:
            print("%s: Failed to connect to the device: %s" % (self._address, err))
            raise err

        print("%s: INFO: Connected" % (self._address,))

        await self.printServices()

        if self._client._backend.__class__.__name__ == "BleakClientBlueZDBus":
            await self._client._backend._acquire_mtu()
        print("%s: DEBUG: MTU: %d" % (self._address, self._client.mtu_size))

        print("%s: INFO: Init completed, running init routine" % (self._address,))

        await self.initBleSessionKey()

    def disconnected(self, *args, **kwargs) -> None:
        print("%s: Disconnected from device callback" % (self._address,))
        if self._retry_on_disconnect:
            loop = asyncio.get_event_loop()
            loop.create_task(self.connect())
        else:
            self._disconnected.set()

    async def sendRequest(self, send_data: bytes, response_handler = None):
        print("%s: Sending: %r" % (self._address, bytearray(send_data).hex()))
        if response_handler:
            await self._client.start_notify(Connection.NOTIFY_CHARACTERISTIC, response_handler)
        await self._client.write_gatt_char(Connection.WRITE_CHARACTERISTIC, bytearray(send_data))

    async def sendPacket(self, packet: Packet, response_handler = None):
        print("%s: Sending packet: %r" % (self._address, packet))
        # Wrapping and encrypting with session key
        to_send = EncPacket(
            EncPacket.FRAME_TYPE_PROTOCOL, EncPacket.PAYLOAD_TYPE_VX_PROTOCOL,
            packet.toBytes(), 0, 0, self._session_key, self._iv,
        ).toBytes()

        await self.sendRequest(to_send, response_handler)

    async def replyPacket(self, packet: Packet):
        '''Copies and changes the packet to be reply packet and sends it back to device'''
        reply_packet = Packet(
            packet.dst,  # Switching src to dst
            packet.src,  # Switching dst to src
            packet.cmdSet,
            packet.cmdId,
            packet.payload,
            0x01,
            0x01,  # Replacing 0 with 1
            packet.version,
            packet.seq,
            packet.productId,
        )
        await self.sendPacket(reply_packet)

    async def initBleSessionKey(self):
        print("%s: initBleSessionKey: Pub key exchange" % (self._address,))
        self._private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP160r1)
        self._public_key = self._private_key.get_verifying_key()

        to_send = EncPacket(
            EncPacket.FRAME_TYPE_COMMAND, EncPacket.PAYLOAD_TYPE_VX_PROTOCOL,
            # Payload contains some weird prefix and generated public key
            b'\x01\x00' + self._public_key.to_string(),
        ).toBytes()

        # Device public key is sent as response, process will continue on device response in handler
        await self.sendRequest(to_send, self.initBleSessionKeyHandler)

    async def initBleSessionKeyHandler(self, characteristic: BleakGATTCharacteristic, recv_data: bytearray):
        await self._client.stop_notify(Connection.NOTIFY_CHARACTERISTIC)

        data = await self.parseSimple(bytes(recv_data))
        status = data[1]
        ecdh_type_size = getEcdhTypeSize(data[2])
        self._dev_pub_key = ecdsa.VerifyingKey.from_string(data[3:ecdh_type_size+3], curve=ecdsa.SECP160r1)

        # Generating shared key from our private key and received device public key
        # NOTE: The device will do the same with it's private key and our public key to generate the
        # same shared key value and use it to encrypt/decrypt using symmetric encryption algorithm
        self._shared_key = ecdsa.ECDH(ecdsa.SECP160r1, self._private_key, self._dev_pub_key).generate_sharedsecret_bytes()
        # Set Initialization Vector from digest of the original shared key
        self._iv = hashlib.md5(self._shared_key).digest()
        if len(self._shared_key) > 16:
            # Using just 16 bytes of generated shared key
            self._shared_key = self._shared_key[0:16]

        await self.getKeyInfoReq()

    async def getKeyInfoReq(self):
        print("%s: INFO: getKeyInfoReq: Receiving session key" % (self._address,))
        to_send = EncPacket(
            EncPacket.FRAME_TYPE_COMMAND, EncPacket.PAYLOAD_TYPE_VX_PROTOCOL,
            b'\x02',  # command to get key info to make the shared key
        ).toBytes()

        await self.sendRequest(to_send, self.getKeyInfoReqHandler)

    async def getKeyInfoReqHandler(self, characteristic: BleakGATTCharacteristic, recv_data: bytearray):
        await self._client.stop_notify(Connection.NOTIFY_CHARACTERISTIC)
        encrypted_data = await self.parseSimple(bytes(recv_data))

        if encrypted_data[0] != 0x02:
            raise Exception("Received type of KeyInfo is != 0x02, need to dig into: " + encrypted_data.hex())

        # Skipping the first byte - type of the payload (0x02)
        data = await self.decryptShared(encrypted_data[1:])

        # Parse the data that contains sRand (first 16 bytes) & seed (last 2 bytes)
        self._session_key = await self.genSessionKey(data[16:18], data[:16])

        await self.getAuthStatus()

    async def getAuthStatus(self):
        print("%s: INFO: getKeyInfoReq: Receiving auth status" % (self._address,))

        # Preparing packet with empty payload
        packet = Packet(0x21, 0x35, 0x35, 0x89, b'', 0x01, 0x01, 0x03)

        await self.sendPacket(packet, self.getAuthStatusHandler)

    async def getAuthStatusHandler(self, characteristic: BleakGATTCharacteristic, recv_data: bytearray):
        await self._client.stop_notify(Connection.NOTIFY_CHARACTERISTIC)
        packets = await self.parseEncPackets(bytes(recv_data))
        if len(packets) < 1:
            print("%s: ERROR: Unable to receive packet" % (self._address,))
        data = packets[0].payload

        print("%s: DEBUG: getAuthStatusHandler data: %r" % (self._address, bytearray(data).hex()))
        await self.autoAuthentication()

    async def autoAuthentication(self):
        print("%s: INFO: autoAuthentication: Sending secretKey consists of user id and device serial number" % (self._address,))

        # Building payload for auth
        md5_data = hashlib.md5((USER_ID + self._dev_sn).encode('ASCII')).digest()
        # We need upper case in MD5 data here
        payload = ("".join("{:02X}".format(c) for c in md5_data)).encode('ASCII')

        # Forming packet
        packet = Packet(0x21, 0x35, 0x35, 0x86, payload, 0x01, 0x01, 0x03)

        # Sending request and starting the common listener
        await self.sendPacket(packet, self.listenForDataHandler)

    async def listenForDataHandler(self, characteristic: BleakGATTCharacteristic, recv_data: bytearray):
        packets = await self.parseEncPackets(bytes(recv_data))

        for packet in packets:
            processed = False
            send_reply = False

            if packet.src == 0x35 and packet.cmdSet == 0x35 and packet.cmdId == 0x86: # Handling autoAuthentication response
                if packet.payload != b'\x00':
                    # TODO: Most probably we need to follow some other way for auth, but happens rarely
                    raise Exception("%s: ERROR: Auth failed with response: %r" % (self._address, bytearray(packet.payload).hex()))
                print("%s: Auth success" % (self._address,))
            if packet.src == 0x0B and packet.cmdSet == 0x0C:
                if packet.cmdId == 0x01:
                    p = pd303_pb2.ProtoTime()
                    p.ParseFromString(packet.payload)
                    processed = True
                    send_reply = True
                    print("PD303 ProtoTime:", str(p))
                elif packet.cmdId == 0x20:
                    p = pd303_pb2.ProtoPushAndSet()
                    p.ParseFromString(packet.payload)
                    processed = True
                    send_reply = True
                    print("PD303 ProtoPushAndSet:", str(p))
                elif packet.cmdId == 0x21:
                    p = pd303_pb2.ProtoPushAndSet()
                    p.ParseFromString(packet.payload)
                    processed = True
                    print("PD303 isGetCfgFlag back:", str(p))
            elif packet.src == 0x35 and packet.cmdSet == 0x01 and packet.cmdId == Packet.NET_BLE_COMMAND_CMD_SET_RET_TIME:
                print("%s: PD303: Device connected & ready: %r" % (self._address, packet))
                # Device requested for time and timezone offset, so responding with that
                # otherwise it will not be able to send us predictions and config data
                if len(packet.payload) == 0:
                    print("%s: PD303: Responding with RTC data to device" % (self._address,))
                    await self.sendUtcTime()
                    await self.sendRTCRespond()
                    await self.sendRTCCheck()
                processed = True
            elif packet.src == 0x0B and packet.cmdSet == 0x01 and packet.cmdId == 0x55:
                # Device is ready so send it the config request
                print("%s: PD303: Requesting config from device" % (self._address,))
                await self.enableConfigData()
                processed = True
            
            # YJ751 logic
            elif packet.src == 0x02 and packet.cmdSet == 0x02:
                if packet.cmdId == 0x01:  # Ping
                    p = yj751_sys_pb2.AppShowHeartbeatReport()
                    p.ParseFromString(packet.payload)
                    processed = True
                    send_reply = True
                    print("YJ751 AppShowHeartbeatReport:", str(p))
                elif packet.cmdId == 0x02:  # Port Current, Voltage, Frequency
                    p = yj751_sys_pb2.BackendRecordHeartbeatReport()
                    p.ParseFromString(packet.payload)
                    processed = True
                    send_reply = True
                    print("YJ751 BackendRecordHeartbeatReport:", str(p))
                elif packet.cmdId == 0x03:  # Configs
                    p = yj751_sys_pb2.APPParaHeartbeatReport()
                    p.ParseFromString(packet.payload)
                    processed = True
                    send_reply = True
                    print("YJ751 APPParaHeartbeatReport:", str(p))
                elif packet.cmdId == 0x04:  # Battery package info
                    p = yj751_sys_pb2.BpInfoReport()
                    p.ParseFromString(packet.payload)
                    processed = True
                    send_reply = True
                    print("YJ751 BpInfoReport:", str(p))
            elif packet.src == 0x06 and packet.cmdSet == 0xFE and packet.cmdId == 0x10:
                # TODO: Not quite sure it's the right message type - but most probably
                p = yj751_sys_pb2.ProductInfoGetAck()
                p.ParseFromString(packet.payload)
                processed = True
                send_reply = True
                pass

            if send_reply:
                # We need to resend packets back to device to enable device to send the additional info
                await self.replyPacket(packet)

            if not processed:
                print("%s: WARN: listenForDataHandler not processed packet: %r" % (self._address, packet))

    async def enableConfigData(self, enable = True):
        print("%s: INFO: enableConfigData" % (self._address,))
        # Forming packet
        ppas = pd303_pb2.ProtoPushAndSet()
        ppas.is_get_cfg_flag = enable
        payload = ppas.SerializeToString()
        packet = Packet(0x21, 0x0B, 0x0C, 0x21, payload, 0x01, 0x01, 0x13)

        await self.sendPacket(packet)

    async def switchCircuitOff(self, circuit_id):
        print("%s: INFO: switchCircuitOff: %d" % (self._address, circuit_id))
        #load_incre_info {
        #  hall1_incre_info {
        #    ch1_sta {
        #      load_sta: LOAD_CH_POWER_OFF
        #      ctrl_mode: RLY_HAND_CTRL_MODE
        #    }
        #  }
        #}
        #EcoPacket(src=21, dst=0B, cmdSet=0C, cmdId=21, dSrc=01, dDst=01, payload=8a05090a07d2050408001001)
        #aa130c00800d000000000000210b01010c21
        # 8a05090a07d2050408001001
        # fdd6
        #5a5a100132004a1cae9dd528ba4253a7f4e15ced6db070205a634b07b92fdb5d412d2f7124e8ba84b03a8e9f4e06f3ac7fb1ddc4de6d71a8

        # Forming packet
        ppas = pd303_pb2.ProtoPushAndSet()
        sta = getattr(ppas.load_incre_info.hall1_incre_info, 'ch'+str(circuit_id+1)+'_sta')
        sta.load_sta = pd303_pb2.LOAD_CH_STA.LOAD_CH_POWER_OFF
        sta.ctrl_mode = pd303_pb2.CTRL_MODE.RLY_HAND_CTRL_MODE
        payload = ppas.SerializeToString()
        packet = Packet(0x21, 0x0B, 0x0C, 0x21, payload, 0x01, 0x01, 0x13)

        await self.sendPacket(packet)

    async def switchCircuitOn(self, circuit_id):
        print("%s: INFO: switchCircuitOn: %d" % (self._address, circuit_id))
        #load_incre_info {
        #  hall1_incre_info {
        #    ch1_sta {
        #      load_sta: LOAD_CH_POWER_ON
        #      ctrl_mode: RLY_HAND_CTRL_MODE
        #    }
        #  }
        #}

        # Forming packet
        ppas = pd303_pb2.ProtoPushAndSet()
        sta = getattr(ppas.load_incre_info.hall1_incre_info, 'ch'+str(circuit_id+1)+'_sta')
        sta.load_sta = pd303_pb2.LOAD_CH_STA.LOAD_CH_POWER_ON
        sta.ctrl_mode = pd303_pb2.CTRL_MODE.RLY_HAND_CTRL_MODE
        payload = ppas.SerializeToString()
        packet = Packet(0x21, 0x0B, 0x0C, 0x21, payload, 0x01, 0x01, 0x13)

        await self.sendPacket(packet)

    async def sendUtcTime(self):
        print("%s: INFO: sendUtcTime" % (self._address,))
        # Forming packet
        utcs = utc_sys_pb2.SysUTCSync()
        utcs.sys_utc_time = int(time.time())
        payload = utcs.SerializeToString()
        packet = Packet(0x21, 0x0B, 0x01, 0x55, payload, 0x01, 0x01, 0x13)

        await self.sendPacket(packet)

    async def sendRTCRespond(self):
        print("%s: INFO: sendRTCRespond" % (self._address,))

        # Building payload
        tz_offset = (time.timezone if (time.localtime().tm_isdst == 0) else time.altzone) / 60 / 60 * -1
        tz_maj = int(tz_offset)
        tz_min = int((tz_offset - tz_maj) * 100)
        time_sec = int(time.time())
        payload = struct.pack('<L', time_sec) + struct.pack('<b', tz_maj) + struct.pack('<b', tz_min)

        # Forming packet
        packet = Packet(0x21, 0x35, 0x01, Packet.NET_BLE_COMMAND_CMD_SET_RET_TIME, payload, 0x01, 0x01, 0x03)

        await self.sendPacket(packet)

    async def sendRTCCheck(self):
        print("%s: INFO: sendRTCCheck" % (self._address,))

        # Building payload
        tz_offset = (time.timezone if (time.localtime().tm_isdst == 0) else time.altzone) / 60 / 60 * -1
        tz_maj = int(tz_offset)
        tz_min = int((tz_offset - tz_maj) * 100)
        time_sec = int(time.time())
        payload = struct.pack('<L', time_sec) + struct.pack('<b', tz_maj) + struct.pack('<b', tz_min)

        # Forming packet
        packet = Packet(0x21, 0x35, 0x01, Packet.NET_BLE_COMMAND_CMD_CHECK_RET_TIME, payload, 0x01, 0x01, 0x03)

        await self.sendPacket(packet)


async def main(address):
    scanner = BleakScanner(discoveryCallback)
    print("INFO: starting scanner")
    async with scanner:
        await asyncio.sleep(4.0)

    if address != None and USER_ID != None:
        print("INFO: connecting to device...")

        d = located_devices[address.upper()]
        await d.connect()
        await d.waitDisconnect()

if __name__ == "__main__":
    asyncio.run(main(ADDRESS))
