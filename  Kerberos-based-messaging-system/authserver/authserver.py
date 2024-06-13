import base64
import binascii
import socket
import threading
import struct
import uuid
from datetime import datetime, timedelta
import sys
import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

# Importing ProtocolHandler from common module
common_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'common'))
sys.path.append(common_path)
from common import ProtocolHandler


class AuthServer:
    HOST_IP = "127.0.0.1"
    PORT_FILE = "port.info"
    CLIENTS_FILE = "clients"
    MSGS_SERVERS_FILE = "servers"
    KERBEROS_VERSION = 24
    SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    BUFFER_SIZE = 1024
    DEFAULT_PORT = 1256
    CLIENT_DICT = {}
    MSGS_SERVERS_DICT = {}

    def initialize_server(self):
        try:
            with open(self.PORT_FILE) as port_num:
                port_num = int(port_num.read())
        except FileNotFoundError:
            port_num = self.DEFAULT_PORT
            print(
                "[AUTH SERVER]: Port file not found. Starting Auth server on default port - " + str(self.DEFAULT_PORT))
        try:
            with open(self.CLIENTS_FILE) as registered_clients_file:
                clients = registered_clients_file.readlines()
                for client in clients:
                    client_data = client.split(":")
                    self.CLIENT_DICT[client_data[0]] = client_data
        except FileNotFoundError:
            print("[AUTH SERVER]: Clients file not found.")
        try:
            with open(self.MSGS_SERVERS_FILE) as registered_servers_file:
                servers = registered_servers_file.readlines()
                for server in servers:
                    server_data = server.split(":")
                    self.MSGS_SERVERS_DICT[server_data[3]] = server_data
        except FileNotFoundError:
            print("[AUTH SERVER]: Servers file not found.")

        self.accept_connections(port_num)
        return port_num

    def accept_connections(self, port_num):
        self.SOCKET.bind((self.HOST_IP, port_num))
        self.SOCKET.listen()
        print("[AUTH SERVER]: Socket is listening on port: " + str(port_num))
        while True:
            conn, addr = self.SOCKET.accept()
            print("[AUTH SERVER]: Got new connection from: " + str(addr))
            conn_thread = threading.Thread(target=self.handle_requests, args=(conn, addr))
            conn_thread.start()

    def handle_requests(self, conn, addr):
        protocol_handler = ProtocolHandler()
        print("[AUTH SERVER]: Now accepting requests from: " + str(addr))
        conn.settimeout(60)  # Set a timeout of 60 seconds
        while True:
            try:
                request = conn.recv(self.BUFFER_SIZE)
                if not request:
                    break
                request_data = protocol_handler.decode_request(request)
                if request_data['request_code'] == 1024:
                    client_uuid = self.register_client(request_data['payload'])
                    if client_uuid:
                        response_bytes = client_uuid.encode('utf-8')
                        response = protocol_handler.encode_response(self.KERBEROS_VERSION, 1600, response_bytes)
                        self.send_response(conn, response)
                elif request_data['request_code'] == 1025:
                    server_uuid = self.register_server(request_data['payload'], addr)
                    if server_uuid:
                        response_bytes = server_uuid.encode('utf-8')
                        response = protocol_handler.encode_response(self.KERBEROS_VERSION, 1600, response_bytes)
                        self.send_response(conn, response)
                elif request_data['request_code'] == 1026:
                    response_bytes = self.send_server_list()
                    response = protocol_handler.encode_response(self.KERBEROS_VERSION, 1602, response_bytes)
                    self.send_response(conn, response)
                elif request_data['request_code'] == 1027:
                    response_bytes = self.generate_symmetric_key(request_data['device_uuid'], request_data['payload'])
                    response = protocol_handler.encode_response(self.KERBEROS_VERSION, 1603, response_bytes)
                    self.send_response(conn, response)
            except socket.timeout:
                print("[AUTH SERVER]: Connection timed out for", addr)
                break
            except Exception as e:
                print("[AUTH SERVER]: Error handling request:", e)
                break
        conn.close()

    def send_response(self, conn, response):
        conn.send(response)

    def register_client(self, data):
        print("[AUTH SERVER]: Registering a new client.")
        payloads = data.split(b'\x00')
        username_bytes = payloads[0]
        password_bytes = payloads[1]
        client_uuid = uuid.uuid4().hex
        clients_file = open(self.CLIENTS_FILE, "a")
        encrypted_password = SHA256.new(data=password_bytes)
        clients_file.write(str(client_uuid) + ":" + username_bytes.decode() + ":" + str(encrypted_password.hexdigest())
                           + ":" + datetime.now().strftime("%d-%m-%Y %H-%M") + "\n")
        clients_file.close()
        self.CLIENT_DICT[str(client_uuid)] = [str(client_uuid), username_bytes.decode(),
                                                    str(encrypted_password.hexdigest()), datetime.now().strftime("%d-%m-%Y %H-%M")]
        return str(client_uuid)

    def register_server(self, data, addr):
        print("[AUTH SERVER]: Registering a new server.")
        payloads = data.split(b'\x00')
        server_name_bytes = payloads[0]
        server_port_bytes = payloads[1]
        aes_key = payloads[2]
        server_uuid = uuid.uuid4().hex
        servers_file = open(self.MSGS_SERVERS_FILE, "a")
        servers_file.write(
            addr[0] + ":" + str(server_port_bytes.decode()) + ":" + str(server_name_bytes.decode()) + ":" + str(
                server_uuid) + ":" + base64.b64encode(aes_key).decode(
                'utf-8') + "\n")
        self.MSGS_SERVERS_DICT[str(server_uuid)] = [addr[0], str(server_port_bytes.decode()), str(server_name_bytes.decode()), str(
                server_uuid), base64.b64encode(aes_key).decode(
                'utf-8')]
        return str(server_uuid)

    def send_server_list(self):
        payload = b""
        for server in self.MSGS_SERVERS_DICT:
            server_port_int = int(self.MSGS_SERVERS_DICT[server][1])
            server_ip_packed = socket.inet_aton(self.MSGS_SERVERS_DICT[server][0])
            server_uid_bytes = bytes.fromhex(self.MSGS_SERVERS_DICT[server][3])
            server_name_encoded = self.MSGS_SERVERS_DICT[server][2].encode("utf-8")
            try:
                s = struct.pack("16s255s4sH", server_uid_bytes, server_name_encoded, server_ip_packed, server_port_int)
                payload += s
            except struct.error as e:
                print("Error packing data:", e)
                continue
        return payload

    def generate_symmetric_key(self, client_uid, payload):
        request_data = struct.unpack("16s8s", payload)
        server_uid, nonce = request_data
        user_data = self.get_client_data(client_uid)
        server_data = self.get_msg_server_data(server_uid)
        print("[AUTH SERVER]: " + user_data[1] + " is requesting symmetric key for server " + server_data[2])

        # Generate a random AES key (32 bytes)
        aes_key = get_random_bytes(32)

        # Generate encrypted key and ticket
        encrypted_key = self.generate_encrypted_key(client_uid, nonce, aes_key)
        ticket = self.generate_ticket(server_uid, client_uid, aes_key)

        # Pack the components into bytes
        packed_payload = struct.pack("<16s80s121s", client_uid, encrypted_key, ticket)

        return packed_payload

    def generate_encrypted_key(self, client_uid, nonce, aes_key):
        # Get the client's password (encryption key) by the client's uuid
        user_data = self.get_client_data(client_uid)
        encryption_key = bytes.fromhex(user_data[2])

        # Encrypt the nonce using the encryption key and provided nonce
        cipher_nonce = AES.new(encryption_key, AES.MODE_CBC)
        encrypted_nonce_bytes = cipher_nonce.encrypt(pad(nonce, AES.block_size))

        # Encrypt the AES key using the encryption key and provided nonce
        cipher_aes = AES.new(encryption_key, AES.MODE_CBC, iv=cipher_nonce.iv)
        encrypted_aes_bytes = cipher_aes.encrypt(pad(aes_key, AES.block_size))

        # Pack the random IV, encrypted AES key, encrypted nonce, and AES key into a struct
        packed_data = struct.pack("<16s48s16s", cipher_nonce.iv, encrypted_aes_bytes, encrypted_nonce_bytes)

        return packed_data

    def generate_ticket(self, server_uid, client_uid, aes_key):
        version = self.KERBEROS_VERSION
        creation_time_ts = int(datetime.timestamp(datetime.now()))

        # Get the server aes key by server id from the user request
        msg_server_aes_key = self.get_msg_server_data(server_uid)[4]
        decoded_bytes = base64.b64decode(msg_server_aes_key)

        # Encrypt the Server AES key using the encryption key and provided nonce
        aes_key_cipher = AES.new(decoded_bytes, AES.MODE_CBC)
        encrypted_aes_key_bytes = aes_key_cipher.encrypt(pad(aes_key, AES.block_size))

        # Encrypt the expiration timestamp using the encryption key
        expiration_time_ts = str(datetime.timestamp(datetime.now() + timedelta(days=365))).encode()
        expiration_time_cipher = AES.new(decoded_bytes, AES.MODE_CBC)
        encrypted_expiration_time_bytes = expiration_time_cipher.encrypt(pad(expiration_time_ts, AES.block_size))

        # Define the format string
        format_string = '<B16s16sQ16s48s16s'

        # Pack the data into binary format
        packed_data = struct.pack(format_string, version, client_uid, server_uid,
                                  creation_time_ts, aes_key_cipher.iv, encrypted_aes_key_bytes,
                                  encrypted_expiration_time_bytes)

        return packed_data

    def get_client_data(self, client_uid):
        uuid_decoded = binascii.hexlify(client_uid).decode()
        return self.CLIENT_DICT[uuid_decoded]

    def get_msg_server_data(self, server_uid):
        uuid_decoded = binascii.hexlify(server_uid).decode()
        return self.MSGS_SERVERS_DICT[uuid_decoded]