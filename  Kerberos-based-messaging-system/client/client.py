import socket
import sys
import os
import uuid
import struct
from datetime import datetime
from time import sleep
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad, pad

from Crypto.Random import get_random_bytes

common_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'common'))
sys.path.append(common_path)
from common import ProtocolHandler


class Client:
    AUTH_SERVER_FILE = "srv.info"
    AUTH_SERVER_IP = None
    AUTH_SERVER_PORT = None
    AUTH_SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    CLIENT_AUTH_FILE = "me.info"
    CLIENT_VERSION = 24
    CLIENT_USERNAME = ""
    CLIENT_PASSWORD = ""
    CLIENT_UUID = ""
    CLIENT_SESSION_TICKET = None
    CLIENT_SESSION_AUTHENTICATOR = None
    CLIENT_SESSION_AES_KEY = None
    MSGS_SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    PROTOCOL_HANDLER = ProtocolHandler()
    MSG_SERVER_LIST = []
    BUFFER_SIZE = 1024

    def initialize_client(self):
        try:
            with open(self.AUTH_SERVER_FILE) as auth_server_info:
                ip, port = auth_server_info.readline().split(":")
                self.AUTH_SERVER_IP = ip
                self.AUTH_SERVER_PORT = int(port)
        except FileNotFoundError:
            print("[CLIENT]: Error - 'srv.info' file not found. Exiting.")
            exit()
        print("[CLIENT]: Connecting to the Authentication server on IP:", self.AUTH_SERVER_IP)
        try:
            self.AUTH_SERVER_SOCKET.connect((self.AUTH_SERVER_IP, self.AUTH_SERVER_PORT))
        except:
            print("[CLIENT]: Error - Authentication server is unreachable. Exiting.")
            exit()
        try:
            with open(self.CLIENT_AUTH_FILE) as user_file:
                data = user_file.readlines()
                self.CLIENT_USERNAME, self.CLIENT_UUID = data[0][:-1], data[1]
                user_file.close()
                return True
        except FileNotFoundError:
            return self.register_client()

    def register_client(self):
        print("[CLIENT]: You are not registered to the Authentication server.")
        print("[CLIENT]: Please provide the following information:")
        print("[CLIENT]: Enter Username (255 chars max.):")
        username = input()
        print("[CLIENT]: Enter Password (255 chars max.): ")
        password = input()
        username = username + '\0'
        password = password + '\0'
        username_bytes = username.encode('utf-8')
        password_bytes = password.encode('utf-8')
        payload = username_bytes + password_bytes
        self.AUTH_SERVER_SOCKET.send(self.PROTOCOL_HANDLER.encode_request(uuid.uuid4().bytes, self.CLIENT_VERSION, 1024,
                                                                          payload))  # Using Random UUID since uuid in this case is not considered
        response = self.AUTH_SERVER_SOCKET.recv(1024)
        response = self.PROTOCOL_HANDLER.decode_response(response)
        user_file = open(self.CLIENT_AUTH_FILE, "w")
        user_file.writelines([str(username)[:-1],
                              "\n" + response['payload'].decode('utf-8')]
                             )
        self.CLIENT_USERNAME = str(username)[:-1]
        self.CLIENT_UUID = response['payload'].decode('utf-8')
        return True

    def receive_server_list(self):
        self.MSG_SERVER_LIST = []
        request = self.PROTOCOL_HANDLER.encode_request(bytes.fromhex(self.CLIENT_UUID), self.CLIENT_VERSION, 1026)
        self.AUTH_SERVER_SOCKET.send(request)
        response = self.AUTH_SERVER_SOCKET.recv(1024)
        response = self.PROTOCOL_HANDLER.decode_response(response)
        payload = response["payload"]
        server_size = 278  # Size of each packed server data
        num_servers = len(payload) // server_size

        # Unpack the payload for each server
        for i in range(num_servers):
            start_index = i * server_size
            end_index = start_index + server_size
            server_data = payload[start_index:end_index]

            # Unpack server data
            server_uid, server_name, server_ip, server_port = struct.unpack("16s255s4sH", server_data)

            # Additional processing for each server data
            self.MSG_SERVER_LIST.append(
                [server_uid.hex(), server_name.decode("utf-8").rstrip('\x00'), socket.inet_ntoa(server_ip),
                 server_port])
            print(f"Server {i + 1}:")
            print("Server UID:", server_uid.hex())
            print("Server Name:", server_name.decode("utf-8").rstrip('\x00'))  # Remove null bytes at the end
            print("Server IP:", socket.inet_ntoa(server_ip))
            print("Server Port:", server_port)

    def request_key(self, server_uid):
        nonce = get_random_bytes(8)
        payload = struct.pack("16s8s", bytes.fromhex(server_uid), nonce)
        request = self.PROTOCOL_HANDLER.encode_request(bytes.fromhex(self.CLIENT_UUID), self.CLIENT_VERSION, 1027,
                                                       payload)
        self.AUTH_SERVER_SOCKET.send(request)
        sleep(1)
        response = self.AUTH_SERVER_SOCKET.recv(1024)
        response = self.PROTOCOL_HANDLER.decode_response(response)
        response_payload = response["payload"]
        return self.handle_key_response(response_payload, nonce)

    def handle_key_response(self, response_payload, original_nonce):
        # Unpack the payload
        client_uid, encrypted_key, ticket = struct.unpack("<16s80s121s", response_payload)

        # Extract relevant data from the encrypted key
        random_iv, encrypted_aes, encrypted_nonce = struct.unpack("<16s48s16s", encrypted_key)

        # Decrypt the encrypted nonce using the password hash and IV
        password = self.CLIENT_PASSWORD.encode("utf-8")
        password_hash = SHA256.new(data=password).hexdigest()
        password_bytes = bytes.fromhex(password_hash)

        nonce_cipher = AES.new(password_bytes, AES.MODE_CBC, random_iv)
        decrypted_nonce = nonce_cipher.decrypt(encrypted_nonce)

        aes_key_cipher = AES.new(password_bytes, AES.MODE_CBC, random_iv)
        decrypted_aes = aes_key_cipher.decrypt(encrypted_aes)

        try:
            decrypted_nonce = unpad(decrypted_nonce, AES.block_size)
            decrypted_aes = unpad(decrypted_aes, AES.block_size)
        except Exception as e:
            print(e)

        if original_nonce == decrypted_nonce:
            self.CLIENT_SESSION_TICKET = ticket
            self.CLIENT_SESSION_AES_KEY = decrypted_aes
            return self.generate_authenticator(ticket, decrypted_aes)

    def generate_authenticator(self, ticket, aes_key_for_encryption):
        authenticator_iv = get_random_bytes(16)

        # Extract relevant data from the ticket
        version, client_uid, server_uid, creation_time_ts, ticket_iv, ct_bytes, expiration_time_ts = struct.unpack(
            "<B16s16sQ16s48s16s", ticket)

        creation_time_ts = int(datetime.timestamp(datetime.now()))
        authenticator_fields = struct.pack("<B16s16sQ", version, client_uid, server_uid, creation_time_ts)

        struct_cipher = AES.new(aes_key_for_encryption, AES.MODE_CBC, authenticator_iv)
        encrypted_struct = struct_cipher.encrypt(pad(authenticator_fields, AES.block_size))
        authenticator = struct.pack("<16s48s", authenticator_iv, encrypted_struct
                                    )
        self.CLIENT_SESSION_AUTHENTICATOR = authenticator
        return True

    def connect_to_msg_server(self, server_ip):
        self.AUTH_SERVER_SOCKET.close()
        server_addr, server_port = server_ip
        self.MSGS_SERVER_SOCKET.connect((str(server_addr), int(server_port)))
        return self.send_symmetric_key()

    def send_symmetric_key(self):
        msg_server_symmetric_key = struct.pack("<121s64s", self.CLIENT_SESSION_TICKET,
                                               self.CLIENT_SESSION_AUTHENTICATOR)
        request = self.PROTOCOL_HANDLER.encode_request(bytes.fromhex(self.CLIENT_UUID), self.CLIENT_VERSION, 1028,
                                                       msg_server_symmetric_key)
        self.MSGS_SERVER_SOCKET.send(request)
        sleep(1)
        response = self.MSGS_SERVER_SOCKET.recv(1024)
        response = self.PROTOCOL_HANDLER.decode_response(response)
        return self.handle_response(response)

    def send_message(self, msg_str):
        msg_bytes = msg_str.encode()
        msg_cipher = AES.new(self.CLIENT_SESSION_AES_KEY, AES.MODE_CBC)
        encrypted_msg = msg_cipher.encrypt(pad(msg_bytes, AES.block_size))
        struct_payload = struct.pack("<I16s", len(encrypted_msg), msg_cipher.iv)
        payload = struct_payload + encrypted_msg
        request = self.PROTOCOL_HANDLER.encode_request(bytes.fromhex(self.CLIENT_UUID), self.CLIENT_VERSION, 1029,
                                                       payload)
        self.MSGS_SERVER_SOCKET.send(request)
        response = self.MSGS_SERVER_SOCKET.recv(1024)
        response = self.PROTOCOL_HANDLER.decode_response(response)
        return self.handle_response(response)

    def handle_response(self, response):
        response_code = response['response_code']
        if response_code == 1604:
            print("[CLIENT]: Symmetric key sent successfully.")
            return True
        elif response_code == 1605:
            print("[CLIENT]: The message has been sent successfully.")
            return True
        elif response_code == 1609:
            print("[CLIENT]: There's an error.")
        else:
            print("[CLIENT]: Received unexpected response code:", response_code)

