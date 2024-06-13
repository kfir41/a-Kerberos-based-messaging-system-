import socket
import sys
import os
import uuid
import struct
import base64
import threading
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

common_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'common'))
sys.path.append(common_path)
from common import ProtocolHandler


class MsgServer:
    SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    BUFFER_SIZE = 1024
    AUTH_SERVER_FILE = "srv.info"
    AUTH_SERVER_IP = None
    AUTH_SERVER_PORT = None
    MSG_SERVER_DETAILS_FILE = "msg.info"
    MSG_SERVER_VERSION = 24
    MSG_SERVER_NAME = ""
    MSG_SERVER_IP = "127.0.0.1"
    MSG_SERVER_PORT = None
    MSG_SERVER_AES_KEY = ""
    MSG_SERVER_UUID = ""
    AES_KEYS_PER_CONNECTION = {}
    PROTOCOL_HANDLER = ProtocolHandler()

    def initialize_server(self):
        with (open(self.MSG_SERVER_DETAILS_FILE) as server_details_file):
            data = server_details_file.readlines()
            self.MSG_SERVER_IP, self.MSG_SERVER_PORT = data[0].split(":")
            self.MSG_SERVER_NAME, self.MSG_SERVER_UUID, self.MSG_SERVER_AES_KEY = data[1][:-1], data[2], data[3]
            server_details_file.close()
            print("[MSG SERVER]: Initializing server...")
            print("[MSG SERVER]: Loading server details from file...")
            print("[MSG SERVER]: Server IP:", self.MSG_SERVER_IP)
            print("[MSG SERVER]: Server Port:", self.MSG_SERVER_PORT)
            print("[MSG SERVER]: Server Name:", self.MSG_SERVER_NAME)
            print("[MSG SERVER]: Server UUID:", self.MSG_SERVER_UUID)
            print("[MSG SERVER]: Server AES Key:", self.MSG_SERVER_AES_KEY)
            self.accept_connections(self.MSG_SERVER_PORT)

    def accept_connections(self, port_num):
        print("[MSG SERVER]: Accepting connections on port:", port_num)
        self.SOCKET.bind((self.MSG_SERVER_IP, int(port_num)))
        self.SOCKET.listen()
        while True:
            conn, addr = self.SOCKET.accept()
            print("[MSG SERVER]: New connection accepted from:", addr)
            conn_thread = threading.Thread(target=self.handle_requests, args=(conn, addr))
            conn_thread.start()

    def handle_requests(self, conn, addr):
        protocol_handler = ProtocolHandler()
        conn.settimeout(60)  # Set a timeout of 60 seconds
        while True:
            try:
                request = conn.recv(self.BUFFER_SIZE)
                if not request:
                    break
                request_data = protocol_handler.decode_request(request)
                if request_data['request_code'] == 1028:
                    if self.receive_symmetric_key(request_data['payload'], conn):
                        print("[MSG SERVER]: Received symmetric key from client.")
                        response = protocol_handler.encode_response(self.MSG_SERVER_VERSION, 1604)
                        self.send_response(conn, response)
                    else:
                        response = protocol_handler.encode_response(self.MSG_SERVER_VERSION, 1609)
                        self.send_response(conn, response)
                elif request_data['request_code'] == 1029:
                    self.receive_msg(request_data['payload'], conn)
                    response = protocol_handler.encode_response(self.MSG_SERVER_VERSION, 1605)
                    self.send_response(conn, response)
                else:
                    response = protocol_handler.encode_response(self.MSG_SERVER_VERSION, 1609)
                    self.send_response(conn, response)
            except socket.timeout:
                print("[MSG SERVER]: Connection timed out for", addr)
                break
            except Exception as e:
                print("[MSG SERVER]: Error handling request:", e)
                break
        conn.close()

    def send_response(self, conn, response):
        conn.send(response)

    def check_first_use(self):
        print("[MSG SERVER]: Checking if first use...")
        try:
            with (open(self.MSG_SERVER_DETAILS_FILE)):
                print("[MSG SERVER]: Server details file found.")
                return True
        except FileNotFoundError:
            print("[MSG SERVER]: Server details file not found.")
            self.load_auth_server_settings()
            return False

    def load_auth_server_settings(self):
        print("[MSG SERVER]: Loading authentication server settings from file...")
        try:
            with open(self.AUTH_SERVER_FILE) as auth_server_info:
                ip, port = auth_server_info.readline().split(":")
                self.AUTH_SERVER_IP = ip
                self.AUTH_SERVER_PORT = int(port)
        except FileNotFoundError:
            print("[MSG SERVER]: Authentication server settings file not found. Exiting.")
            exit()

    def register_server(self):
        print("[MSG SERVER]: Registering server to authentication server...")
        print("[MSG SERVER]: Enter Server Name:")
        server_name = input()
        print("[MSG SERVER]: Enter Server Port (0-65535): ")
        server_port = input()
        aes_key = get_random_bytes(32)  # for aes key
        print("[MSG SERVER]: Generated AES Key:", aes_key)
        server_name = server_name + '\0'
        server_port = server_port + '\0'
        server_name_bytes = server_name.encode('utf-8')
        server_port_bytes = server_port.encode('utf-8')
        payload = server_name_bytes + server_port_bytes + aes_key
        auth_server_connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        auth_server_connection_socket.connect((self.AUTH_SERVER_IP, self.AUTH_SERVER_PORT))
        auth_server_connection_socket.send(self.PROTOCOL_HANDLER.encode_request(uuid.uuid4().bytes,
                                                                                self.MSG_SERVER_VERSION, 1025,
                                                                                payload))
        response = auth_server_connection_socket.recv(1024)
        response = self.PROTOCOL_HANDLER.decode_response(response)
        server_details_file = open(self.MSG_SERVER_DETAILS_FILE, "w")
        server_details_file.writelines(["127.0.0.1:" + str(server_port)[:-1] + "\n", str(server_name)[:-1] + "\n",
                                        response['payload'].decode('utf-8') + "\n" + base64.b64encode(aes_key).decode(
                                            'utf-8')])
        auth_server_connection_socket.close()
        print("[MSG SERVER]: Server registration completed successfully.")
        return True

    def receive_symmetric_key(self, payload, conn):
        print("[MSG SERVER]: Receiving symmetric key from client...")
        ticket, encrypted_authenticator = struct.unpack("<121s64s", payload)

        ticket_version, ticket_client_uid, ticket_server_uid, ticket_creation_time_ts, ticket_iv, ticket_encrypted_aes, ticket_expiration_time_ts = struct.unpack(
            "<B16s16sQ16s48s16s", ticket)

        decoded_bytes = base64.b64decode(self.MSG_SERVER_AES_KEY)

        aes_key_cipher = AES.new(decoded_bytes, AES.MODE_CBC, ticket_iv)
        decrypted_aes = aes_key_cipher.decrypt(ticket_encrypted_aes)

        try:
            decrypted_aes = unpad(decrypted_aes, AES.block_size)
        except Exception as e:
            print(e)

        authenticator_iv, encrypted_struct = struct.unpack("<16s48s", encrypted_authenticator)
        authenticator_struct_cipher = AES.new(decrypted_aes, AES.MODE_CBC, authenticator_iv)
        decrypted_authenticator_struct = authenticator_struct_cipher.decrypt(encrypted_struct)

        try:
            decrypted_authenticator_struct = unpad(decrypted_authenticator_struct, AES.block_size)
        except Exception as e:
            print(e)

        auth_version, auth_client_uid, auth_server_uid, auth_creation_time_ts = struct.unpack("<B16s16sQ",
                                                                                              decrypted_authenticator_struct)

        if auth_version == ticket_version and auth_client_uid == ticket_client_uid and auth_server_uid == ticket_server_uid:
            print("[MSG SERVER]: Symmetric key authentication successful.")
            self.AES_KEYS_PER_CONNECTION[conn] = decrypted_aes
            return True
        else:
            print("[MSG SERVER]: Symmetric key authentication failed.")
            return False

    def receive_msg(self, payload, conn):
        msg_len, msg_iv = struct.unpack("<I16s", payload[0:20])
        msg_content = payload[20:20 + msg_len]
        msg_cipher = AES.new(self.AES_KEYS_PER_CONNECTION[conn], AES.MODE_CBC, msg_iv)
        decrypted_msg = msg_cipher.decrypt(msg_content)
        try:
            decrypted_msg = unpad(decrypted_msg, AES.block_size)
            print("[MSG SERVER]: Decrypted message:", decrypted_msg.decode("utf-8"))
        except Exception as e:
            print("[MSG SERVER]: Error decrypting message:", e)