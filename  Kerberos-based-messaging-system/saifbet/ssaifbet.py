import struct
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import unpad
import os

client_reqeust = b'CNrmg\x87I~\xa3j@\xea\x8d\x98\x1b\x02od\xd9\xa2$\x96\xbc_'
server_response = (b'\xa3\xd3(\x85\xb4\xb7C_\xa9\xf4\xf8\xd2@\x7f\xa9\x91\x02\xa4z\xd1Y\xbd\x00\x96\xab\x02\x1e\xb3#T'
                   b'\x84\xe4\xd53t\x8e\x8a\xef)%\x16P@\xda\xee\xa5\xcd\xe5\x1a\xa3k\xb44\xea\xc4AH\xb2S$\xba\xea\xcd'
                   b'\xa0U\xee\xcd\x17\x14Y5nF%L\xaa\x9a\xe6\xf1\xc5\xa9q\x8f\xee?\xe5\x1e{'
                   b'\xdc\x85l\xf5^\xb4\xfe\xa4\x18\xa3\xd3('
                   b'\x85\xb4\xb7C_\xa9\xf4\xf8\xd2@\x7f\xa9\x91CNrmg\x87I~\xa3j@\xea\x8d\x98\x1b\x02\xbc%\xefe\x00'
                   b'\x00\x00\x00\x17h\xcfy \xe4\x04|\xb5T<\xe9Fx\x1e2\xe3C\x08\'k\xe1\xf9"\x11\x07\x96/\xc5\xdc4'
                   b'\xc8q\x99\x0c\xb0+q\xab\xaaw\xa8\x1c:\x8eNe\xf6a\x07x8\xd5\x18\xa7\x85\x12\xfaQ\xcb['
                   b'\x98\x04\xf2\xde\xfb)\x1b\xea\xad\xd7\xd6\'\xf5V\xc1\xab\x13\xa0g')

current_directory = os.path.dirname(os.path.abspath(__file__))
passwords_path = os.path.join(current_directory, 'most_used_passwords.txt')

if __name__ == '__main__':

    server_id, original_nonce = struct.unpack("16s8s", client_reqeust)

    client_uid, encrypted_key, ticket = struct.unpack("<16s80s121s", server_response)

    version, ticket_client_uid, server_uid, creation_time_ts, ticket_iv, ct_bytes, expiration_time_ts = struct.unpack(
        "<B16s16sQ16s48s16s", ticket)

    random_iv, encrypted_aes, encrypted_nonce = struct.unpack("<16s48s16s", encrypted_key)

    try:
        with open(passwords_path) as password_files:
            passwords = password_files.readlines()
            for password in passwords:

                # Decrypt the encrypted nonce using the password hash and IV
                password = password.encode("utf-8")[:-1]
                password_hash = SHA256.new(data=password).hexdigest()
                password_bytes = bytes.fromhex(password_hash)

                nonce_cipher = AES.new(password_bytes, AES.MODE_CBC, random_iv)
                decrypted_nonce = nonce_cipher.decrypt(encrypted_nonce)

                try:
                    decrypted_nonce = unpad(decrypted_nonce, AES.block_size)
                except Exception as e:
                    print(e, " The password is not ", password.decode("utf-8"))

                if original_nonce == decrypted_nonce:
                    print("We got the password!!!! The password is:  ", password.decode("utf-8"))
                    break
    except FileNotFoundError:
        print("Passwords files not found.")
