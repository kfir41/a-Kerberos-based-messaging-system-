import client

if __name__ == "__main__":
    client_side = client.Client()
    s = client_side.initialize_client()
    if s:
        print("[CLIENT]: Welcome Back, " + client_side.CLIENT_USERNAME)
        print("[CLIENT]: Displaying Messages Servers list: ")
        client_side.receive_server_list()
        print("[CLIENT]: Choose a server to connect from the list above.")
        print("[CLIENT]: Please enter the server number: ")
        server_num = input()
        print("[CLIENT]: Please enter your password: ")
        client_side.CLIENT_PASSWORD = input()
        server_uid = client_side.MSG_SERVER_LIST[int(server_num) - 1][0]
        server_ip = client_side.MSG_SERVER_LIST[int(server_num) - 1][2], client_side.MSG_SERVER_LIST[int(server_num) - 1][3]
        connection = None
        if client_side.request_key(server_uid):
            print("[CLIENT]: Successfully obtained the ticket. Connecting to the desired server...")
            connection = client_side.connect_to_msg_server(server_ip)
        if connection:
            while True:
                print("[CLIENT]: Please enter a message (:quit to exit): ")
                message = input()
                if message == ":quit":
                    break
                client_side.send_message(message)
