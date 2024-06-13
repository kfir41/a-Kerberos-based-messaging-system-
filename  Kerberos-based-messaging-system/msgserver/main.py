import msgserver

if __name__ == "__main__":
    msg_server = msgserver.MsgServer()
    s = msg_server.check_first_use()
    if s:
        msg_server.initialize_server()
    else:
        registered = msg_server.register_server()
        if registered:
            msg_server.initialize_server()
