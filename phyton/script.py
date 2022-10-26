#!/usr/bin/python
import socket,sys

ip = sys.argv[1]
port = int(sys.argv[2])

addr = (ip, port)
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
res = client_socket.connect(addr)

if res == 0:
    print("porta aberta!\n")
else:
    print("Porta fchada!\n")
client_socket.close()


