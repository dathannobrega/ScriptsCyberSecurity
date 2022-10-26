import socket,sys

def conectar(ip,port):
    addr = (ip, port)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    res = client_socket.connect(("192.168.0.1", 80))
    if res == 0:
        print("porta aberta!\n")
    else:
        print("Porta fchada!\n")
    client_socket.close()

if __name__ == '__main__':


    ip = sys.argv[1]
    port = int(sys.argv[2])
    conectar(ip,port)