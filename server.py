'''
message format
{
    "method":"CONNECT/LOGIN/LOGOUT/SEND",
    "token":"user token", #!required ALL except CONNECT
    "username":"username", #!required ALL except CONNECT
    "room":"room name", #!required LOGIN
    "msg":"message" #!required SEND
}
'''
from datetime import datetime
import threading
import secrets
import socket
import json
import sys


IP_ADDRESS = socket.gethostbyname(socket.gethostname())
PORT = 5000


class Rooms:
    def __init__(self, roomName, socket):
        self.__roomName = roomName
        self.__userList = []
        self.socket = socket

        log(f"Created room # {self.__roomName}")

    def __del__(self):
        log(f"Room # {self.__roomName} deleted")

    def num_of_group_users(self):
        return len(self.__userList)

    def addUser(self, addr, username):
        print("r adduser, addr = ", addr, username)
        welcomemsg = "Welcome {}"
        self.__userList.append(addr)
        self.broadcast(welcomemsg.format(username), addr)

    def delUser(self, addr, username):
        self.__userList.remove(addr)
        self.broadcast(f"{username} leave the room", addr)

    def broadcast(self, msg, addr, username=None):
        print("r broadcast, addr = ", addr, "usename:",username, "msg",msg)

        if username is not None:
            log(f"{username}({self.__roomName}) > {msg}")
        else:
            log(msg)

        msg = msg.encode('utf-8')

        for user_addr in self.__userList:
            if addr != user_addr:
                self.socket.sendto(msg, user_addr)


class UDPServer:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.__userList = dict()
        self.__roomList = dict()

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.settimeout(1)

    def start(self):
        """bind socket to ip, port"""
        print("s start server")

        self.socket.bind((self.ip, self.port))
        self.running = True

        log(f"Server running on {self.ip}:{self.port}")
        self.listen()

    def stop(self):
        self.server_broadcast("Server has been stopped")
        self.running = False
        log("Server stopped")
        self.socket.close()
        print("Server Closed")
        sys.exit()

    def server_broadcast(self, msg):
        print("s server broadcast, msg= ",msg)

        msg = msg.encode('utf-8')

        for user in list(self.__userList.keys()):
            self.socket.sendto(msg, self.__userList[user][0])

    def send_token(self, addr):
        print("s send token, addr = ", addr)

        # generating cryptographically strong random
        # numbers suitable for managing data such as
        # security tokens.
        token = secrets.token_urlsafe(8)
        log(f"{addr[0]}:{addr[1]} connected to this server and generating token")
        self.socket.sendto(token.encode('utf-8'), addr)

    def user_login(self, addr, data):
        print("s user login, addr = ", addr, "data:", data)

        username = data['username']
        room = data['room']
        token = data['token']
#write here ...........
        if username not in self.__userList.keys():
            if room not in self.__roomList:
                self.__roomList[room] = Rooms(
                    room, self.socket)
            else:
                self.socket.sendto()


            user_attributes = [addr, room, token]
            self.__userList[username] = user_attributes
            self.__roomList[room].addUser(addr, username)
            log(
                f"{addr[0]}:{addr[1]} with username {username} joined to {room}")
            self.socket.sendto("[SUCCESS]".encode('utf-8'), addr)
            return

        self.socket.sendto("[!username is not available]".encode('utf-8'), addr)

    def user_logout(self, addr, data):
        token = data['token']
        username = data['username']
        user_room = self.__userList[username][1]
        user_token = self.__userList[username][2]

        if token == user_token:
            self.__roomList[user_room].delUser(addr, username)
            del self.__userList[username]

            if self.__roomList[user_room].num_of_group_users() == 0:
                del self.__roomList[user_room]

    def send_msg(self, addr, data):
        print("s broadcast, addr = ", addr, "data:", data)

        msg = data["msg"]
        token = data['token']
        username = data['username']

        user_room = self.__userList[username][1]
        user_token = self.__userList[username][2]

        if token == user_token:
            self.__roomList[user_room].broadcast(
                msg, addr, username)

    def listen(self):
        print("s start listening, ")

        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                print(data, addr, "s daddr in listen function")
                data = data.decode('utf-8')
                data = json.loads(data)
                method = data["method"]

                if method == "CONNECT":
                    threading.Thread(target=self.send_token,
                                     args=(addr,)).start()

                elif method == "LOGIN":
                    threading.Thread(target=self.user_login,
                                     args=(addr, data,)).start()

                elif method == "LOGOUT":
                    threading.Thread(target=self.user_logout,
                                     args=(addr, data)).start()

                elif method == "SEND":
                    threading.Thread(target=self.send_msg,
                                     args=(addr, data)).start()

            except KeyboardInterrupt:
                self.stop()
            except socket.timeout:
                continue
            except Exception as e:
                log(str(e))
        else:
            print("Done")


def log(msg):
    time = datetime.now()
    time = time.strftime("%H:%M:%S")
    print(f"[{time}] {msg}")


server = UDPServer(IP_ADDRESS, PORT)

server.start()
