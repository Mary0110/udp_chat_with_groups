import sys
import json
import socket
import threading


class Client:
    def __init__(self, ip, port, token):
        self.ip = ip
        self.port = int(port)
        self.__token = token
        self.__username = ""
        self.__room = ""
        self.running = True

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.connect((self.ip, self.port))

    def start(self):
        print("c start")
        if (self.user_login()):
            threading.Thread(target=self.listen).start()
            threading.Thread(target=self.send).start()

    def user_login(self):
        print("c user_login")
        while True:
            self.__username = input("Input Username: ")
            self.__room = input("Join Room: ")

            msg = {
                "method": "LOGIN",
                "token": self.__token,
                "username": self.__username,
                "room": self.__room
            }

            msg = json.dumps(msg)
            msg = msg.encode('utf-8')
            # for connected UDP sockets, use the SEND command.
            self.socket.send(msg)
    # server user login
            resp, addr = self.socket.recvfrom(1024)

            resp = resp.decode('utf-8')

            if addr == (self.ip, self.port):
                if resp == "[SUCCESS]":
                    return True
                elif resp == "[!username is not available]":
                    print("Username default")
                    continue


            else:
                print("Login another name")
                continue

    def send_usernameRoom(self, username, room):
        print("c send username room room = ", room, "username", username)

        msg = {
            "method": "LOGIN",
            "token": self.__token,
            "username": username,
            "room": room
        }

        msg = json.dumps(msg).encode('utf-8')

        self.socket.send(msg)

    def send_msg(self, content):
        print("c send msg", content)

        msg = {
            "method": "SEND",
            "token": self.__token,
            "username": self.__username,
            "msg": content
        }

        msg = json.dumps(msg).encode('utf-8')

        self.socket.send(msg)

    def user_logout(self):
        msg = {
            "method": "LOGOUT",
            "token": self.__token,
            "username": self.__username,
        }

        msg = json.dumps(msg).encode('utf-8')

        self.socket.send(msg)

        sys.exit()

    def listen(self):
        print("c listens, ")

        msgformat = {"method": "SEND",
                     "token": self.__token,
                     "username": self.__username
                     }

        self.socket.settimeout(1)

        while self.running:
            try:

                #
                msg = input(f"{self.__username} > ")
                if msg != "":
                    sendmsg = msgformat
                    sendmsg["msg"] = f"{self.__username} > " + msg
                    sendmsg = json.dumps(sendmsg).encode('utf-8')
                    self.socket.send(sendmsg)

                # data = self.socket.recv(1024)
                # data = data.decode('utf-8')
                # print(data)

            except KeyboardInterrupt:
                self.user_logout()
            except:
                pass

    def send(self):
        msgformat = {"method": "RECEIVE",
                     "token": self.__token,
                     "username": ""
                     }
        while self.running:
            try:
                data, addr = self.socket.recvfrom(1024)
                data = json.loads(data.decode('utf-8'))

                print("c received data", data )
                room_to_join = data["room"]
                user_to_join = data["username"]
                print("method", data["method"])
                sendmsg = msgformat
                sendmsg["username"] = user_to_join
                sendmsg["room"] = room_to_join
                # self.socket.send(sendmsg)
                if data["method"] == "room_request":
                    print("inside if")
                    answ = input("allow user to join room (yes/no):")
                    print("answer=", answ)
                    if answ == "yes":
                        sendmsg["msg"] = "yes"
                        print(sendmsg)
                        sendmsg = json.dumps(sendmsg).encode('utf-8')

                        self.socket.send(sendmsg)
                    else:
                        sendmsg["msg"] = "no"
                        sendmsg = json.dumps(sendmsg).encode('utf-8')
                        self.socket.send(sendmsg)
            except KeyboardInterrupt:
                self.stop()
            except socket.timeout:
                continue

            except Exception as e:
                a = (str(e))


def check_connection(addr, port):
    print("c check connection, addr = ", addr, "port", port)

    msg = '{"method":"CONNECT"}'
    # create udp socket
    socket_test = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    socket_test.sendto(msg.encode('utf-8'), (addr, port))
    oldTimeout = socket_test.gettimeout()
    socket_test.settimeout(10)
    try:
        token, address = socket_test.recvfrom(1024)
    except:
        print("Port Closed")
        return False

    socket_test.settimeout(oldTimeout)

    if (addr, port) == address:
        return token.decode('utf-8')
    else:
        print("Error server response. Please try again")


if __name__ == "__main__":
    token = ""
    ip = socket.gethostbyname(socket.gethostname())
    port = 5000
    while not token:
         token = check_connection(ip, port)

    client = Client(ip, port, token)
    client.start()
