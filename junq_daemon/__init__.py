import json
from socket import *
from junq_daemon.consts import *
from selectors import DefaultSelector, EVENT_READ
import logging
from time import time
from ipaddress import IPv6Address


class Daemon:
    def __init__(self, logger:logging.Logger) -> None:
        self.logger = logger
        self.logger.info("start")

        self.sel = DefaultSelector()
        self.pfds = []
        self.clients = []
        self.n_users = 0
        self.n_socks = 0

        self.running = True

        r = self.parse_conf()
        if r != 0: self.exit(r)

        r = self.prnt_u_config()
        if r != 0: self.exit(r)
    
    def yggsp_r_connect(self, sock, addr):
        sock.send(bytes([5,1,0]))
        b = sock.recv(2)
        try:
            if b[0] != 5 or b[1] != 0:
                sock.close()
                raise ConnectionError("Wrong proxy protocol")
            
            msg = bytes([5,1,0,4]) + addr + int(1109).to_bytes(2)
            sock.send(msg)

            """
            char sabuf[2];
            recv(sock, sabuf, 22, 0);
            if (sabuf[1]!=0)
            {
                return 1;
            }
            """
            b = sock.recv(2)
            if b[1] != 0:
                sock.close()
                raise ConnectionError("Can't connect to remote addr")
            return 0
        except ConnectionError as e:
            
            print(e, "Err")
            self.logger.error(e)
            return -1

    def check_ygg_proxy(self):
        users = self.config["users"]
        for i in users:
            ypa,ypp = i["ygg_proxy_addr"], i["ygg_proxy_port"]
            try:
                sock = create_connection((ypa,ypp), 5)
                sock.send(bytes([5,1,0]))
                b = sock.recv(2)
                if b[0] != 5 or b[1] != 0:
                    sock.close()
                    raise ConnectionError("Wrong proxy protocol")
                sock.close()
            except ConnectionError as e:
                print("Err connection user", i["login"])
                raise e

    def handle_connection(self, i_sock: int):
        sock = self.pfds[i_sock]
        sid = self.pfds.index(sock)

        cl_sock, addr = sock.accept()
        self.sel.register(cl_sock, EVENT_READ, 1)
        self.clients.append({"socket": cl_sock, "addr": addr[0], "auth": False, "dest": sid, "step": 0})
        self.n_socks += 1
        self.pfds.append(cl_sock)

        self.logger.info(f"connected {self.clients[-1]}")
        print(f"connected {addr}")

    def ygg_check(self, i, msg_len):
        buf = self.crecv(i, msg_len)
        if not buf: return
        if len(buf) == msg_len == 16:
            try:
                inet_ntoa(buf)
                self.clients[i-self.n_users]["addr"] = buf
                print("ygg connect")
            except:
                self.send_er(i)
        else:
            self.clients[i-self.n_users]["addr"] = bytes([0]*16)
            print("normal connect")
        self.send_ok(i)

    
    def unreg(self, i):
        self.sel.unregister(self.pfds[i])
        self.pfds.pop(i)
        self.clients.pop(i-self.n_users)
        self.n_socks -= 1

    def crecv(self, i: int, n: int):
        buf = self.pfds[i].recv(n)
        if buf == b"":
            self.unreg(i)
            return None
        return buf
    

    def send_ok(self, i):
        self.pfds[i].send(bytes([255,255,255,255]))

    def send_er(self, i):
        self.pfds[i].send(bytes([255,255,255,0]))

    def login(self, i, msg_len):
        buf = self.crecv(i, msg_len)
        if not buf: return

        login_l = int.from_bytes(buf[:BYTES_LOGIN_LEN])
        login_s = buf[BYTES_LOGIN_LEN:login_l+1]
        passw_l = int.from_bytes(buf[BYTES_LOGIN_LEN+login_l:BYTES_LOGIN_LEN+login_l+BYTES_PASSWORD_LEN])
        passw_s = buf[BYTES_LOGIN_LEN+login_l+BYTES_PASSWORD_LEN:BYTES_LOGIN_LEN+login_l+BYTES_PASSWORD_LEN+passw_l]

        dest = self.clients[i-self.n_users]["dest"]
        user = self.config["users"][dest]
        if user["login"].encode() == login_s and user["password"].encode() == passw_s:
            self.clients[i-self.n_users]["auth"] = True
            self.send_ok(i)
            print("login ok", login_s, passw_s)
            return
        self.send_er(i)
        print("логин хуйня", login_s, passw_s)
        return
    
    def write_msg_l(self, i, msg_len):
        print("write msg l")
        buf = self.crecv(i, msg_len)
        if not buf: return

        msg_l = int.from_bytes(buf[:BYTES_MSG_LEN])
        msg_b = buf[BYTES_MSG_LEN-1:BYTES_MSG_LEN+msg_l]

        dest = self.clients[i-self.n_users]["dest"]
        msgs = self.config["users"][dest]["messages"]
        cid = self.config["users"][dest]["current_id"]
        lid = cid%SAVED_MESSAGES_N
        if lid < SAVED_MESSAGES_N:
            msgs.append({"msg": msg_b, "time": int(time()), "sender_addr":self.clients[i-self.n_users]["addr"], "id":cid})
        else:
            msgs[lid] = {"msg": msg_b, "time": int(time()), "sender_addr":self.clients[i-self.n_users]["addr"], "id":cid}
        self.config["users"][dest]["current_id"] += 1
        print("msg: ", msg_b)
        self.send_ok(i)

    def get_messages(self, i, msg_len):
        print("get msgs")
        buf = self.crecv(i, msg_len)
        if not buf: return
        if len(buf) == 6:
            count = int.from_bytes(buf[:2])
            offset = int.from_bytes(buf[2:4+2])

            dest = self.clients[i-self.n_users]["dest"]
            print(self.config["users"][dest]["current_id"] - SAVED_MESSAGES_N)
            # if (self.config["users"][dest]["current_id"] - SAVED_MESSAGES_N) <= offset:
            if offset <= self.config["users"][dest]["current_id"]:
                msgs = self.config["users"][dest]["messages"]

                if offset+count < self.config["users"][dest]["current_id"]:
                    last = last = count
                else:
                    last = self.config["users"][dest]["current_id"]-offset
                self.send_ok(i)
                self.pfds[i].send(last.to_bytes(BYTES_NUM))
                rsock = self.pfds[i]
                for j in range(last):
                    mid = (offset+j)%SAVED_MESSAGES_N
                    mlen = len(msgs[mid]["msg"])
                    # msize = mlen + BYTES_TEXT_LEN + sizeof(sender_addr)+sizeof(jusers[user_id].messages[id].time)+sizeof(jusers[user_id].messages[id].id)
                    msize = mlen + BYTES_TEXT_LEN + 16 + 8 + 4

                    rsock.send(msize.to_bytes(BYTES_MSG_LEN, "little"))
                    rsock.send(mlen.to_bytes(BYTES_TEXT_LEN, "little"))
                    rsock.send(msgs[mid]["msg"])
                    rsock.send(msgs[mid]["sender_addr"])
                    rsock.send(msgs[mid]["time"].to_bytes(8,"little"))
                    rsock.send(msgs[mid]["id"].to_bytes(4, "little"))
            else:
                self.send_er(i)

    def write_msg_r(self, i, msg_len):
        print("write msg r")
        buf = self.crecv(i, msg_len)
        if not buf: return

        raddr = buf[:16]
        msg_l = int.from_bytes(buf[16:16+BYTES_MSG_LEN-1])
        msg = buf[16+BYTES_MSG_LEN-1:16+BYTES_MSG_LEN+msg_l]
        # print(msg_l, msg, IPv6Address(raddr))
        dest = self.clients[i-self.n_users]["dest"]
        ygpa,ygpp = self.config["users"][dest]["ygg_proxy_addr"], self.config["users"][dest]["ygg_proxy_port"]
        try:
            sock = create_connection((ygpa,ygpp), 5)
            if self.yggsp_r_connect(sock, raddr) == 0:
                msg = int(1).to_bytes(BYTES_CMD_LEN) + buf[16:]
                sock.send(len(msg).to_bytes(BYTES_MSG_LEN) + msg)
                if sock.recv(4) == bytes([255,255,255,255]):
                    self.send_ok(i)
                else:
                    self.send_er(i)
                return
        except ConnectionError as e:
                print("Err connection user", dest)
                self.logger.error(f"Err connection user {dest}")
        self.send_er(i)

    def handle_data(self, i: int):
        step = self.clients[i-self.n_users]["step"]

        buf = self.crecv(i, BYTES_MSG_LEN)
        if not buf: return
        msg_len = int.from_bytes(buf)

        match step:
            case 0: # just connected
                self.ygg_check(i, msg_len)
                self.clients[i-self.n_users]["step"] = 1
            case 1:
                r = self.crecv(i, BYTES_CMD_LEN)
                if not r: return
                cmd = int.from_bytes(r)
                match cmd:
                    case 0: # login
                        self.login(i, msg_len-BYTES_CMD_LEN)
                    case 1: # write msg local
                        self.write_msg_l(i, msg_len-BYTES_CMD_LEN)
                    case 2: # get messages
                        self.get_messages(i, msg_len-BYTES_CMD_LEN)
                    case 3: # ping
                        self.send_ok(i)
                    case 4:
                        self.write_msg_r(i, msg_len-BYTES_CMD_LEN)
                    case _:
                        ...

    def loop(self):

        while self.running and self.n_socks > 0:
            try:
                for key,mask in self.sel.select():
                    sock = key.fileobj
                    i = self.pfds.index(sock)
                    if type(sock) == socket:
                        match key.data:
                            case 0: # connect
                                self.handle_connection(i)
                            case _: # data
                                self.handle_data(i)
            except KeyboardInterrupt:
                self.exit(0)
            except Exception as e:
                print(e)
                self.logger.error(e)

    def create_server(self):
        try:
            for user in self.config.get("users"):
                sock = socket(AF_INET, SOCK_STREAM, 0)
                sock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
                sock.bind((self.config["sockets"]["listen"], user["socket_port"]))
                sock.listen(0)

                self.sel.register(sock, EVENT_READ, 0)
                self.pfds.append(sock)
                self.n_socks += 1

                self.logger.info(f"listening {user['login']} - {self.config['sockets']['listen']}:{user['socket_port']}")
            return 0
        except Exception as e:
            self.logger.error("Can't create server")
            raise e
        


    def prnt_u_config(self):
        users = self.config.get("users")
        if not type(users) == list:
            self.logger.error("Wrong config format 'users'")
        try:
            for user in users:
                print(f"{user['login']} - {self.config['sockets']['listen']}:{user['socket_port']}")
                self.n_users += 1
                user.update({"messages":[], "current_id": 0})
            return 0
        except:
            self.logger.error("Wrong config format 'users' or 'sockets.listening'")

    def exit(self, n):
        self.logger.info("exiting")
        if self.n_socks != 0:
            for i in self.pfds:
                i.close()
        exit(1)

    def parse_conf(self):
        try:
            self.config = json.load(open(CONFIG_PATH))
            self.logger.debug("parse config OK")
            return 0
        except:
            self.logger.error("can't parse config")
            return 1




