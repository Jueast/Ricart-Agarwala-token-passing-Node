#!/usr/bin/python3
import socket
# import multiprocessing
import threading as th
import sys
import logging
import time
import json


def hstr(p):
    hostname, port = p
    return hostname + ':' + str(port)


def addClock(method):
    def wrapper(self, *args, **kwargs):
        self.time_lock.acquire()
        self.logical_time += 1
        self.time_lock.release()
        result = method(self, *args, **kwargs)
        return result
    return wrapper


def MutualExclusion(method):
    def wrapper(self, *args, **kwargs):
        if not self.hasToken:
            message = "/request"
            for addr in self.nodes:
                self.send(addr, message)
            while not self.hasToken:
                time.sleep(1)
        self.inUse = True
        self.data_lock.acquire()
        result = method(self, *args, **kwargs)
        self.data_lock.release()
        self.Token[hstr((self.address))] = self.logical_time
        self.inUse = False
        self.nodes_lock.acquire()
        for addr in self.nodes:
            if addr == self.address:
                continue
            if self.Req[hstr(addr)] > self.Token[hstr(addr)] and self.hasToken and not self.inUse:
                self.hasToken = False
                self.send(addr, "/token")
        self.nodes_lock.release()
        return result
    return wrapper


class Node(object):
    # Singleton.

    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, 'instance'):
            cls.instance = super(Node, cls).__new__(cls)
        return cls.instance

    def __init__(self, address, hasToken):

        self.logical_time = 0
        self.address =  address
        self.nodes = list()
        self.Token = dict([(hstr((self.address)), self.logical_time)])  # RA-alogrithm
        self.Req = dict([(hstr((self.address)), self.logical_time)])   # RA-alogrithm

        self.data = dict()  # critical data
        self.data_lock = th.BoundedSemaphore()
        self.nodes_lock = th.BoundedSemaphore()
        self.time_lock = th.BoundedSemaphore()
        self.hasToken = hasToken
        self.inUse = False

        # Logger part
        self.logger = logging.Logger("(%s, %d)$" % self.address)
        self.logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)
        self.logger.debug("LC %d: self.address: %s:%d" % (0, self.address[0], self.address[1]))

    def start(self):
        self.logger.info("LC %d: Start server" % self.logical_time)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(self.address)
        while True:
            line, addr = self.sock.recvfrom(4096)
            # self.logger.info("LC %d: Get information from %s:%d." % (self.logical_time, addr[0], addr[1]))
            process = th.Thread(target=self.handle, args=(line, addr))
            process.start()

    @addClock
    def send(self, addr, message):

        temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_address = (self.address[0], self.address[1] - 1)
        temp_sock.bind(send_address)
        message = hstr(self.address)+ "@" + str(self.logical_time) + "@" + message
        self.logger.info("LC %d: Send %s to %s:%d." % (self.logical_time,
                                                       message,
                                                       addr[0], addr[1]))
        temp_sock.sendto(message.encode(), addr)
        temp_sock.close()

    @MutualExclusion
    def init(self, addr):
        self.logger.info("LC %d: send initial info to %s:%d " % (self.logical_time,
                                                                 addr[0],
                                                                 addr[1]))
        message = "/init " + json.dumps([self.address] + self.nodes,
                                        separators=(',', ':'))
        message += " " + json.dumps(self.data, separators=(',', ':'))
        message += " " + json.dumps(self.Token, separators=(',', ':'))
        message += " " + json.dumps(self.Req, separators=(',', ':'))
        self.send(addr, message)

    @addClock
    def login(self, hostname, port):
        try:
            message = "/login " + "%s:%d" % self.address
            self.send((hostname, port), message)
        except Exception as e:
            print(e)
            self.logger.warning("LC %d: Log in failed in connection" % self.logical_time)
        finally:
            self.logger.info("LC %d: Closing loginning socket." % self.logical_time)

    @MutualExclusion
    @addClock
    def change_data(self, line):
        try:
            target = line[1]
            value = int(line[2])
            self.data[target] = value
            message = "/data " + target + " " + str(value)
            print (self.nodes)
            for addr in self.nodes:
                self.send(addr, message)
            self.logger.info("LC %d: data[%s] = %s " % (self.logical_time, target, str(value)))
        except Exception as e:
            print(e)
            return -1
        return value

    @addClock
    def get_data(self, line):
        target = line[1]
        r = self.data.get(target, 0)
        return r

    @addClock
    def logout(self, line):
        if self.hasToken:
            while self.inUse:
                time.sleep(1)    # temprory
            self.send(self.nodes[0], "/token")
        self.hasToken = False
        message = "/logout"
        for addr in self.nodes:
            self.send(addr, message)
        self.nodes = list()
        self.Token = dict([(hstr((self.address)), self.logical_time)])  # RA-alogrithm
        self.Req = dict([(hstr((self.address)), self.logical_time)])   # RA-alogrithm
        self.data = dict()  # critical data
        return "logout successfully."

    def get_login(self, msg_time, line, addr):
        hostname = line[1].split(':')[0]
        port = int(line[1].split(':')[1])
        login_addr = tuple((hostname, port))
        self.logger.info("LC %d: Get login from %s:%d" % (self.logical_time,
                                                          login_addr[0],
                                                          login_addr[1]))
        need_init = login_addr == addr
        message = ' '.join(line)
        if need_init:
            for addr in self.nodes:
                self.send(addr, message)
            self.init(login_addr)
        self.nodes_lock.acquire()
        self.nodes.append(login_addr)
        self.Token[hstr((login_addr))] = self.logical_time
        self.Req[hstr((login_addr))] = self.logical_time
        self.nodes_lock.release()

    def get_logout(self, msg_time, line, addr):
        self.logger.info("LC %d: Get logout from %s:%d" % (self.logical_time,
                                                           addr[0],
                                                           addr[1]))
        self.nodes_lock.acquire()
        self.nodes.remove(addr)
        self.nodes_lock.release()

    def get_data_change(self, msg_time, line, addr):
        # Must be direct change, not reposting!
        print(addr)
        self.Token[hstr((addr))] = max(self.Token[hstr((addr))], msg_time)
        target = line[1]
        value = int(line[2])
        self.logger.info("LC %d: Get data change: data[%s] = %s from %s:%d."
                         % (self.logical_time, target, str(value),
                            addr[0], addr[1]))
        self.data[target] = value

    def get_init(self, msg_time, line, addr):
        self.logger.info("LC %d: Get initial info." % (self.logical_time))
        self.nodes += [tuple(x) for x in json.loads(line[1])]
        self.data.update(dict(json.loads(line[2])))
        self.Token.update(dict(json.loads(line[3])))
        self.Req.update(dict(json.loads(line[4])))

    def error(self, msg_time, line, addr=None):
        self.logger.error("Wrong message: %s" % ' '.join(line))
        return "Wrong message: %s" % ' '.join(line)

    def get_request(self, msg_time, line, addr):
        self.logger.info("LC %d: Get request from %s:%d" % (self.logical_time,
                                                            addr[0],
                                                            addr[1]))
        self.Req[hstr((addr))] = max(msg_time, self.Req[hstr((addr))])
        if self.hasToken and not self.inUse:
            self.nodes_lock.acquire()
            for addr in self.nodes:
                if addr == self.address:
                    continue
                if self.Req[hstr((addr))] > self.Token[hstr((addr))] and self.hasToken and not self.inUse:
                    self.hasToken = False
                    self.send(addr, "/token")
            self.nodes_lock.release()
    def get_token(self, msg_time, line, addr):
        self.logger.info("LC %d: Get token from %s:%d" % (self.logical_time,
                                                            addr[0],
                                                            addr[1]))
        self.hasToken = True

    def handle(self, line, addr):
        l = line.decode().strip().split('@')
        p = l[0].split(":")
        recieve_addr = (p[0], int(p[1]))
        msg_time = int(l[1])
        self.time_lock.acquire()
        self.logical_time = max(msg_time, self.logical_time) + 1
        self.time_lock.release()
        line = l[2].split(' ')
        dispatch = {
            '/login': self.get_login,
            '/logout': self.get_logout,
            '/init': self.get_init,
            '/data': self.get_data_change,
            '/token': self.get_token,
            '/request': self.get_request
        }
        comm = dispatch.get(line[0], self.error)
        comm(msg_time, line, recieve_addr)

if __name__ == '__main__':
    def login_check(node, line):
        try:
            hostname, port = line.strip().split(':')
            node.login(hostname, int(port))
        except Exception as e:
            print(e)
            print("Invalid Login.")
            return -1
        return 0
    token = False
    if len(sys.argv) == 3:
        token = sys.argv[2] == '-t'
    p = sys.argv[1].split(':')
    address = (p[0], int(p[1]))
    node = Node(address, token)
    p = th.Thread(target=node.start)
    p.start()
    line = input("Please input the address of target node: (form: 'hostname:port')\n")
    login_check(node, line)
    while True:
        command = input("Please input your command: \n")
        line = command.strip().split(' ')
        dispatch = {
            '/login': lambda line: login_check(node, line),
            '/logout': node.logout,
            '/get_data': node.get_data,
            '/change_data': node.change_data,
            '/exit': lambda: sys.exit(0)
        }
        c = dispatch.get(line[0], lambda line: node.error(0, line))
        result = c(line)
        print("Command result: %s" % str(result))
        print("--------------------------------")
