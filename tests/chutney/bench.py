#!/usr/bin/env python3

import selectors
import socket
import socks
from time import time_ns

## config variables
port_to_bind = 2
client_to_run = 1
## TODO setting this to twice as much appear to make arti freeze
bench_len = 256 * 1024
buffer_len = 2048
verbose = True

## stream format:
# client -> server: |     id[8]    | data[bench_len]
# server -> client: | timestamp[8] | data[bench_len]

send_buffer = bytes([i%256 for i in range(buffer_len)])

sel = selectors.DefaultSelector()
int_to_buff = lambda i: int.to_bytes(i, 8, 'little')
buff_to_int = lambda b: int.from_bytes(b, 'little')

def printv(message):
    if verbose:
        print(message)

class ClientState:
    def __init__(self, port, ident, sock):
        self.port = port
        self.id = ident
        self.sock = sock
        self.state='start'
        self.side = 'client'
        # time
        self.connet_time = time_ns()
        self.start_time = 0
        self.one_way = 0
        self.rev_one_way = 0
        self.two_way = 0

        self.start_send = 0
        self.start_recv = 0
        self.stop_send = 0
        self.stop_recv = 0
        # buffer
        self.sent = 0
        self.received = 0
        self.inb = b''
        self.outb = b''

    def send(self):
        printv("client-" + str(self.id) + " (" + self.state + str(self.sent) + "/" + str(self.received) + "): sending")
        if len(self.outb) > 0:
            l = self.sock.send(self.outb)
            self.outb = self.outb[l:]
            if len(self.outb) > 0: return
        if self.state == 'start':
            self.send_hello()
            self.state = 'await_start'
        elif self.state == 'await_start':
            pass # nothing to send, we want to receive something
        elif self.state == 'bench':
            self.bench()
        elif self.state == 'await_bench' or self.state == 'end':
            pass
        else:
            raise Exception("unknow state")
    
    def send_hello(self):
        self.outb = int_to_buff(self.id)
        self.start_time = time_ns()
        l = self.sock.send(self.outb)
        self.outb = self.outb[l:]

    def bench(self):
        if self.sent == 0:
            self.start_send = time_ns()
        if self.sent < bench_len:
            to_send = min(buffer_len, bench_len - self.sent)
            self.sent += to_send
            self.outb = send_buffer[:to_send]
            l = self.sock.send(self.outb)
            self.outb = send_buffer[l:]
        else:
            self.state = 'await_bench'

    def receive(self):
        printv("client-" + str(self.id) + " (" + self.state + "): receive")
        if self.state == 'start' or self.state == 'await_start':
            self.recv_time()
        elif self.state == 'bench' or self.state == 'await_bench':
            self.recv_bench()
        elif self.state == 'end':
            pass
        else:
            raise Exception("unknow state")

    def recv_time(self):
        self.inb += self.sock.recv(8 - len(self.inb))
        if len(self.inb) == 8:
            now = time_ns()
            resp_timestamp = buff_to_int(self.inb)
            self.inb = b''
            self.one_way = resp_timestamp - self.start_time
            self.rev_one_way = now - resp_timestamp
            self.two_way = now - self.start_time
            self.state = 'bench'
            self.send()

    def recv_bench(self):
        if self.received == 0:
            self.start_recv = time_ns()
        self.inb += self.sock.recv(buffer_len)
        self.received += len(self.inb)
        self.inb = b''
        if self.received == bench_len:
            self.stop_recv = time_ns()
            self.state = 'end'
            sel.unregister(self.sock)
            self.sock.close()
            printv("client-" + str(self.id) + ": destroyed")


class ServerState:
    def __init__(self, sock):
        self.sock = sock

        self.state = 'wait_hello'
        self.side = 'server'
        self.client_id = -1
        self.inb = b''
        self.outb = b''

    def send(self):
        printv("server-" + str(self.client_id) + " (" + self.state + "): sending")
        if len(self.outb) > 0:
            l = self.sock.send(self.outb)
            self.outb = self.outb[l:]
            if len(self.outb) > 0: return
        if self.state == 'wait_hello':
            pass
        elif self.state == 'send_hello':
            self.send_hello()
        elif self.state == 'mirror':
            pass # queued when received, and sent just above
    
    def send_hello(self):
        self.outb = int_to_buff(time_ns())
        l = self.sock.send(self.outb)
        self.outb = self.outb[l:]
        self.state = 'mirror'

    def receive(self):
        printv("server-" + str(self.client_id) + " (" + self.state +"): receiving")
        if self.state == 'wait_hello':
            self.inb += self.sock.recv(8 - len(self.inb))
            if len(self.inb) == 8:
                self.client_id = buff_to_int(self.inb)
                self.state = 'send_hello'
        elif self.state == 'send_hello':
            pass
        elif self.state == 'mirror':
            if len(self.outb) < buffer_len:
                buff = self.sock.recv(buffer_len)
                self.outb += buff
                if len(self.outb) == 0:
                    printv("server-" + str(self.client_id) + ": destroyed")
                    sel.unregister(self.sock)
                    self.sock.close()
                    return


def bind():
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(('', 0))
    lsock.listen()
    lsock.setblocking(False)
    sel.register(lsock, selectors.EVENT_READ, data=None)
    return lsock.getsockname()[1]

def connect(port, ident):
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, 'localhost', 9150)
    #sock.set_proxy(socks.SOCKS5, 'localhost', 9009)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    sock.connect(('127.0.0.1', port))
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    data = ClientState(port, ident, sock)
    sel.register(sock, events, data=data)

def accept(sock):
    conn, _ = sock.accept()
    conn.setblocking(False)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    data = ServerState(conn)
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)

def socket_handle(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        data.receive()
    if mask & selectors.EVENT_WRITE:
        data.send()


binded = []
for i in range(port_to_bind):
    port = bind()
    binded.append(port)
    print("binded {}".format(port))

for i in range(client_to_run):
    connect(binded[i%port_to_bind], i)

while True:
    events = sel.select(timeout=0.5)
    for key, mask in events:
        if key.data is None:
            accept(key.fileobj)
        else:
            socket_handle(key, mask)
    if len(events) == 0:
        break
