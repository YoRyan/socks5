#!/usr/bin/env python3

import ipaddress as ip
import logging
import select
import socket
import struct
from socketserver import ForkingTCPServer, StreamRequestHandler

logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5


class SocksProxy(StreamRequestHandler):
    def handle(self):
        logging.info('Accepting connection from %s:%s' % self.client_address[:2])

        # greeting header
        # read and unpack 2 bytes from a client
        header = self.connection.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        # socks 5
        assert version == SOCKS_VERSION

        # get available methods
        methods = self.get_available_methods(nmethods)

        # send welcome message
        self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 0))

        # request
        version, cmd, _, address_type = struct.unpack("!BBBB", self.connection.recv(4))
        assert version == SOCKS_VERSION

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = ord(self.connection.recv(1)[0])
            address = self.connection.recv(domain_length)

        port = struct.unpack('!H', self.connection.recv(2))[0]

        # reply
        try:
            if cmd == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((address, port))
                bind_address = remote.getsockname()
                logging.info('Connected to %s %s' % (address, port))
            else:
                self.server.close_request(self.request)

            addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, address_type,
                                addr, port)

        except Exception as err:
            logging.error(err)
            # return connection refused error
            reply = self.generate_failed_reply(address_type, 5)

        self.connection.sendall(reply)

        # establish data exchange
        if reply[1] == 0 and cmd == 1:
            self.exchange_loop(self.connection, remote)

        self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):

        while True:

            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break


class IPv6ForkingTCPServer(ForkingTCPServer):
    def server_bind(self):
        if isinstance(ip.ip_address(self.server_address[0]), ip.IPv6Address):
            self.socket = socket.socket(socket.AF_INET6, self.socket_type)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ForkingTCPServer.server_bind(self)


if __name__ == '__main__':
    with IPv6ForkingTCPServer(('::1', 9011), SocksProxy) as server:
        server.serve_forever()
