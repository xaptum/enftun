#!/usr/bin/env python3

import argparse
import ipaddress
import socket
import socketserver
import ssl
import struct
import sys

import dpkt

def set_icmp6_checksum(ip):
    pseudohdr = struct.pack('!16s16sL3xB',
                            ip.src, ip.dst, ip.plen, ip.nxt)
    ip.data.sum = 0
    ip.data.sum = dpkt.dpkt.in_cksum(pseudohdr + bytes(ip.data))

def set_icmp4_checksum(ip):
    ip.data.sum = 0
    ip.data.sum = dpkt.dpkt.in_cksum(bytes(ip.data))

def ip6_addr_str(addr):
    return socket.inet_ntop(socket.AF_INET6, addr)

def ip6_str(ip):
    fmt = "IP6 [{} => {}] (flow {:x}, hlim {}, nxt {}, plen {}), {}"
    return fmt.format(ip6_addr_str(ip.src),
                      ip6_addr_str(ip.dst),
                      ip.flow,
                      ip.hlim,
                      ip.nxt,
                      ip.plen,
                      str(ip.data))

def icmp6_str(icmp):
    fmt = "ICMP6 (code {}), "
    echo_fmt = "echo {}, seq {}"

    if icmp.type == 128:
        return (fmt + echo_fmt).format(icmp.code,
                                       "request",
                                       icmp.data.seq)
    elif icmp.type == 129:
        return (fmt + echo_fmt).format(icmp.code,
                                       "reply",
                                       icmp.data.seq)

dpkt.ip6.IP6.__str__ = lambda self: ip6_str(self)
dpkt.icmp6.ICMP6.__str__ = lambda self: icmp6_str(self)

def is6(host):
    try:
        addr = ipaddress.ip_address(host)
        return addr.version == 6
    except:
        return False

class Router(socketserver.ThreadingMixIn, socketserver.TCPServer):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.allow_reuse_address = True

        self.ssl_ctx = ssl.SSLContext()
        ## Doesn't seem to be a way to get Python ssl module to accept
        ## arbitrary self-signed certs.
        #self.ssl_ctx.verify_mode = ssl.CERT_REQUIRED
        self.ssl_ctx.options |= ssl.OP_NO_SSLv2
        self.ssl_ctx.options |= ssl.OP_NO_SSLv3
        self.ssl_ctx.options |= ssl.OP_NO_TLSv1
        self.ssl_ctx.options |= ssl.OP_NO_TLSv1_1
        self.ssl_ctx.load_cert_chain(certfile="router.crt.pem",
                                     keyfile="router.key.pem")

        self.conns = set()

    def server_activate(self):
        super().server_activate()
        print('Listening on {}:{}'.format(*self.server_address))

    def get_request(self):
        sock, peer = self.socket.accept()
        conn = self.ssl_ctx.wrap_socket(sock, server_side=True)
        return conn, peer

class Connection(socketserver.BaseRequestHandler):

    def setup(self):
        print('Connection from {}:{} opened.'.format(*self.client_address))
        self.server.conns.add(self)

    def finish(self):
        print('Connection from {}:{} closed.'.format(*self.client_address))
        self.server.conns.remove(self)

    def handle(self):
        try:
            while True:
                pkt = self.recv_packet()
                if not pkt:
                    break
                else:
                    self.handle_packet(pkt)
        except Exception as e:
            print(e)
        finally:
            self.request.shutdown(socket.SHUT_RDWR)
            self.request.close()

    def recv_packet(self):
        hdr = self.request.recv(2)
        if not hdr:
            return None

        (size,) = struct.unpack('!H', hdr)
        pkt = self.request.recv(size)
        if not pkt:
            return None

        vsn = (pkt[0] & 0xF0) >> 4
        ip = None
        if vsn == 4:
            ip = dpkt.ip.IP(pkt)
        elif vsn == 6:
            ip = dpkt.ip6.IP6(pkt)
        else:
            print("Unsupported packet type. Must be IPv4 or IPv6")

        print(ip)
        return ip

    def send_packet(self, ip):
        print(ip)
        body = bytes(ip)
        head = struct.pack('!H', len(body))
        buf = head + body
        self.request.send(buf)

    def handle_packet(self, ip):
        if isinstance(ip.data, dpkt.icmp.ICMP):
            self.handle_v4_echo_request(ip)
        elif isinstance(ip.data, dpkt.icmp6.ICMP6):
            self.handle_v6_echo_request(ip)
        else:
            self.forward(ip)

    def handle_v4_echo_request(self, ip):
        icmp = ip.data

        # transform request to response
        icmp.type = 0

        # fixup IP header
        ip.src, ip.dst = ip.dst, ip.src

        # fixup checksum
        set_icmp4_checksum(ip)

        self.send_packet(ip)

    def handle_v6_echo_request(self, ip):
        icmp = ip.data

        # transform request to response
        icmp.type = 129

        # fixup IP header
        ip.src, ip.dst = ip.dst, ip.src

        # fixup checksum
        set_icmp6_checksum(ip)

        self.send_packet(ip)

    def forward(self, ip):
        for conn in self.server.conns:
            if conn != self:
                conn.send_packet(ip)

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--bind",
                        help="set IP address to bind server to",
                        default="localhost")
    parser.add_argument("-p", "--port",
                        help="set TCP port to bind server to",
                        type=int, default=4443)
    args = parser.parse_args()

    router = Router((args.bind, args.port), Connection)
    router.serve_forever()
