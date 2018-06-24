#!/usr/bin/env python3

import ssl
import socket
import struct
import sys

import dpkt

def set_icmp6_checksum(ip):
    pseudohdr = struct.pack('!16s16sL3xB',
                            ip.src, ip.dst, ip.plen, ip.nxt)
    ip.data.sum = 0
    ip.data.sum = dpkt.dpkt.in_cksum(pseudohdr + bytes(ip.data))

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

class Router(object):

    def __init__(self, host='localhost', port=4443):
        self.host = host
        self.port = port

    def start(self):
        address = (self.host, self.port)

        print('Listening up on {}:{}'.format(*address))

        self._sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self._sock.bind(address)
        self._sock.listen(1)

        try:
            while True:
                print('Waiting for connection')
                sock, address = self._sock.accept()

                print('Connection from {}:{}'.format(*address))
                try:
                    Connection(sock).start()
                except:
                    pass
        finally:
            self._sock.close()

class Connection(object):

    def __init__(self, sock):
        ctx = ssl.SSLContext(ssl.CERT_REQUIRED)
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1
        ctx.options |= ssl.OP_NO_TLSv1_1
        ctx.load_cert_chain(certfile="router.crt.pem",
                                 keyfile="router.key.pem")

        try:
            self._sock = ctx.wrap_socket(sock,
                                         server_side=True)
        except Exception as e:
            print(e)
            raise

    def start(self):
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
            self._sock.shutdown(socket.SHUT_RDWR)
            self._sock.close()

    def recv_packet(self):
        hdr = self._sock.recv(2)
        if not hdr:
            return None

        (size,) = struct.unpack('!H', hdr)
        pkt = self._sock.recv(size)
        if not pkt:
            return None

        ip = dpkt.ip6.IP6(pkt)
        print(ip)
        return ip

    def send_packet(self, ip):
        print(ip)
        buf = bytes(ip)
        self._sock.send(struct.pack('!H', len(buf)))
        self._sock.send(buf)

    def handle_packet(self, ip):
        self.handle_echo_request(ip)

    def handle_echo_request(self, ip):
        icmp = ip.data

        # transform request to response
        icmp.type = 129

        # fixup IP header
        ip.src, ip.dst = ip.dst, ip.src

        # fixup checksum
        set_icmp6_checksum(ip)

        self.send_packet(ip)

if __name__ == "__main__":
    router = Router()
    router.start()
