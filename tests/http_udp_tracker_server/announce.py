# send announce url with hash info
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
info_hash = bytes.fromhex("0123456789abcdef0123456789abcdef01234567") # 20 bytes hex
peer_id = b"-PC0001-123456789012"[:20].ljust(20,b'\0')
port = 6881
flags = 1
pkt = b'\x01' + info_hash + peer_id + (port).to_bytes(2,'big') + bytes([flags])
s.sendto(pkt, ("127.0.0.1", 9000))
print(s.recv(1024))
