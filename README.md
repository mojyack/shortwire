# shortwire
minimal yet working VPN(virtual private network) daemon for Linux

# Features
- establishes P2P connection between two computers
- creates a virtual NIC and allows any applications(ssh,nfs,http-server,...) to transparently use P2P connection
- packets are encrypted of course

# Performance
Throughput between two PCs(Ryzen Threadripper 2920X and Xeon E5-2696) in the same LAN, wired across a router, measured with iperf3.  
If the nodes are in the same LAN, shortwire detects this and only communicates within the LAN. Therefore, this result is not related to the internet speed of my environment, but represents pure software overhead.  

Native(no shortwire) throughput: 871 Mbps  
| Encryption method | Throughput(Mbps) |
| ---- | ---- |
| None | 601 |
| AES | 590 |
| ChaCha20-Poly1305 | 592 |

# Install
## dependencies
- libwebsockets
## build
```
# clone this repository
git clone --recursive https://github.com/mojyack/shortwire
cd shortwire
# build
meson setup build -Dbuildtype=release
ninja -C build
```

# Usage
## generate encryption key
key length must be 32 bytes.  
`dd if=/dev/random of=key.bin bs=32 count=1`  
place the same key on the server and client side.

## start server
work on server side:
```
USER=username   # anything that doesn't conflict with others
PEER_LINKER=ec2-15-168-12-186.ap-northeast-3.compute.amazonaws.com # my test server

sudo modprobe tun
while true; do
sudo build/shortwired \
    --username $USER \
    --cidr 192.168.2.1/24 \
    --peer-linker-addr $PEER_LINKER \
    --peer-linker-cert var/user-cert.txt \
    --encryption-method chacha20-poly1305 \
    --key key.bin \
    --server
sleep 5
done
```
if all goes well, a NIC named tunN with address 192.168.2.1 should appear.

## start client
work on client side:
```
sudo modprobe tun
while true; do
sudo build/shortwired \
    --username $USER \
    --cidr 192.168.2.2/24 \
    --peer-linker-addr $PEER_LINKER \
    --peer-linker-cert var/user-cert.txt \
    --encryption-method chacha20-poly1305 \
    --key key.bin \
sleep 5
done
```
if all goes well, a NIC named tunN with address 192.168.2.2 should appear.

## test
try `ping 192.168.2.2` on the server side or `ping 192.168.2.1` on the client side

