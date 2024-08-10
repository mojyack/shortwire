# shortwire
minimal yet working VPN(virtual private network) daemon for Linux

# Features
- establishes P2P connection between two computers
- creates a virtual NIC and allows any applications(ssh,nfs,http-server,...) to transparently use P2P connection
- packets are encrypted of course

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
key length must be 16 bytes.  
`dd if=/dev/random of=key.bin bs=16 count=1`  
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
    --peer-linker-addr $PEER_LINKER \
    --peer-linker-cert var/user-cert.txt \
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
    --peer-linker-addr $PEER_LINKER \
    --peer-linker-cert var/user-cert.txt \
    --key key.bin \
sleep 5
done
```
if all goes well, a NIC named tunN with address 192.168.2.2 should appear.

## test
try `ping 192.168.2.2` on the server side or `ping 192.168.2.1` on the client side

