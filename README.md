# switch-lan-play
[![Build status](https://drone.imspace.cn:444/api/badges/spacemeowx2/switch-lan-play/status.svg)](https://drone.imspace.cn:444/spacemeowx2/switch-lan-play)
[![Chat on discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg)](https://discord.gg/zEMCu5n)
[![Chat on telegram](https://img.shields.io/badge/chat-on%20telegram-blue.svg)](https://t.me/joinchat/CBl2pxJCT-NtEME6ip6v5g)

Make you and your friends play games like in a LAN.

```
Switch <--------> PC <---> Server
        ARP,IPv4      UDP
```

**NOTE:** This project is in an early stage. The protocol may change frequently.

# Build

This project depends on libpcap, you can install libpcap0.8-dev on Ubuntu or Debian:

`sudo apt install libpcap0.8-dev`

Prepare a cmake, gcc, and run like this:

```sh
mkdir build
cd build
cmake ..
make
```

# Server

```sh
cd server
npm install
npm run build # build ts to js, only run it when code changed.
npm start
```

# Protocol

The protocol is very simple now, but I'm going to add some fileds to calculate network quality(packet loss, ping), like timestamp, seq_id, etc.

```c
struct packet {
    uint8_t type;
    uint8_t payload[packet_len - 1];
};
```

```c
enum type {
    KEEPALIVE = 0,
    IPV4 = 1,
};
```

The server can read IP addresses from payload and save source IP -> LAN IP to a cache table. If target ip address shown in payload doesn't hit the cache, broadcast this packet to the entire room(now a server is a room).
