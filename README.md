# switch-lan-play
[![Build status](https://github.com/spacemeowx2/switch-lan-play/workflows/Build/badge.svg)](https://github.com/spacemeowx2/switch-lan-play/actions?query=workflow%3ABuild)
[![Chat on discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg)](https://discord.gg/zEMCu5n)

English | [中文](README_zh.md)

Enjoy games with your friends as if you were on a LAN.

```
                     Internet
                        |
                  [SOCKS5 Proxy] (optional)
                        |
        ARP,IPv4        |          LAN Packets
Switch <-------->  PC(lan-play)  <-------------> Server
                                       UDP
```

# Usage

To play with your friends, both you and your friends need to run the lan-play client connecting to the **same** Server on your PCs, and set static IP on your Switch.

Your PC and Switch **must** be connected to the same router.

Visit [https://www.lan-play.com/](http://lan-play.com/install-switch) for instructions on how to set this up. See below for build instructions.

## SOCKS5 Proxy

lan-play --socks5-server-addr example.com:1080

Data sent to the relay server does not pass through the proxy.

# Build

## Debug or Release

`cmake -DCMAKE_BUILD_TYPE=Debug ..`
`cmake -DCMAKE_BUILD_TYPE=Release ..`

## Ubuntu / Debian

This project depends on libpcap, you can install libpcap0.8-dev on Ubuntu or Debian:

`sudo apt install libpcap0.8-dev git gcc g++ cmake`

Prepare cmake and gcc, then run the following:

```sh
mkdir build
cd build
cmake ..
make
```

## Windows

Use [MSYS2](http://www.msys2.org/) to compile.

```sh
pacman -Sy
pacman -S make \
    mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-gcc
```

To compile a 32-bit program:

```sh
pacman -S mingw-w64-i686-cmake \
    mingw-w64-i686-gcc
```

Open `MSYS2 MinGW 64-bit` or `MSYS2 MinGW 32-bit`.

```sh
mkdir build
cd build
cmake -G "MSYS Makefiles" ..
make
```

## Mac OS

```sh
brew install cmake
```

```sh
mkdir build
cd build
cmake ..
make
```

# Server

## Docker

`docker run -d -p 11451:11451/udp -p 11451:11451/tcp spacemeowx2/switch-lan-play`

## Node

```sh
git clone https://github.com/spacemeowx2/switch-lan-play
cd switch-lan-play/server
npm install
npm run build # build ts to js. run it again when code changes.
npm start
```

Use `--port` to pass the port parameter, or it will use `11451/udp` as the default.

Use `--simpleAuth` to pass authentication via username and password, or there will be no authentication.

Use `--httpAuth` to pass authentication via HTTP URL, or there will be no authentication.

Use `--jsonAuth` to pass authentication via JSON file, or there will be no authentication.

Example:

```sh
npm run build
npm start -- --port 10086 --simpleAuth username:password
```

Meanwhile, the monitor service will start on port `11451/tcp` by default. You can get the online client count via an HTTP request:

Request: `GET http://{YOUR_SERVER_IP}:11451/info`

Response: `{ "online": 42 }`


# Protocol

The protocol is quite simple at the moment, but additional fields may be added to calculate network quality (packet loss, ping), such as timestamp, seq_id, etc.

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
    PING = 2,
    IPV4_FRAG = 3
};
```

The server can read IP addresses from the payload and save the source IP -> LAN IP to a cache table. If the target IP address shown in the payload doesn't match the cache, the packet is broadcast to the entire room.
