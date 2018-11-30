# switch-lan-play
[![Build status](https://drone.imspace.cn:444/api/badges/spacemeowx2/switch-lan-play/status.svg)](https://drone.imspace.cn:444/spacemeowx2/switch-lan-play)
[![Chat on discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg)](https://discord.gg/zEMCu5n)
[![Chat on telegram](https://img.shields.io/badge/chat-on%20telegram-blue.svg)](https://t.me/joinchat/CBl2pxJCT-NtEME6ip6v5g)

Make you and your friends play games like in a LAN.

```
                     Internet
                        |
                  [SOCKS5 Proxy] (optional)
                        |
        ARP,IPv4        |          LAN Packets
Switch <-------->  PC(lan-play)  <-------------> Server
                                       UDP
```

**NOTE:**
* This project is in an early stage. The protocol may change frequently.
* The proxy part is WIP.

# Usage

To play with your friends, you and your friends should run lan-play client connecting to the **same** Server on your PC, and set static IP on your Switch.

Your PC and Switch **must** be connected to the same router.

## 1. Windows Client

1. Download and install WinPcap from https://www.winpcap.org/install/default.htm

2. Download the latest `lan-play.exe` from https://github.com/spacemeowx2/switch-lan-play/releases

3. Run lan-play.exe with paramter `--relay-server-addr`. For example:

```sh
lan-play.exe --relay-server-addr example.com:11451
```

After that, you may see the list like below:

```
1. \Device\NPF_{538AED4A-7BC9-47D9-A1DD-3F8E0AD2D2B0} (Microsoft Corporation)
        IP: [10.0.75.1]
2. \Device\NPF_{A885EB2A-D362-4846-8554-E6F59A044EB9} (Intel(R) Ethernet Connection (2) I219-V)
        IP: [192.168.233.153]
Enter the interface number (1-2):
```

Select the interface which is in the same LAN with your Switch.

## 2. Switch

0. Make sure lan-play client is running.

1. Go to your Switch settings page, set the IP address to static. The IP address can be any from `10.13.0.1` to `10.13.255.254`, excepting `10.13.37.1`. But don't use the same IP address with your friend.

    <table>
        <tbody>
            <tr>
                <td>IP Address</td>
                <td>10.13.?.?</td>
            </tr>
            <tr>
                <td>Subnet Mask</td>
                <td>255.255.0.0</td>
            </tr>
            <tr>
                <td>Gateway</td>
                <td>10.13.37.1</td>
            </tr>
        </tbody>
    </table>

2. Click save. Your Switch now can access the Internet via your PC.

3. Launch your game, hold L+R+LStick to enter lan-play mode. Host or join a game, enjoy!

## Server

```
git clone https://github.com/spacemeowx2/switch-lan-play.git
cd switch-lan-play/server
npm install
npm run build
npm run server
```

# Build

## Debug or Release

`cmake -DCMAKE_BUILD_TYPE=Debug ..`
`cmake -DCMAKE_BUILD_TYPE=Release ..`

## Ubuntu / Debian

This project depends on libpcap and libuv, you can install libpcap0.8-dev and libuv1-dev on Ubuntu or Debian:

`sudo apt install libpcap0.8-dev libuv1-dev`

Prepare a cmake, gcc, and run like this:

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

To compile 32bit program:

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
brew install cmake libpcap libuv
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
npm run build # build ts to js. run it again when code changed.
npm start
```

The server will listen to port `11451/udp`.

Meanwhile the monitor service will be started on port `11451/tcp` by default, you can get online client count via HTTP request:

Request: `GET http://{YOUR_SERVER_IP}:11451/info`

Response: `{ "online": 42 }`


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
