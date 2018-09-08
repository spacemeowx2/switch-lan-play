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
* The Internet part is WIP.

# Usage

To play with your friends, you and your friends should run lan-play connecting to the same Server on your PC, and set static IP on your Switch.

Your PC and Switch should be connected to the same router.

## Windows Client

1. Download and install WinPcap from https://www.winpcap.org/install/default.htm

2. Download `lan-play.exe` from https://github.com/spacemeowx2/switch-lan-play/releases

3. Run lan-play.exe with paramter `--relay-server-addr`. For example:

```sh
lan-play.exe --relay-server-addr example.com:11451
```

After that, you may see the list like below:

```
1. en0 (No description available)
        IP: [192.168.1.100]
2. p2p0 (No description available)
        IP: []
Enter the interface number (1-2):
```

Select the interface which is in the same LAN with your Switch.

## Switch

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

2. Click save. Press B. Switch may not be able to connect to the Internet and refuse to connect to this setting, but it doesn't matter.

3. Launch your game, hold L+R+LStick to enter lan-play mode, Switch will try to connect the no Internet setting. Host or join a game, enjoy!

## Server

```
git clone https://github.com/spacemeowx2/switch-lan-play.git
cd switch-lan-play/server
npm install
npm run build
npm run server
```

# Build

# Ubuntu / Debian

This project depends on libpcap, you can install libpcap0.8-dev on Ubuntu or Debian:

`sudo apt install libpcap0.8-dev`

Prepare a cmake, gcc, and run like this:

```sh
mkdir build
cd build
cmake ..
make
```

# Windows

Use [MSYS2](http://www.msys2.org/) to compile.

```sh
pacman -Sy
pacman -S mingw-w64-i686-gcc \
    mingw-w64-i686-cmake \
    mingw-w64-i686-make \
    mingw-w64-i686-libevent \
    cmake
```

Open `MSYS2 MinGW 32-bit`.

```sh
mkdir build
cd build
cmake -G "MSYS Makefiles" ..
make
```

# Server

```sh
cd server
npm install
npm run build # build ts to js, only run it when code changed.
npm start
```

The server will listen to port 11451/udp,

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
