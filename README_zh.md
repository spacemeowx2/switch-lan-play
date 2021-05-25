# switch-lan-play
[![Build status](https://github.com/spacemeowx2/switch-lan-play/workflows/Build/badge.svg)](https://github.com/spacemeowx2/switch-lan-play/actions?query=workflow%3ABuild)
[![Chat on discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg)](https://discord.gg/zEMCu5n)

[English](README.md) | 中文

Switch 虚拟局域网联机工具，能让你和远方的朋友像在局域网里一样联机。

```
                      互联网
                        |
                  [SOCKS5 代理] (可选)
                        |
        ARP,IPv4        |          局域网数据包
Switch <-------->  PC(本工具)  <-------------------> 服务器
                                     UDP协议
```

**注意:**
* 这个项目正处于早期开发阶段，通信协议可能会频繁变化。

# 用法

本工具分为服务端和客户端，你和朋友要在**各自的电脑**上运行 lan-play 客户端，并连接到**同一个**服务器，最后给 Switch 设置静态 IP 上网。

提示：电脑和 Switch 需要连接到同一个局域网。

## 1. Windows 客户端

1. 下载并安装最新的 [Npcap](https://nmap.org/npcap/#download)

2. 安装 Npcap 的时候记得选择 **Installed in WinPcap API-compatible mode** (以 WinPcap API 兼容模式安装) 

3. 从 [releases](https://github.com/spacemeowx2/switch-lan-play/releases) 下载最新版 `lan-play.exe` 客户端

4. 运行 `lan-play.exe`

然后程序会提示你输入服务器地址

```
--relay-server-addr is required (必须输入 --relay-server-addr 参数)
Input the relay server address [ domain/ip:port ]: (输入中继服务器地址)
```
你可以从这个网站里提供的公共中继服务器列表中选择一个
https://www.lan-play.com/

也可以到本项目的 Discord 群组里找人匹配
https://discord.gg/zEMCu5n

## 2. Switch 设置

0. 启动 lan-play Windows 客户端。

1. 打开 Switch 的 互联网 - 互联网设置 - 有线连接/连接WiFi - 更改设置 - 静态 IP。 IP 地址可以在 10.13.0.1 - 10.13.255.254 中任选，只要保证两位玩家的 IP 不同。

    <table>
        <tbody>
            <tr>
                <td>IP 地址</td>
                <td>10.13.?.?</td>
            </tr>
            <tr>
                <td>子网掩码</td>
                <td>255.255.0.0</td>
            </tr>
            <tr>
                <td>网关</td>
                <td>10.13.37.1</td>
            </tr>
        </tbody>
    </table>

2. 点击保存，这时候 Switch 会开始通过你的电脑上网。

3. 启动游戏，然后按 L+R+LStick 进入局域网联机模式。

## SOCKS5 代理

使用参数为 `lan-play --socks5-server-addr example.com:1080`

发送到中继服务器的数据不走代理。

# 编译

## Debug or Release

`cmake -DCMAKE_BUILD_TYPE=Debug ..`
`cmake -DCMAKE_BUILD_TYPE=Release ..`

## Ubuntu / Debian

本项目依赖 libpcap，你可以通过如下命令在 Ubuntu 或者 Debian 上安装 libpcap0.8-dev。

`sudo apt install libpcap0.8-dev git gcc g++ cmake`

系统装好 cmake, gcc，然后运行如下编译命令：

```sh
mkdir build
cd build
cmake ..
make
```

## Windows

使用 [MSYS2](http://www.msys2.org/) 来编译.

```sh
pacman -Sy
pacman -S make \
    mingw-w64-x86_64-cmake \
    mingw-w64-x86_64-gcc
```

如果要编译 32 位可执行文件：

```sh
pacman -S mingw-w64-i686-cmake \
    mingw-w64-i686-gcc
```

运行 `MSYS2 MinGW 64-bit` 或者 `MSYS2 MinGW 32-bit`.

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

# 服务端部署

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

添加 `--port` 参数来设置端口，否则使用默认端口 `11451/udp`

添加 `--simpleAuth` 参数来设置用户名和密码认证，默认没有认证

添加 `--httpAuth` 参数来设置 URL 认证，默认没有认证

添加 `--jsonAuth`参数来设置 JSON 文件认证，默认没有认证

示例：

```sh
npm run build
npm start -- --port 10086 --simpleAuth username:password
```

同时，状态监控会默认在 `11451/tcp` 端口上运行，你可以通过 HTTP 请求来获取在线客户端数量：

请求: `GET http://{服务器IP}:11451/info`

响应: `{ "online": 42 }`


# 协议

目前的通信协议十分简单，但以后会加入一些用于测量网络质量（丢包率、延迟）的参数，比如 timestamp 和 seq_id 等

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

服务器可以从有效负载中读取IP地址，并将源IP到局域网IP的映射关系保存到缓存表中；如果缓存表里查不到目标IP地址，则将此数据包广播到整个房间（目前一个服务器算一个房间）。
