#pragma once

#include <memory>
#include <stdint.h>
#include <uv.h>
#include <uvw.hpp>
#include <base/slp_addr.h>
#include "packet.h"

#define PROXY_UDP_TABLE_LEN 128
#define PROXY_UDP_TABLE_TTL 30 // 30sec

namespace slp {

class IProxyTcp {
    using Deleter = void(*)(char *);
    public:
        using onDataCallback = std::function<void(uvw::DataEvent &)>;
        using onWriteCallback = std::function<void(uvw::WriteEvent &)>;
        using onConnectCallback = std::function<void(uvw::ConnectEvent &)>;
        using onCloseCallback = std::function<void(uvw::ErrorEvent &)>;
        virtual void connect(const sockaddr &addr) = 0;
        virtual void stop() = 0;
        virtual void read() = 0;
        virtual void write(char *data, unsigned int len) = 0;
        virtual void write(std::unique_ptr<char []> data, unsigned int len) = 0;
        virtual void close() = 0;
        virtual void onData(onDataCallback f) = 0;
        virtual void onWrite(onWriteCallback f) = 0;
        virtual void onConnect(onConnectCallback f) = 0;
        virtual void onClose(onCloseCallback f) = 0;
        virtual ~IProxyTcp() {};
};

class IProxy {
    public:
        static std::shared_ptr<IProxy> initDirect(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx);
        static std::shared_ptr<IProxy> initSocks5(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx, const slp_addr_in *proxy_server, const char *username, const char *password);
        virtual std::shared_ptr<IProxyTcp> newTcp() = 0;
        virtual void udpSend(uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport, const void *data, uint16_t data_len) = 0;
        virtual ~IProxy() {};
};

}
