#include "proxy.hpp"
#include "proxy_common.hpp"
#include "helper.h"
#include "gateway.h"
#include "packet.h"
#include "ipv4/ipv4.h"
#include <assert.h>
#include <base/llog.h>
#include <uvw.hpp>
#include <unordered_map>
#include <cstring>
#include <chrono>

namespace slp {
namespace detail{

class DirectProxyUdp {
    protected:
        std::shared_ptr<uvw::UDPHandle> udp;
        time_t expire_at;
        uint8_t src[4];
        uint16_t srcport;
        struct packet_ctx *p;
    public:
        DirectProxyUdp(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *p) : p(p) {
            udp = loop->resource<uvw::UDPHandle>();
        }
        ~DirectProxyUdp() {
            udp->close();
        }
        void init(const uint8_t src[4], const uint16_t srcport, const uint8_t dst[4], const uint16_t dstport) {
            CPY_IPV4(this->src, src);
            this->srcport = srcport;
            udp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &e, uvw::UDPHandle &) {
                LLOG(LLOG_ERROR, "DirectProxyUdp Error: %d %s", e.code(), e.what());
            });
            udp->on<uvw::UDPDataEvent>([this](const uvw::UDPDataEvent &e, uvw::UDPHandle &) {
                struct payload part = {(const u_char *)(e.data.get()), static_cast<uint16_t>(e.length), NULL};

                struct sockaddr_in addr_in;
                uvw::details::IpTraits<uvw::IPv4>::addrFunc(e.sender.ip.data(), e.sender.port, &addr_in);
                const void *from_ip = &addr_in.sin_addr;
                uint16_t from_port = ntohs(addr_in.sin_port);

                int ret = send_udp_ex(p, from_ip, from_port, this->src, this->srcport, &part);
                if (ret != 0) {
                    LLOG(LLOG_ERROR, "proxy_udp_recv_cb %d", ret);
                }
                this->visit();
            });
            udp->recv();
            this->visit();
        }
        void visit() {
            time_t now = time(NULL);
            expire_at = now + PROXY_UDP_TABLE_TTL;
        }
        bool isExpire() {
            time_t now = time(NULL);
            return expire_at < now;
        }
        void send(const sockaddr &addr, const void *dat, unsigned int len) {
            std::unique_ptr<char[]> data{new char[len]};
            std::memcpy(data.get(), dat, len);
            udp->send(addr, std::move(data), len);
            visit();
        }
};

class DirectProxyTcp : public IProxyTcp {
    protected:
        std::shared_ptr<uvw::TCPHandle> tcp;
    public:
        DirectProxyTcp(std::shared_ptr<uvw::Loop> loop) {
            tcp = loop->resource<uvw::TCPHandle>();
        }
        ~DirectProxyTcp() {
            tcp->close();
        }
        virtual void connect(const sockaddr &addr) override {
            tcp->connect(addr);
        }
        virtual void stop() override {
            tcp->stop();
        }
        virtual void read() override {
            tcp->read();
        }
        virtual void write(char *data, unsigned int len) override {
            tcp->write(data, len);
        }
        virtual void write(std::unique_ptr<char []> data, unsigned int len) override {
            tcp->write(std::move(data), len);
        }
        virtual void close() override {
            tcp->close();
        }
        virtual void onData(onDataCallback f) override {
            tcp->on<uvw::DataEvent>([f](uvw::DataEvent &e, uvw::TCPHandle &) {
                f(e);
            });
        }
        virtual void onWrite(onWriteCallback f) override {
            tcp->on<uvw::WriteEvent>([f](uvw::WriteEvent &e, uvw::TCPHandle &) {
                f(e);
            });
        }
        virtual void onConnect(onConnectCallback f) override {
            tcp->on<uvw::ConnectEvent>([f](uvw::ConnectEvent &e, uvw::TCPHandle &) {
                f(e);
            });
        }
        virtual void onClose(onCloseCallback f) override {
            tcp->on<uvw::EndEvent>([f](uvw::EndEvent &e, uvw::TCPHandle &) {
                auto err = uvw::ErrorEvent{0};
                f(err);
            });
            tcp->on<uvw::ErrorEvent>([f](uvw::ErrorEvent &e, uvw::TCPHandle &) {
                f(e);
            });
        }
};

using DirectProxyBase = ProxyBase<DirectProxyTcp, DirectProxyUdp>;
class DirectProxy : public DirectProxyBase {
    public:
        DirectProxy(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx) : DirectProxyBase(loop, packet_ctx) {}
        ~DirectProxy() {}
        virtual std::shared_ptr<IProxyTcp> newTcp() override {
            return std::make_shared<DirectProxyTcp>(loop);
        }
        virtual std::shared_ptr<DirectProxyUdp> newUdp() override {
            return std::make_shared<DirectProxyUdp>(loop, packet_ctx);
        }
};

}
}

namespace slp {

std::shared_ptr<IProxy> IProxy::initDirect(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx) {
    // TODO: use uvw::Loop
    return std::make_shared<detail::DirectProxy>(loop, packet_ctx);
}

}
