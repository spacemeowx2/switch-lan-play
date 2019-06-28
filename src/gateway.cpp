#include "proxy.hpp"
#include <uv_lwip.hpp>
#include <base/llog.h>
#include <functional>
#include <memory>
#include "gateway.h"
#include "helper.h"
#include "packet.h"
#include "ipv4/ipv4.h"


namespace slp {

class TcpConnection: public lwip::IConnection {
    protected:
        std::shared_ptr<IProxyTcp> ptcp;
        bool closing;
    public:
        TcpConnection(std::shared_ptr<lwip::UvLwipBase> lwip, std::shared_ptr<IProxyTcp> ptcp) : lwip::IConnection(lwip), ptcp(ptcp), closing(false) {
        }
        virtual void onConnection() override {
            LLOG(LLOG_DEBUG, "TcpConnection::onConnection");

            this->ptcp->onData([this](uvw::DataEvent &e) {
                ptcp->stop();
                this->write(std::move(e.data), e.length);
            });
            this->ptcp->onWrite([this](uvw::WriteEvent &e) {
                this->read();
            });
            this->ptcp->onClose([&](uvw::ErrorEvent &e) {
                LLOG(LLOG_DEBUG, "ptcp->onClose %d %s", e.code(), e.what());
                this->kill();
            });

            this->ptcp->onConnect([&](uvw::ConnectEvent &e) {
                LLOG(LLOG_DEBUG, "ptcp->onConnect");
                ptcp->read();
                this->read();
            });
            sockaddr_in addr = this->getLocalAddr();
            this->ptcp->connect(*reinterpret_cast<sockaddr*>(&addr));
        };
        virtual void onData(std::unique_ptr<char []> data, unsigned int len) override {
            this->stop();
            ptcp->write(std::move(data), len);
        };
        virtual void onWrite() override {
            ptcp->read();
        }
        virtual void onClose() override {
            LLOG(LLOG_DEBUG, "lwip->onClose");
            this->kill();
        };
        virtual void onClosed() override {
            this->kill();
        }
        void kill() {
            if (!this->closing) {
                this->closing = true;
                ptcp->stop();
                this->stop();
                ptcp->close();
                this->close();
            }
        }
};
class SwitchFakeTcpConnection: public lwip::IConnection {
    protected:
    public:
        SwitchFakeTcpConnection(std::shared_ptr<lwip::UvLwipBase> lwip) : lwip::IConnection(lwip) {

        }
        virtual void onConnection() override {
            const char *fake_body = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Organization: Nintendo\r\n\r\nok";
            this->write(fake_body, strlen(fake_body));
        };
        virtual void onWrite() override {
            this->close();
        }
        virtual void onData(std::unique_ptr<char []> data, unsigned int len) override {
        };
        virtual void onClose() override {
        };
        virtual void onClosed() override {
        };
};

class UvLwip : public lwip::UvLwipBase {
    protected:
        std::shared_ptr<slp::IProxy> proxy;
        struct packet_ctx *packet_ctx;
        virtual int uvlOutput(void *buffer, uint32_t len) override {
            return lan_play_gateway_send_packet(this->packet_ctx, buffer, len);
        };
        virtual std::shared_ptr<lwip::IConnection> newConnection(std::shared_ptr<UvLwipBase> self) override {
            if (this->proxy) {
                return std::make_shared<TcpConnection>(shared_from_this(), this->proxy->newTcp());
            } else {
                return std::shared_ptr<lwip::IConnection>(nullptr);
            }
        };
    public:
        UvLwip(uv_loop_t *loop, struct packet_ctx *packet_ctx, std::shared_ptr<slp::IProxy> proxy)
            : lwip::UvLwipBase(loop), proxy(proxy), packet_ctx(packet_ctx) {
        }
};

class FakeInternetUvLwip : public lwip::UvLwipBase {
    protected:
        struct packet_ctx *packet_ctx;
        virtual int uvlOutput(void *buffer, uint32_t len) override {
            return lan_play_gateway_send_packet(this->packet_ctx, buffer, len);
        };
        virtual std::shared_ptr<lwip::IConnection> newConnection(std::shared_ptr<UvLwipBase> self) override {
            return std::make_shared<SwitchFakeTcpConnection>(shared_from_this());
        };
    public:
        FakeInternetUvLwip(uv_loop_t *loop, struct packet_ctx *packet_ctx) : lwip::UvLwipBase(loop), packet_ctx(packet_ctx) {
        }
};

}

struct gateway {
    protected:
        struct packet_ctx *packet_ctx;
        std::shared_ptr<slp::IProxy> proxy;
        std::shared_ptr<slp::lwip::UvLwipBase> uvlwip;
    public:
        gateway(struct packet_ctx *packet_ctx) : packet_ctx(packet_ctx) {}
        ~gateway() {
            LLOG(LLOG_DEBUG, "~gateway");
            uvlwip->release();
        }
        void setProxy(const struct sockaddr *socks5_proxy_addr, const char *username, const char *password) {
            if (socks5_proxy_addr) {
                this->proxy = slp::IProxy::initSocks5(uvw::Loop::getDefault(), packet_ctx, socks5_proxy_addr, username, password);
            } else {
                this->proxy = slp::IProxy::initDirect(uvw::Loop::getDefault(), packet_ctx);
            }
        }
        void initLwip(bool fake_internet) {
            if (fake_internet) {
                this->uvlwip = std::make_shared<slp::FakeInternetUvLwip>(packet_ctx->arg->loop, packet_ctx);
            } else {
                this->uvlwip = std::make_shared<slp::UvLwip>(packet_ctx->arg->loop, packet_ctx, this->proxy);
            }
        }
        int processUdp(const uint8_t *data, int data_len) {
            uint8_t ip_version = 0;
            if (data_len > 0) {
                ip_version = (data[0] >> 4);
            }

            if (ip_version == 4) {
                // ignore non-UDP packets
                if (data_len < IPV4_OFF_END || data[IPV4_OFF_PROTOCOL] != IPV4_PROTOCOL_UDP) {
                    return -1;
                }
                uint16_t ipv4_header_len = (data[0] & 0xF) * 4;
                const uint8_t *udp_base = data + ipv4_header_len;
                uint8_t src[4];
                uint8_t dst[4];
                uint16_t srcport;
                uint16_t dstport;
                const void *payload;
                uint16_t len;

                CPY_IPV4(src, data + IPV4_OFF_SRC);
                CPY_IPV4(dst, data + IPV4_OFF_DST);
                srcport = READ_NET16(udp_base, UDP_OFF_SRCPORT);
                dstport = READ_NET16(udp_base, UDP_OFF_DSTPORT);
                payload = udp_base + UDP_OFF_END;
                len = data_len - ipv4_header_len - UDP_OFF_END;

                this->proxy->udpSend(src, srcport, dst, dstport, payload, len);
                return 0;
            }

            return -1;
        }
        void onPacket(const uint8_t *data, int data_len) {
            if (this->processUdp(data, data_len) == 0) {
                return;
            }

            uv_buf_t b;

            b.base = (char *)data;
            b.len = data_len;

            this->uvlwip->input(b);
        }
};

int gateway_init(struct gateway **gw, struct packet_ctx *packet_ctx, bool fake_internet, struct sockaddr *socks5_proxy_addr, const char *username, const char *password) {
    *gw = new gateway(packet_ctx);
    (*gw)->setProxy(socks5_proxy_addr, username, password);
    (*gw)->initLwip(fake_internet);
    return 0;
}
int gateway_close(struct gateway *gateway) {
    delete gateway;
    return 0;
}

void gateway_on_packet(struct gateway *gateway, const uint8_t *data, int data_len) {
    data += ETHER_OFF_END;
    data_len -= ETHER_OFF_END;
    gateway->onPacket(data, data_len);
}
