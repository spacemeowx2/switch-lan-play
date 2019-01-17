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

namespace detail {

struct Socks5ServerConfig {
    struct sockaddr server;
    std::string username;
    std::string password;
};

class ProtocolUnpacker {
    protected:
        std::unique_ptr<const char[]> data;
        size_t offset;
    public:
        const size_t length;
    public:
        ProtocolUnpacker(std::unique_ptr<const char[]> &&data, size_t len) : data(std::move(data)), offset(0), length(len) {
        }
        ~ProtocolUnpacker() {}
        bool readInt8(int8_t &v) {
            return readAny<int8_t>(v);
        }
        bool readUint8(uint8_t &v) {
            return readAny<uint8_t>(v);
        }
        bool readUint16(uint16_t &v) {
            return readAny<uint16_t>(v);
        }
        bool readUint32(uint32_t &v) {
            return readAny<uint32_t>(v);
        }
        template<typename T>
        bool readAny(T &v) {
            if (offset + sizeof(T) > length) return false;
            std::memcpy(&v, data.get() + offset, sizeof(T));
            offset += sizeof(T);
            return true;
        }
        std::unique_ptr<const char[]> ptr() {
            return std::move(this->data);
        }
};

class ProtocolPacker {
    protected:
        std::unique_ptr<char[]> data;
        size_t offset;
    public:
        const size_t length;
    public:
        ProtocolPacker(size_t len) : data(std::unique_ptr<char[]>{new char[len]}), offset(0), length(len) {
        }
        ProtocolPacker(std::unique_ptr<char[]> &&data, size_t len) : data(std::move(data)), offset(0), length(len) {
        }
        ~ProtocolPacker() {}
        bool writeInt8(const int8_t v) {
            return writeAny<int8_t>(v);
        }
        bool writeUint8(const uint8_t v) {
            return writeAny<uint8_t>(v);
        }
        bool writeUint16(const uint16_t v) {
            return writeAny<uint16_t>(v);
        }
        bool readInt8(int8_t &v) {
            return readAny<int8_t>(v);
        }
        bool readUint8(uint8_t &v) {
            return readAny<uint8_t>(v);
        }
        bool readUint16(uint16_t &v) {
            return readAny<uint16_t>(v);
        }
        bool readUint32(uint32_t &v) {
            return readAny<uint32_t>(v);
        }
        bool writeRaw(const void *v, size_t size) {
            if (offset + size > length) return false;
            std::memcpy(data.get() + offset, v, size);
            offset += size;
            return true;
        }
        template<typename T>
        bool writeAny(const T &v) {
            if (offset + sizeof(T) > length) return false;
            std::memcpy(data.get() + offset, &v, sizeof(T));
            offset += sizeof(T);
            return true;
        }
        template<typename T>
        bool readAny(T &v) {
            if (offset + sizeof(T) > length) return false;
            std::memcpy(&v, data.get() + offset, sizeof(T));
            offset += sizeof(T);
            return true;
        }
        std::unique_ptr<char[]> ptr() {
            return std::move(this->data);
        }
};

class Socks5Protocol {
#define RASSERT(exp, err) if (!Assert((exp), (err))) return;
    public:
        enum class ErrCode {
            VersionMismatch,
            UnexpectMethod,
            UnexpectResponse,
            UnexpectAddressType,
            UnexpectLength
        };
        using ReadyCallback = std::function<void(std::shared_ptr<uvw::TCPHandle> tcp)>;
        using UDPReadyCallback = std::function<void(struct sockaddr addr)>;
        using ErrorCallback = std::function<void(ErrCode)>;
    protected:
        bool Assert(bool expression, ErrCode errCode) {
            if (!expression) {
                if (errorCallback) {
                    errorCallback(errCode);
                } else {
                    LLOG(LLOG_ERROR, "Socks5Protocol::Assert %d", errCode);
                }
                tcp->close();
            }
            return expression;
        }
        void auth(std::function<void()> cb) {
            tcp->connect(cfg.server);
            tcp->once<uvw::ConnectEvent>([this](uvw::ConnectEvent &e, uvw::TCPHandle &) {
                tcp->read();
                ProtocolPacker packer{3};
                packer.writeUint8(5);
                packer.writeUint8(1);
                packer.writeUint8(0);
                tcp->write(packer.ptr(), packer.length);
            });
            tcp->once<uvw::DataEvent>([cb, this](uvw::DataEvent &e, uvw::TCPHandle &) {
                RASSERT(e.length == 2, ErrCode::UnexpectLength);
                char version = e.data[0];
                char method = e.data[1];
                RASSERT(version == 5, ErrCode::VersionMismatch);
                RASSERT(method == 0, ErrCode::UnexpectMethod);
                cb();
            });
        }
        std::shared_ptr<uvw::TCPHandle> tcp;
        Socks5ServerConfig cfg;
        ReadyCallback readyCallback;
        UDPReadyCallback udpReadyCallback;
        ErrorCallback errorCallback;
    public:
        Socks5Protocol(std::shared_ptr<uvw::TCPHandle> tcp, Socks5ServerConfig &cfg) : tcp(tcp), cfg(cfg) {
        }
        ~Socks5Protocol() {
            tcp->close();
        }
        void associate(const sockaddr &saddr) {
            this->auth([this, saddr]() {
                const sockaddr_in *addr = reinterpret_cast<const sockaddr_in *>(&saddr);
                ProtocolPacker packer{10};
                packer.writeUint8(5);
                packer.writeUint8(3); // Associate
                packer.writeUint8(0);
                packer.writeUint8(1); // IPv4
                packer.writeAny(addr->sin_addr);
                packer.writeUint16(addr->sin_port);
                tcp->write(packer.ptr(), packer.length);
                tcp->once<uvw::DataEvent>([this](uvw::DataEvent &e, uvw::TCPHandle &) {
                    RASSERT(e.length == 10, ErrCode::UnexpectLength);
                    ProtocolPacker unpacker{std::move(e.data), e.length};
                    uint8_t ver, rep, rsv, atyp;
                    struct sockaddr_in addr;
                    unpacker.readUint8(ver);
                    unpacker.readUint8(rep);
                    unpacker.readUint8(rsv);
                    unpacker.readUint8(atyp);
                    unpacker.readAny(addr.sin_addr);
                    unpacker.readUint16(addr.sin_port);
                    RASSERT(ver == 5, ErrCode::VersionMismatch);
                    RASSERT(rep == 0, ErrCode::UnexpectResponse);
                    RASSERT(atyp == 1, ErrCode::UnexpectAddressType);
                    this->udpReadyCallback(*reinterpret_cast<sockaddr*>(&addr));
                });
            });
        }
        void connect(const sockaddr &saddr) {
            this->auth([saddr, this]() {
                const sockaddr_in *addr = reinterpret_cast<const sockaddr_in *>(&saddr);
                ProtocolPacker packer{10};
                packer.writeUint8(5);
                packer.writeUint8(1); // Connect
                packer.writeUint8(0);
                packer.writeUint8(1); // IPv4
                packer.writeAny(addr->sin_addr);
                packer.writeUint16(addr->sin_port);
                tcp->write(packer.ptr(), packer.length);
                tcp->once<uvw::DataEvent>([this](uvw::DataEvent &e, uvw::TCPHandle &) {
                    RASSERT(e.length == 10, ErrCode::UnexpectLength);
                    ProtocolPacker unpacker{std::move(e.data), e.length};
                    uint8_t ver, rep, rsv, atyp;
                    uint32_t bndaddr;
                    uint16_t bndport;
                    unpacker.readUint8(ver);
                    unpacker.readUint8(rep);
                    unpacker.readUint8(rsv);
                    unpacker.readUint8(atyp);
                    unpacker.readUint32(bndaddr);
                    unpacker.readUint16(bndport);
                    RASSERT(ver == 5, ErrCode::VersionMismatch);
                    RASSERT(rep == 0, ErrCode::UnexpectResponse);
                    RASSERT(atyp == 1, ErrCode::UnexpectAddressType);
                    tcp->stop();
                    this->readyCallback(this->tcp);
                });
            });
        }
        void onReady(ReadyCallback readyCallback) {
            this->readyCallback = readyCallback;
        }
        void onUDPReady(UDPReadyCallback cb) {
            this->udpReadyCallback = cb;
        }
        void onError(ErrorCallback errorCallback) {
            this->errorCallback = errorCallback;
        }
};

class Socks5ProxyUdp {
    const static int UDPHeaderSize = 10;
    protected:
        std::shared_ptr<uvw::TCPHandle> tcp;
        std::shared_ptr<uvw::UDPHandle> udp;
        time_t expire_at;
        std::shared_ptr<uvw::Loop> loop;
        struct packet_ctx *p;
        Socks5ServerConfig cfg;
        Socks5Protocol protocol;
        bool isReady;
        std::unique_ptr<char[]> waitingData;
        size_t waitingLength;
    public:
        ~Socks5ProxyUdp() {
            LLOG(LLOG_DEBUG, "~Socks5ProxyUdp");
            if (tcp) {
                tcp->close();
            }
            if (udp) {
                udp->close();
            }
        }
        Socks5ProxyUdp(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *p, Socks5ServerConfig &cfg)
            : loop(loop),
            p(p),
            cfg(cfg),
            protocol(loop->resource<uvw::TCPHandle>(), cfg),
            isReady(false)
        {
            LLOG(LLOG_DEBUG, "Socks5ProxyUdp");
        }
        void init(const uint8_t s[4], const uint16_t srcport, const uint8_t dst[4], const uint16_t dstport) {
            uint8_t src[4];
            CPY_IPV4(src, s);

            protocol.onError([](Socks5Protocol::ErrCode code) {
                LLOG(LLOG_DEBUG, "socks5 udp protocol error: %d", static_cast<int>(code));
            });
            protocol.onUDPReady([this](struct sockaddr addr) {
                this->isReady = true;
                this->udp->recv();
                this->visit();
                if (waitingData) {
                    this->udp->send(cfg.server, std::move(waitingData), waitingLength);
                }
            });
            struct sockaddr addr = {0};
            struct sockaddr_in *paddr = reinterpret_cast<decltype(paddr)>(&addr);
            paddr->sin_family = AF_INET;
            paddr->sin_addr.s_addr = htonl(INADDR_ANY);
            paddr->sin_port = htons(dstport);
            protocol.associate(addr);

            udp = loop->resource<uvw::UDPHandle>();
            udp->on<uvw::ErrorEvent>([](const uvw::ErrorEvent &e, uvw::UDPHandle &) {
                LLOG(LLOG_ERROR, "Socks5ProxyUdp Error: %d %s", e.code(), e.what());
            });
            udp->on<uvw::UDPDataEvent>([this, src, srcport](uvw::UDPDataEvent &e, uvw::UDPHandle &) {
                struct sockaddr_in addr_in;
                ProtocolUnpacker unpacker{std::move(e.data), e.length};
                uint16_t rev;
                uint8_t frag, atyp;
                unpacker.readUint16(rev);
                unpacker.readUint8(frag);
                unpacker.readUint8(atyp);
                if (atyp != 1) {
                    LLOG(LLOG_WARNING, "atyp: %d", atyp);
                    return;
                }
                unpacker.readAny(addr_in.sin_addr);
                unpacker.readUint16(addr_in.sin_port);

                auto data = unpacker.ptr();

                struct payload part = {(const u_char *)(data.get()) + UDPHeaderSize, static_cast<uint16_t>(e.length - UDPHeaderSize), NULL};

                const void *from_ip = &addr_in.sin_addr;
                uint16_t from_port = ntohs(addr_in.sin_port);

                int ret = send_udp_ex(p, from_ip, from_port, src, srcport, &part);
                if (ret != 0) {
                    LLOG(LLOG_ERROR, "proxy_udp_recv_cb %d", ret);
                }
                this->visit();
            });
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
            const sockaddr_in *paddr = reinterpret_cast<const sockaddr_in *>(&addr);

            ProtocolPacker packer{UDPHeaderSize + len};
            packer.writeUint16(0);
            packer.writeInt8(0);   // FRAG
            packer.writeInt8(1);   // IPv4
            packer.writeAny(paddr->sin_addr);
            packer.writeUint16(paddr->sin_port);
            packer.writeRaw(dat, len);

            if (isReady) {
                udp->send(cfg.server, packer.ptr(), packer.length);
            } else {
                this->waitingData = packer.ptr();
                this->waitingLength = packer.length;
            }
            visit();
        }
};

class Socks5ProxyTcp : public IProxyTcp {
    protected:
        std::shared_ptr<uvw::Loop> loop;
        std::shared_ptr<uvw::TCPHandle> tcp;
        Socks5Protocol protocol;
        IProxyTcp::onDataCallback dataCallback;
        IProxyTcp::onWriteCallback writeCallback;
        IProxyTcp::onConnectCallback connectCallback;
        IProxyTcp::onCloseCallback closeCallback;
    public:
        Socks5ProxyTcp(std::shared_ptr<uvw::Loop> loop, Socks5ServerConfig &cfg)
            : loop(loop),
            protocol(loop->resource<uvw::TCPHandle>(), cfg)
        {
            LLOG(LLOG_DEBUG, "Socks5ProxyTcp");
        }
        ~Socks5ProxyTcp() {
            LLOG(LLOG_DEBUG, "~Socks5ProxyTcp");
            if (tcp) {
                tcp->close();
            }
        }
        virtual void connect(const sockaddr &addr) override {
            protocol.onError([](Socks5Protocol::ErrCode code) {
                LLOG(LLOG_DEBUG, "protocol error: %d", static_cast<int>(code));
            });
            protocol.onReady([this](std::shared_ptr<uvw::TCPHandle> tcp) {
                this->tcp = tcp;
                tcp->on<uvw::DataEvent>([this](uvw::DataEvent &e, uvw::TCPHandle &) {
                    this->dataCallback(e);
                });
                tcp->on<uvw::WriteEvent>([this](uvw::WriteEvent &e, uvw::TCPHandle &) {
                    this->writeCallback(e);
                });
                tcp->on<uvw::EndEvent>([this](uvw::EndEvent &e, uvw::TCPHandle &) {
                    auto err = uvw::ErrorEvent{0};
                    this->closeCallback(err);
                });
                tcp->on<uvw::ErrorEvent>([this](uvw::ErrorEvent &e, uvw::TCPHandle &) {
                    this->closeCallback(e);
                });
                auto conn = uvw::ConnectEvent{};
                this->connectCallback(conn);
            });
            protocol.connect(addr);
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
            dataCallback = f;
        }
        virtual void onWrite(onWriteCallback f) override {
            writeCallback = f;
        }
        virtual void onConnect(onConnectCallback f) override {
            connectCallback = f;
        }
        virtual void onClose(onCloseCallback f) override {
            closeCallback = f;
        }
};

using Socks5ProxyBase = ProxyBase<Socks5ProxyTcp, Socks5ProxyUdp>;
class Socks5Proxy : public Socks5ProxyBase {
    protected:
        Socks5ServerConfig cfg;
    public:
        Socks5Proxy(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx, const struct sockaddr *proxy_server, const char *username, const char *password)
            : Socks5ProxyBase(loop, packet_ctx) {
            this->cfg = {*proxy_server, username ? username : "", password ? password : ""};
        }
        ~Socks5Proxy() {}
        virtual std::shared_ptr<IProxyTcp> newTcp() override {
            auto tcp = std::make_shared<Socks5ProxyTcp>(loop, this->cfg);
            return tcp;
        }
        virtual std::shared_ptr<Socks5ProxyUdp> newUdp() override {
            auto udp = std::make_shared<Socks5ProxyUdp>(loop, packet_ctx, this->cfg);
            return udp;
        }
};

}

std::shared_ptr<IProxy> IProxy::initSocks5(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx, const struct sockaddr *proxy_server, const char *username, const char *password) {
    // TODO: use uvw::Loop
    return std::make_shared<detail::Socks5Proxy>(loop, packet_ctx, proxy_server, username, password);
}

}
