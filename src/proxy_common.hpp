#pragma once

#include <unordered_map>
#include <base/llog.h>
#include "proxy.hpp"
#include "helper.h"

namespace slp {

namespace detail {

struct UdpCacheKey {
    uint8_t src[4];
    uint16_t srcport;
    UdpCacheKey(const uint8_t src[4], const uint16_t srcport) : srcport(srcport) {
        CPY_IPV4(this->src, src);
    }
    bool operator==(const UdpCacheKey &other) const {
        return (CMP_IPV4(this->src, other.src)
            && this->srcport == other.srcport);
    }
};

struct UdpKeyHash {
    std::size_t operator() (const UdpCacheKey &t) const {
        return (*reinterpret_cast<const uint16_t*>(t.src + 2) << 16) + t.srcport;
    }
};

template<typename T, typename U>
class ProxyBase : public IProxy {
    protected:
        std::shared_ptr<U> getUdp(const uint8_t src[4], const uint16_t srcport, const uint8_t dst[4], const uint16_t dstport) {
            auto key = UdpCacheKey(src, srcport);
            auto search = cacheTable.find(key);
            if (search != cacheTable.end()) {
                auto item = search->second;
                if (item->isExpire()) {
                    item = this->newUdp();
                    item->init(src, srcport, dst, dstport);
                }
                cacheTable[key] = item;
                return item;
            } else {
                auto item = this->newUdp();
                item->init(src, srcport, dst, dstport);
                cacheTable[key] = item;
                return item;
            }
        }
        std::shared_ptr<uvw::Loop> loop;
        struct packet_ctx *packet_ctx;
        std::unordered_map<UdpCacheKey, std::shared_ptr<U>, UdpKeyHash> cacheTable;
        std::shared_ptr<uvw::TimerHandle> gc;
    public:
        ProxyBase(std::shared_ptr<uvw::Loop> loop, struct packet_ctx *packet_ctx): loop(loop), packet_ctx(packet_ctx) {
            gc = loop->resource<uvw::TimerHandle>();
            gc->on<uvw::TimerEvent>([&](const uvw::TimerEvent &, uvw::TimerHandle &) {
                for(auto it = cacheTable.begin(); it != cacheTable.end(); ) {
                    if (it->second->isExpire()) {
                        it = cacheTable.erase(it);
                    } else {
                        ++it;
                    }
                }
            });
            gc->start(std::chrono::milliseconds(0), std::chrono::seconds(10));
        }
        ~ProxyBase() {
            gc->close();
        }
        virtual std::shared_ptr<IProxyTcp> newTcp() override = 0;
        virtual std::shared_ptr<U> newUdp() = 0;
        virtual void udpSend(uint8_t src[4], uint16_t srcport, uint8_t dst[4], uint16_t dstport, const void *data, uint16_t data_len) override {
            auto item = getUdp(src, srcport, dst, dstport);
            struct sockaddr addr;
            struct sockaddr_in *addr_ptr = reinterpret_cast<sockaddr_in *>(&addr);

            addr_ptr->sin_family = AF_INET;
            CPY_IPV4(&addr_ptr->sin_addr, dst);
            addr_ptr->sin_port = htons(dstport);
            item->send(addr, data, data_len);
        }
};

}

}
