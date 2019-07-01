#pragma once

#include <vector>
#include <memory>

class BufferList {
    protected:
        std::vector<std::unique_ptr<char[]>> list;
        std::vector<unsigned int> sizeList;
        unsigned int totalSize;
        unsigned int offset;
        char get(const unsigned int &k) {
            unsigned int left = 0;
            for (unsigned i = 0; i < sizeList.size(); i++) {
                auto len = sizeList[i];
                auto actId = k + offset;
                if (left + len >= actId) {
                    auto item = list[i].get();
                    return item[actId - left];
                }
                left += len;
            }
            throw "not found";
        }
    public:
        BufferList (): totalSize(0), offset(0) {}
        ~BufferList () {}
        unsigned int size() {
            return totalSize - offset;
        }
        void clear() {
            list.clear();
            sizeList.clear();
            totalSize = 0;
            offset = 0;
        }
        void add(std::unique_ptr<char[]> buf, unsigned int size) {
            list.push_back(std::move(buf));
            sizeList.push_back(size);
            totalSize += size;
        }
        void advance(unsigned int n) {
            offset += n;
            while (offset >= sizeList[0]) {
                auto len = sizeList[0];

                list.erase(list.begin());
                sizeList.erase(sizeList.begin());

                totalSize -= len;
                offset -= len;
            }
        }
        void copyTo(unsigned int begin, char* dst, unsigned int n) {
            for (unsigned int i = 0; i < n; i++) {
                dst[i] = get(begin + i);
            }
        }
        char operator [](const unsigned int &k) {
            return get(k);
        }
};
