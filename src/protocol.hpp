#pragma once
#include "args.hpp"
#include "p2p/net/common.hpp"

namespace proto {
struct Success {
    constexpr static auto pt = net::PacketID(0x00);
};

struct Error {
    constexpr static auto pt = net::PacketID(0x01);
};

struct Signaling {
    constexpr static auto pt = net::PacketID(0x02);

    SerdeFieldsBegin;
    net::BytesArray SerdeField(payload);
    SerdeFieldsEnd;
};

struct ServerParameters {
    constexpr static auto pt = net::PacketID(0x03);

    SerdeFieldsBegin;
    EncMethod SerdeField(enc);
    uint16_t  SerdeField(mtu);
    bool      SerdeField(tap);
    SerdeFieldsEnd;
};

struct Nop {
    constexpr static auto pt = net::PacketID(0x04);
};
} // namespace proto
