#pragma once
#include "args.hpp"
#include "p2p/net/common.hpp"

namespace proto {
// control packets
struct Success {
    constexpr static auto pt = net::PacketID(0x00);
};

struct Error {
    constexpr static auto pt = net::PacketID(0x01);
};

struct StartSignaling {
    constexpr static auto pt = net::PacketID(0x02);
};

struct Signaling {
    constexpr static auto pt = net::PacketID(0x03);

    SerdeFieldsBegin;
    net::BytesArray SerdeField(payload);
    SerdeFieldsEnd;
};

struct ServerParameters {
    constexpr static auto pt = net::PacketID(0x04);

    SerdeFieldsBegin;
    EncMethod SerdeField(enc);
    bool      SerdeField(tap);
    SerdeFieldsEnd;
};

// p2p packets
struct P2PPacketType {
    constexpr static auto Payload              = std::byte(0x00);
    constexpr static auto ConnectivityTest     = std::byte(0x01);
    constexpr static auto ConnectivityResponse = std::byte(0x02);
};
} // namespace proto
