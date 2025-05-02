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

struct CalibrationDone {
    constexpr static auto pt = net::PacketID(0x05);
};
} // namespace proto
