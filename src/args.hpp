#pragma once
#include <cstdint>
#include <optional>

#include "util/variant.hpp"

enum class EncMethod {
    None,
    AES,
    C20P1305,
};

struct PeerLinkerArgs {
    const char* addr;
    const char* user_cert_path = nullptr;
    uint16_t    port           = 8080;
};

struct DiscordArgs {
    const char* bot_token;
    uint64_t    channel_id;
};

using SignalingMethod = Variant<PeerLinkerArgs, DiscordArgs>;

struct Args {
    const char*     username = nullptr;
    const char*     key_file = nullptr;
    SignalingMethod sig_method;
    EncMethod       enc = EncMethod::None;
    uint32_t        address;
    uint32_t        mask;
    bool            server = false;
    bool            tap    = false;

    static auto parse(int argc, const char* const* argv) -> std::optional<Args>;
};
