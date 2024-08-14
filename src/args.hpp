#pragma once
#include <cstdint>
#include <optional>

enum class EncMethod {
    None,
    AES,
    C20P1305,
};

struct Args {
    const char* username                   = nullptr;
    const char* key_file                   = nullptr;
    const char* peer_linker_user_cert_path = nullptr;
    const char* peer_linker_addr;
    EncMethod   enc_method       = EncMethod::None;
    uint16_t    peer_linker_port = 8080;
    uint8_t     subnet           = 2;
    bool        verbose          = false;
    bool        server           = false;
    bool        ws_only          = false;
    bool        help             = false;

    static auto parse(int argc, const char* const argv[]) -> std::optional<Args>;
};
