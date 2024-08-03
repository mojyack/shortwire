#pragma once
#include <optional>

struct Args {
    const char* key_file = nullptr;
    const char* peer_linker_addr;
    uint16_t    peer_linker_port;
    uint8_t     subnet  = 2;
    bool        verbose = false;
    bool        server  = false;
    bool        ws_only = false;

    static auto parse(int argc, const char* const argv[]) -> std::optional<Args>;
};
