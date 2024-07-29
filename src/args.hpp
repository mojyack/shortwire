#pragma once
#include <optional>

struct Args {
    const char* key_file;
    const char* peer_linker_addr;
    uint16_t    peer_linker_port;
    bool        verbose;
    bool        server;
    bool        ws_only;

    static auto parse(int argc, const char* const argv[]) -> std::optional<Args>;
};
