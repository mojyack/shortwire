#include <string_view>

#include "args.hpp"
#include "macros/unwrap.hpp"
#include "util/charconv.hpp"

namespace {
const auto usage = R"(usage: p2p-vpn (option)...
options:
    --peer-linker-addr HOSTNAME         peer-linker address
    --peer-linker-port PORT             peer-linker port number
    --key              FILE_PATH        path to encryption key
    --subnet           SUBNET           x of 192.168.x.(1,2)
    --role             server,client    role of this process
    --websocket-only                    do not use p2p connection
    -v                                  enable verbose output
    -h,--help                           print this help message
)";
}

auto Args::parse(const int argc, const char* const argv[]) -> std::optional<Args> {
    auto ret = Args();
    for(auto i = 1; i < argc; i += 1) {
        if(const auto str = std::string_view(argv[i]); str == "--key") {
            i += 1;
            assert_o(i < argc);
            ret.key_file = argv[i];
        } else if(str == "--peer-linker-addr") {
            i += 1;
            assert_o(i < argc);
            ret.peer_linker_addr = argv[i];
        } else if(str == "--peer-linker-port") {
            i += 1;
            assert_o(i < argc);
            unwrap_oo(value, from_chars<uint16_t>(argv[i]));
            ret.peer_linker_port = value;
        } else if(str == "--subnet") {
            i += 1;
            assert_o(i < argc);
            unwrap_oo(value, from_chars<uint8_t>(argv[i]));
            ret.subnet = value;
        } else if(str == "--role") {
            i += 1;
            assert_o(i < argc);
            if(const auto role = std::string_view(argv[i]); role == "server") {
                ret.server = true;
            } else if(role == "client") {
                ret.server = false;
            } else {
                assert_o(false, "invalid role");
            }
        } else if(str == "--websocket-only") {
            ret.ws_only = true;
        } else if(str == "-v") {
            ret.verbose = true;
        } else if(str == "-h" || str == "--help") {
            print(usage);
            exit(0);
        } else {
            assert_o(false, "unknown argument");
        }
    }

    assert_o(ret.peer_linker_addr != nullptr, "no peer-linker address given");
    assert_o(ret.peer_linker_port != 0, "no peer-linker port given");
    return ret;
}
