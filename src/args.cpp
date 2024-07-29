#include <string_view>

#include "args.hpp"
#include "macros/unwrap.hpp"
#include "util/charconv.hpp"

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
        } else {
            assert_o(false, "unknown argument");
        }
    }

    assert_o(ret.peer_linker_addr != nullptr);
    assert_o(ret.peer_linker_port != 0);
    return ret;
}
