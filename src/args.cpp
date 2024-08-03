#include "args.hpp"
#include "util/argument-parser.hpp"

auto Args::parse(const int argc, const char* const argv[]) -> std::optional<Args> {
    auto args   = Args();
    auto parser = args::Parser<uint8_t, uint16_t>();
    parser.kwarg(&args.peer_linker_addr, {"--peer-linker-addr"}, {"HOSTNAME", "peer-linker address"});
    parser.kwarg(&args.peer_linker_port, {"--peer-linker-port"}, {"PORT", "peer-linker port number"});
    parser.kwarg(&args.key_file, {"--key"}, {"FILE_PATH", "enable encryption using the key", args::State::Initialized});
    parser.kwarg(&args.subnet, {"--subnet"}, {"SUBNET", "x of 192.168.x.(1,2)", args::State::DefaultValue});
    parser.kwarg(&args.server, {"--server"}, {"", "act as a server", args::State::Initialized});
    parser.kwarg(&args.ws_only, {"--websocket-only"}, {"", "do not use p2p connection", args::State::Initialized});
    parser.kwarg(&args.ws_only, {"-v"}, {"", "enable verbose output", args::State::Initialized});
    parser.kwarg(&args.help, {"-h", "--help"}, {.arg_desc = "print this help message", .state = args::State::Initialized, .no_error_check = true});
    if(!parser.parse(argc, argv) || args.help) {
        print("usage: p2p-vpn ", parser.get_help());
        exit(0);
    }
    return args;
}
