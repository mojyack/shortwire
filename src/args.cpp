#include "args.hpp"
#include "macros/unwrap.hpp"
#include "util/argument-parser.hpp"
#include "util/pair-table.hpp"

namespace args {
const auto enc_method_str = make_pair_table<EncMethod, std::string_view>({
    {EncMethod::None, "none"},
    {EncMethod::AES, "aes"},
    {EncMethod::C20P1305, "chacha20-poly1305"},
});

template <>
auto from_string<EncMethod>(const CStr str) -> std::optional<EncMethod> {
    unwrap(m, enc_method_str.find(str));
    return m;
}

template <>
auto to_string<EncMethod>(const EncMethod& data) -> std::string {
    return std::string(*enc_method_str.find(data));
}
} // namespace args

auto parse_cidr(const char* const cidr) -> std::optional<std::array<uint32_t, 2>> {
    auto a = uint8_t(), b = uint8_t(), c = uint8_t(), d = uint8_t(), m = uint8_t();
    ensure(sscanf(cidr, "%hhu.%hhu.%hhu.%hhu/%hhu", &a, &b, &c, &d, &m) == 5, "invalid cidr");
    ensure(m <= 32, "invalid mask");
    const auto addr = uint32_t(a << 24 | b << 16 | c << 8 | d);
    const auto mask = uint32_t(0xffffffff << (32 - m));
    return std::array{addr, mask};
}

auto Args::parse(const int argc, const char* const argv[]) -> std::optional<Args> {
    auto cidr   = (const char*)(nullptr);
    auto args   = Args();
    auto parser = args::Parser<uint8_t, uint16_t, EncMethod>();
    parser.kwarg(&cidr, {"-c", "--cidr"}, {"CIDR", "address and subnet-mask of the virtual nic"});
    parser.kwarg(&args.username, {"-u", "--username"}, {"USERNAME", "name to identify you from other users"});
    parser.kwarg(&args.peer_linker_addr, {"-pa", "--peer-linker-addr"}, {"HOSTNAME", "peer-linker address"});
    parser.kwarg(&args.peer_linker_port, {"-pp", "--peer-linker-port"}, {"PORT", "peer-linker port number", args::State::DefaultValue});
    parser.kwarg(&args.peer_linker_user_cert_path, {"-pc", "--peer-linker-cert"}, {"FILE", "peer-linker user certificate", args::State::Initialized});
    parser.kwarg(&args.enc_method, {"-e", "--encryption-method"}, {"none|aes|chacha20-poly1305", "server-only: encryption method to use", args::State::DefaultValue});
    parser.kwarg(&args.key_file, {"-k", "--key"}, {"FILE", "shared key for encryption", args::State::Initialized});
    parser.kwarg(&args.server, {"-s", "--server"}, {"", "act as a server", args::State::Initialized});
    parser.kwarg(&args.tap, {"-t", "--tap"}, {"", "server-only: use tap device instead of tun", args::State::Initialized});
    parser.kwarg(&args.mtu, {"-m", "--mtu"}, {"MTU", "server-only: mtu of virtual nic", args::State::DefaultValue});
    parser.kwarg(&args.ws_only, {"-wo", "--websocket-only"}, {"", "server-only: do not use p2p connection", args::State::Initialized});
    parser.kwarg(&args.ws_only, {"-v"}, {"", "enable verbose output", args::State::Initialized});
    parser.kwarg(&args.help, {"-h", "--help"}, {.arg_desc = "print this help message", .state = args::State::Initialized, .no_error_check = true});
    if(!parser.parse(argc, argv) || args.help) {
        print("usage: p2p-vpn ", parser.get_help());
        exit(0);
    }
    unwrap(parsed_cidr, parse_cidr(cidr));
    args.address = parsed_cidr[0];
    args.mask    = parsed_cidr[1];
    ensure(!args.server || args.enc_method == EncMethod::None || args.key_file != nullptr, "encryption enabled, but no key file specified");
    ensure(!args.server || args.enc_method != EncMethod::None || args.key_file == nullptr, "key file specified, but no encryption method set");
    return args;
}
