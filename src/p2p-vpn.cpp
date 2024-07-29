#include "args.hpp"
#include "common.hpp"
#include "macros/unwrap.hpp"
#include "p2p/ice-session-protocol.hpp"
#include "p2p/ice-session.hpp"
#include "p2p/ws/misc.hpp"
#include "util/event-fd.hpp"
#include "util/fd.hpp"
#include "util/misc.hpp"

namespace {
namespace proto {
struct Type {
    enum : uint16_t {
        EthernetFrame = ::p2p::ice::proto::Type::Limit,

        Limit,
    };
};

struct EthernetFrame : ::p2p::proto::Packet {
    // std::byte data[];
};
} // namespace proto

using Key = std::array<std::byte, 16>;

class Session : public p2p::ice::IceSession {
  private:
    Key                 key;
    FileDescriptor      dev;
    EventFileDescriptor stop;
    bool                ws_only;

    auto auth_peer(std::string_view peer_name, std::span<const std::byte> secret) -> bool override;
    auto on_pad_created() -> void override;
    auto on_disconnected() -> void override;
    auto on_p2p_packet_received(std::span<const std::byte> payload) -> void override;

  public:
    bool verbose = false;

    auto start(p2p::wss::ServerLocation peer_linker, bool is_server, bool ws_only) -> bool;
    auto run() -> bool;
    auto load_key(const char* key_path) -> bool;
};

auto calc_xor(std::byte* const a, const std::byte* const b, const size_t len) -> void {
    for(auto i = 0u; i < len; i += 1) {
        a[i] ^= b[i];
    }
}

auto Session::auth_peer(std::string_view peer_name, std::span<const std::byte> /*secret*/) -> bool {
    // we don't use this auth method
    return peer_name == "client";
}

auto Session::on_pad_created() -> void {
}

auto Session::on_disconnected() -> void {
    PRINT("session disconnected");
    stop.notify();
}

auto Session::on_p2p_packet_received(std::span<const std::byte> payload) -> void {
    unwrap_pn(header, p2p::proto::extract_header(payload));

    switch(header.type) {
    case proto::Type::EthernetFrame: {
        auto data = payload.subspan(sizeof(proto::EthernetFrame));
        if(verbose) {
            print(">>> ", data.size(), " bytes");
        }
        assert_n(data.size() >= 0);
        assert_n(size_t(write(dev.as_handle(), data.data(), data.size())) == data.size(), strerror(errno));
        return;
    }
    default:
        WARN("unknown packet type");
    }
}

auto Session::start(const p2p::wss::ServerLocation peer_linker, const bool is_server, const bool ws_only) -> bool {
    this->ws_only = ws_only;

    const auto local_addr = is_server ? to_inet_addr(192, 168, 2, 1) : to_inet_addr(192, 168, 2, 2);
    unwrap_ob(dev, setup_tap_dev(local_addr, ws_only ? 1500 : 1300));
    this->dev = FileDescriptor(dev);

    const auto params = p2p::plink::PeerLinkerSessionParams{
        .peer_linker     = peer_linker,
        .stun_server     = {"stun.l.google.com", 19302},
        .pad_name        = is_server ? "server" : "client",
        .target_pad_name = is_server ? "" : "server",
    };
    if(ws_only) {
        assert_b(p2p::ice::IceSession::start(params));
    } else {
        assert_b(p2p::plink::PeerLinkerSession::start(params));
    }
    return true;
}

auto Session::run() -> bool {
    auto buf = std::array<char, 1536>();
    auto fds = std::array{
        pollfd{.fd = dev.as_handle(), .events = POLLIN},
        pollfd{.fd = stop, .events = POLLIN},
    };
loop:
    assert_b(poll(fds.data(), fds.size(), -1) != -1);
    if(fds[0].revents & POLLIN) {
        const auto len = read(fds[0].fd, buf.data(), buf.size());
        if(verbose) {
            print("<<< ", len, " bytes");
        }
        assert_b(len > 0);
        const auto payload = std::span<std::byte>{(std::byte*)buf.data(), size_t(len)};
        if(ws_only) {
            send_packet_detached(
                proto::Type::EthernetFrame, [](uint32_t result) {
                    assert_n(result);
                },
                payload);
        } else {
            send_packet_p2p(p2p::proto::build_packet(proto::Type::EthernetFrame, 0, payload));
        }
    }
    if(fds[1].revents & POLLIN) {
        return true;
    }
    goto loop;
}

auto Session::load_key(const char* const key_path) -> bool {
    const auto key_r = read_binary(key_path);
    assert_b(key_r, key_r.as_error().cstr());
    const auto key_b = key_r.as_value();
    assert_b(key_b.size() == key.size());
    std::memcpy(key.data(), key_b.data(), key.size());
    return true;
}

auto run(const int argc, const char* const argv[]) -> bool {
    unwrap_ob(args, Args::parse(argc, argv));
    const auto peer_linker = p2p::wss::ServerLocation{args.peer_linker_addr, args.peer_linker_port};

    auto session    = Session();
    session.verbose = args.verbose;
    ws::set_log_level(0b11);
    session.set_ws_debug_flags(false, false);
    assert_b(session.load_key(args.key_file));
    assert_b(session.start(peer_linker, args.server, args.ws_only));
    assert_b(session.run());
    return true;
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    return run(argc, argv) ? 0 : 1;
}
