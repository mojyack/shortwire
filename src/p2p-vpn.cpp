#include "common.hpp"
#include "macros/unwrap.hpp"
#include "p2p/ice-session-protocol.hpp"
#include "p2p/ice-session.hpp"
#include "p2p/ws/misc.hpp"
#include "util/charconv.hpp"
#include "util/event-fd.hpp"
#include "util/fd.hpp"

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

class Session : public p2p::ice::IceSession {
  private:
    FileDescriptor      dev;
    EventFileDescriptor stop;

    auto auth_peer(std::string_view peer_name) -> bool override;
    auto on_pad_created() -> void override;
    auto on_disconnected() -> void override;
    auto on_p2p_packet_received(std::span<const std::byte> payload) -> void override;

  public:
    auto start(p2p::wss::ServerLocation peer_linker, bool is_server) -> bool;
    auto run() -> bool;
};

auto Session::auth_peer(const std::string_view peer_name) -> bool {
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
        assert_n(data.size() >= 0);
        assert_n(size_t(write(dev.as_handle(), data.data(), data.size())) == data.size(), strerror(errno));
        return;
    }
    default:
        WARN("unknown packet type");
    }
}

auto Session::start(const p2p::wss::ServerLocation peer_linker, const bool is_server) -> bool {
    const auto local_addr = is_server ? to_inet_addr(192, 168, 2, 1) : to_inet_addr(192, 168, 2, 2);
    unwrap_ob(dev, setup_tap_dev(local_addr, 1300));
    this->dev = FileDescriptor(dev);

    assert_b(p2p::ice::IceSession::start({
        .peer_linker     = peer_linker,
        .stun_server     = {"stun.l.google.com", 19302},
        .pad_name        = is_server ? "server" : "client",
        .target_pad_name = is_server ? "" : "server",
    }));
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
        assert_b(len > 0);
        send_packet_p2p(p2p::proto::build_packet(proto::Type::EthernetFrame, 0, std::span<std::byte>{(std::byte*)buf.data(), size_t(len)}));
    }
    if(fds[1].revents & POLLIN) {
        return true;
    }
    goto loop;
}

auto run(const int argc, const char* const argv[]) -> bool {
    assert_b(argc >= 4);
    const auto peer_linker_addr = argv[1];
    unwrap_ob(peer_linker_port, from_chars<uint16_t>(argv[2]));
    const auto peer_linker = p2p::wss::ServerLocation{peer_linker_addr, peer_linker_port};

    const auto command = std::string_view(argv[3]);

    auto session = Session();
    ws::set_log_level(0b11);
    session.set_ws_debug_flags(false, false);
    if(command == "server") {
        assert_b(session.start(peer_linker, true));
        assert_b(session.run());
        return true;
    } else if(command == "client") {
        assert_b(session.start(peer_linker, false));
        assert_b(session.run());
        return true;
    } else {
        assert_b(false, "unknown command");
    }
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    return run(argc, argv) ? 0 : 1;
}
