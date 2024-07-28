#include "common.hpp"
#include "macros/unwrap.hpp"
#include "p2p/peer-linker-protocol.hpp"
#include "p2p/peer-linker-session.hpp"
#include "p2p/ws/misc.hpp"
#include "util/event-fd.hpp"
#include "util/fd.hpp"

namespace {
namespace proto {
struct Type {
    enum : uint16_t {
        EthernetFrame = ::p2p::plink::proto::Type::Limit,

        Limit,
    };
};

struct EthernetFrame : ::p2p::proto::Packet {
    // std::byte data[];
};
} // namespace proto

class Session : public p2p::plink::PeerLinkerSession {
  private:
    FileDescriptor      dev;
    EventFileDescriptor stop;

    auto auth_peer(std::string_view peer_name) -> bool override;
    auto on_pad_created() -> void override;
    auto on_disconnected() -> void override;
    auto on_packet_received(std::span<const std::byte> payload) -> bool override;

  public:
    auto start(bool is_server) -> bool;
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

auto Session::on_packet_received(std::span<const std::byte> payload) -> bool {
    unwrap_pb(header, p2p::proto::extract_header(payload));

    switch(header.type) {
    case proto::Type::EthernetFrame: {
        auto data = payload.subspan(sizeof(proto::EthernetFrame));
        print(">>> ", data.size(), " bytes");
        assert_b(data.size() >= 0);
        assert_b(size_t(write(dev.as_handle(), data.data(), data.size())) == data.size(), strerror(errno));

        send_result(p2p::plink::proto::Type::Success, header.id);
        return true;
    }
    default:
        return p2p::plink::PeerLinkerSession::on_packet_received(payload);
    }
}

auto Session::start(const bool is_server) -> bool {
    const auto local_addr = is_server ? to_inet_addr(192, 168, 2, 1) : to_inet_addr(192, 168, 2, 2);
    unwrap_ob(dev, setup_tap_dev(local_addr));
    this->dev = FileDescriptor(dev);

    assert_b(p2p::plink::PeerLinkerSession::start({
        .peer_linker     = {"192.168.1.1", 8080},
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
        print("<<< ", len, " bytes");
        assert_b(len > 0);
        send_packet_detached(
            proto::Type::EthernetFrame, [](uint32_t result) {
                assert_n(result);
            },
            std::span<std::byte>{(std::byte*)buf.data(), size_t(len)});
    }
    if(fds[1].revents & POLLIN) {
        return true;
    }
    goto loop;
}

auto run(const int argc, const char* const argv[]) -> bool {
    assert_b(argc >= 2);
    const auto command = std::string_view(argv[1]);

    auto session = Session();
    ws::set_log_level(0x00);
    session.set_ws_debug_flags(false, true);
    if(command == "server") {
        assert_b(session.start(true));
        assert_b(session.run());
        return true;
    } else if(command == "client") {
        assert_b(session.start(false));
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
