#include <random>

#include "aes.hpp"
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
using Key = std::array<std::byte, 16>;

namespace proto {
struct Type {
    enum : uint16_t {
        EthernetFrame = ::p2p::ice::proto::Type::Limit,
        EncKey,

        Limit,
    };
};

struct EthernetFrame : ::p2p::proto::Packet {
    // std::byte data[];
};

struct EncKey : ::p2p::proto::Packet {
    aes::IV iv;
    Key     key;
};
} // namespace proto

struct EventKind {
    enum {
        EncKeyReceived = p2p::plink::EventKind::Limit,

        Limit,
    };
};

class Session : public p2p::ice::IceSession {
  private:
    aes::IV             iv;
    Key                 key;
    FileDescriptor      dev;
    EventFileDescriptor stop;
    bool                ws_only    = false;
    bool                verbose    = false;
    bool                key_loaded = false;

    auto auth_peer(std::string_view peer_name, std::span<const std::byte> secret) -> bool override;
    auto on_pad_created() -> void override;
    auto on_disconnected() -> void override;
    auto on_packet_received(std::span<const std::byte> payload) -> bool override;
    auto on_p2p_packet_received(std::span<const std::byte> payload) -> void override;

    auto load_key(const char* key_path) -> bool;
    auto process_received_ethernet_frame(std::span<const std::byte> data) -> bool;

  public:
    auto start(Args args) -> bool;
    auto run() -> bool;
};

auto calc_xor(std::byte* const a, const std::byte* const b, const size_t len) -> void {
    for(auto i = 0u; i < len; i += 1) {
        a[i] ^= b[i];
    }
}

auto generate_key() -> Key {
    static auto engine = std::mt19937((std::random_device())());

    auto nonce = Key();
    for(auto& b : nonce) {
        b = std::byte(engine());
    }
    return nonce;
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

auto Session::on_packet_received(const std::span<const std::byte> payload) -> bool {
    unwrap_pb(header, p2p::proto::extract_header(payload));

    switch(header.type) {
    case proto::Type::EncKey: {
        assert_b(key_loaded);
        unwrap_pb(packet, p2p::proto::extract_payload<proto::EncKey>(payload));

        iv = packet.iv;
        calc_xor(key.data(), packet.key.data(), key.size());
        if(verbose) {
            print("received session key");
        }
        events.invoke(EventKind::EncKeyReceived, p2p::no_id, p2p::no_value);

        send_result(::p2p::plink::proto::Type::Success, header.id);
        return true;
    }
    case proto::Type::EthernetFrame: {
        assert_b(process_received_ethernet_frame(payload.subspan(sizeof(proto::EthernetFrame))));
        send_result(p2p::plink::proto::Type::Success, header.id);
        return true;
    }
    default:
        if(ws_only) {
            return p2p::plink::PeerLinkerSession::on_packet_received(payload);
        } else {
            return p2p::ice::IceSession::on_packet_received(payload);
        }
    }
}

auto Session::on_p2p_packet_received(std::span<const std::byte> payload) -> void {
    unwrap_pn(header, p2p::proto::extract_header(payload));

    switch(header.type) {
    case proto::Type::EthernetFrame: {
        assert_n(process_received_ethernet_frame(payload.subspan(sizeof(proto::EthernetFrame))));
        return;
    }
    default:
        WARN("unknown packet type");
        return;
    }
}

auto Session::process_received_ethernet_frame(std::span<const std::byte> data) -> bool {
    if(verbose) {
        print(">>> ", data.size(), " bytes");
    }
    auto decrypted = std::vector<std::byte>();
    if(key_loaded) {
        unwrap_ob_mut(dec, aes::decrypt(key, iv, data));
        decrypted = std::move(dec);
        data      = decrypted;
    }
    assert_b(size_t(write(dev.as_handle(), data.data(), data.size())) == data.size(), strerror(errno));
    return true;
}

auto Session::start(Args args) -> bool {
    verbose = args.verbose;
    ws_only = args.ws_only;
    if(args.key_file != nullptr) {
        assert_b(load_key(args.key_file));
    }

    const auto local_addr = to_inet_addr(192, 168, args.subnet, args.server ? 1 : 2);
    unwrap_ob(dev, setup_tap_dev(local_addr, ws_only ? 1500 : 1300));
    this->dev = FileDescriptor(dev);

    struct Events {
        Event key;
    };
    auto events = std::shared_ptr<Events>(new Events());
    if(!args.server && key_loaded) {
        add_event_handler(EventKind::EncKeyReceived, [events](uint32_t) { events->key.notify(); });
    }
    const auto params = p2p::plink::PeerLinkerSessionParams{
        .peer_linker     = p2p::wss::ServerLocation{args.peer_linker_addr, args.peer_linker_port},
        .stun_server     = {"stun.l.google.com", 19302},
        .pad_name        = args.server ? "server" : "client",
        .target_pad_name = args.server ? "" : "server",
    };
    if(ws_only) {
        assert_b(p2p::plink::PeerLinkerSession::start(params));
    } else {
        assert_b(p2p::ice::IceSession::start(params));
    }

    if(!key_loaded) {
        warn("no private key provided\ncontinuing without encryption");
        return true;
    }

    if(args.server) {
        iv                     = generate_key();
        const auto session_key = generate_key();
        if(verbose) {
            print("sending session key");
        }
        assert_b(send_packet(proto::Type::EncKey, iv, session_key));
        calc_xor(key.data(), session_key.data(), key.size());
    } else {
        events->key.wait();
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
        auto payload   = std::span<std::byte>((std::byte*)buf.data(), size_t(len));
        auto encrypted = std::vector<std::byte>();
        if(key_loaded) {
            unwrap_ob_mut(enc, aes::encrypt(key, iv, payload));
            encrypted = std::move(enc);
            payload   = encrypted;
        }
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
    key_loaded = true;
    return true;
}

auto run(const int argc, const char* const argv[]) -> bool {
    unwrap_ob(args, Args::parse(argc, argv));

    ws::set_log_level(0b11);
    auto session = Session();
    session.set_ws_debug_flags(false, false);
    assert_b(session.start(args));
    print("ready");
    assert_b(session.run());
    return true;
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    return run(argc, argv) ? 0 : 1;
}
