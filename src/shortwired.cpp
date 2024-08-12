#include <random>

#include "args.hpp"
#include "common.hpp"
#include "crypto/aes.hpp"
#include "macros/unwrap.hpp"
#include "p2p/ice-session-protocol.hpp"
#include "p2p/ice-session.hpp"
#include "p2p/ws/misc.hpp"
#include "util/event-fd.hpp"
#include "util/fd.hpp"
#include "util/file-io.hpp"
#include "util/span.hpp"

namespace {
using Key = std::array<std::byte, 32>;

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
    std::string         username;
    FileDescriptor      dev;
    EventFileDescriptor stop;

    crypto::AutoCipherContext cipher_context;
    Key                       key;

    bool ws_only    = false;
    bool verbose    = false;
    bool key_loaded = false;

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

auto engine = std::mt19937((std::random_device())());

template <std::integral T, size_t size>
auto generate_random_bytes() -> std::array<std::byte, size> {
    static_assert(size % sizeof(T) == 0);

    auto ret = std::array<std::byte, size>();
    for(auto i = 0u; i < size / sizeof(T); i += 1) {
        std::bit_cast<T*>(&ret)[i] = engine();
    }
    return ret;
}

auto Session::auth_peer(std::string_view peer_name, std::span<const std::byte> /*secret*/) -> bool {
    return peer_name.starts_with(build_string(username, "_")) && peer_name.ends_with("_client");
}

auto Session::on_pad_created() -> void {
}

auto Session::on_disconnected() -> void {
    print("session disconnected");
    stop.notify();
}

auto Session::on_packet_received(const std::span<const std::byte> payload) -> bool {
    unwrap_pb(header, p2p::proto::extract_header(payload));

    switch(header.type) {
    case proto::Type::EthernetFrame: {
        assert_b(process_received_ethernet_frame(payload.subspan(sizeof(proto::EthernetFrame))));
        send_result(p2p::proto::Type::Success, header.id);
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
        assert_b(data.size() > crypto::aes::iv_len, "packet too short");
        const auto iv  = data.subspan(0, crypto::aes::iv_len);
        const auto enc = data.subspan(crypto::aes::iv_len);
        unwrap_ob_mut(dec, crypto::aes::decrypt(cipher_context.get(), key, iv, enc));
        decrypted = std::move(dec);
        data      = decrypted;
    }
    assert_b(size_t(write(dev.as_handle(), data.data(), data.size())) == data.size(), strerror(errno));
    return true;
}

auto Session::start(Args args) -> bool {
    username = args.username;
    verbose  = args.verbose;
    ws_only  = args.ws_only;
    if(args.key_file != nullptr) {
        assert_b(load_key(args.key_file));
    }

    const auto local_addr = to_inet_addr(192, 168, args.subnet, args.server ? 1 : 2);
    unwrap_ob(dev, setup_tap_dev(local_addr, ws_only ? 1500 : 1300));
    this->dev = FileDescriptor(dev);

    auto plink_user_cert = std::string();
    if(args.peer_linker_user_cert_path != nullptr) {
        unwrap_ob(cert, read_file(args.peer_linker_user_cert_path), "failed to read user certificate");
        plink_user_cert = from_span(cert);
    }
    const auto server_pad_name = build_string(username, "_subnet-", int(args.subnet), "_server");
    const auto client_pad_name = build_string(username, "_subnet-", int(args.subnet), "_client");
    const auto plink_params    = p2p::plink::PeerLinkerSessionParams{
           .peer_linker                   = p2p::wss::ServerLocation{args.peer_linker_addr, args.peer_linker_port},
           .pad_name                      = args.server ? server_pad_name : client_pad_name,
           .target_pad_name               = args.server ? "" : std::string_view(server_pad_name),
           .user_certificate              = plink_user_cert,
           .peer_linker_allow_self_signed = true,
    };
    if(ws_only) {
        assert_b(p2p::plink::PeerLinkerSession::start(plink_params));
    } else {
        assert_b(p2p::ice::IceSession::start({{"stun.l.google.com", 19302}, {}}, plink_params));
    }

    if(!key_loaded) {
        warn("no private key provided\ncontinuing without encryption");
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
            // generate iv
            const auto iv = generate_random_bytes<uint64_t, crypto::aes::iv_len>();

            // encrypt
            unwrap_ob_mut(enc, crypto::aes::encrypt(cipher_context.get(), key, iv, payload));

            // build packet(iv+enc)
            encrypted.resize(iv.size() + enc.size());
            std::memcpy(encrypted.data(), iv.data(), iv.size());
            std::memcpy(encrypted.data() + iv.size(), enc.data(), enc.size());
            payload = encrypted;
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
    unwrap_ob(key_b, read_file(key_path));
    assert_b(key_b.size() == key.size());
    std::memcpy(key.data(), key_b.data(), key.size());
    cipher_context.reset(crypto::alloc_cipher_context());
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