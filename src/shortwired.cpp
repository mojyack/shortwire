#include "args.hpp"
#include "common.hpp"
#include "crypto/aes.hpp"
#include "crypto/c20p1305.hpp"
#include "macros/unwrap.hpp"
#include "p2p/ice-session-protocol.hpp"
#include "p2p/ice-session.hpp"
#include "p2p/ws/misc.hpp"
#include "util/concat.hpp"
#include "util/event-fd.hpp"
#include "util/fd.hpp"
#include "util/file-io.hpp"
#include "util/random.hpp"
#include "util/span.hpp"

namespace {
constexpr auto key_len = 32;
static_assert(crypto::c20p1305::key_len == key_len);
using Key = std::array<std::byte, key_len>;

namespace proto {
struct Type {
    enum : uint16_t {
        ServerParameters = ::p2p::ice::proto::Type::Limit,
        Datagram,
        Nop,

        Limit,
    };
};

struct ServerParameters : ::p2p::proto::Packet {
    EncMethod enc_method;
    uint16_t  mtu;
    uint8_t   websocket_only;
    uint8_t   tap;
};

struct Datagram : ::p2p::proto::Packet {
    // std::byte data[];
};
} // namespace proto

struct EventKind {
    enum {
        ServerParameters = p2p::ice::EventKind::Limit,

        Limit,
    };
};

class Session : public p2p::ice::IceSession {
  private:
    Args                args;
    FileDescriptor      dev;
    EventFileDescriptor stop;

    RandomEngine              random_engine;
    crypto::AutoCipherContext enc_context;
    crypto::AutoCipherContext dec_context;
    Key                       key;

    auto auth_peer(std::string_view peer_name, std::span<const std::byte> secret) -> bool override;
    auto on_pad_created() -> void override;
    auto on_disconnected() -> void override;
    auto on_packet_received(std::span<const std::byte> payload) -> bool override;
    auto on_p2p_packet_received(std::span<const std::byte> payload) -> void override;

    auto process_received_datagram(std::span<const std::byte> data) -> bool;
    auto send_packet_p2p_retry(std::span<const std::byte> payload) -> bool;

  public:
    auto start() -> bool;
    auto run() -> bool;

    Session(Args args);
};

auto split_iv_enc(const std::span<const std::byte> data, const size_t iv_len) -> std::array<std::span<const std::byte>, 2> {
    const auto iv  = data.subspan(0, iv_len);
    const auto enc = data.subspan(iv_len);
    return {iv, enc};
}

auto get_packet_overhead(const Args& args) -> size_t {
    const auto header_len = args.tap ? 14 : 0;
    switch(args.enc_method) {
    case EncMethod::None:
        return header_len;
    case EncMethod::AES:
        return header_len + crypto::aes::iv_len + crypto::aes::block_len; // +block_len is worst case
    case EncMethod::C20P1305:
        return header_len + crypto::c20p1305::iv_len + crypto::c20p1305::tag_len;
    }
}

auto Session::auth_peer(std::string_view peer_name, std::span<const std::byte> /*secret*/) -> bool {
    return peer_name == build_string(args.username, "_client");
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
    case proto::Type::ServerParameters: {
        unwrap_pb(packet, p2p::proto::extract_payload<proto::ServerParameters>(payload));
        args.enc_method = packet.enc_method;
        args.mtu        = packet.mtu;
        args.ws_only    = packet.websocket_only;
        args.tap        = packet.tap;
        send_result(p2p::proto::Type::Success, header.id);
        events.invoke(EventKind::ServerParameters, p2p::no_id, p2p::no_value);
        return true;
    }
    case proto::Type::Datagram: {
        assert_b(process_received_datagram(payload.subspan(sizeof(proto::Datagram))));
        return true;
    }
    default:
        if(args.ws_only) {
            return p2p::plink::PeerLinkerSession::on_packet_received(payload);
        } else {
            return p2p::ice::IceSession::on_packet_received(payload);
        }
    }
}

auto Session::on_p2p_packet_received(std::span<const std::byte> payload) -> void {
    unwrap_pn(header, p2p::proto::extract_header(payload));

    switch(header.type) {
    case proto::Type::Datagram: {
        assert_n(process_received_datagram(payload.subspan(sizeof(proto::Datagram))));
        return;
    }
    case proto::Type::Nop: {
        return;
    }
    default:
        WARN("unknown packet type");
        return;
    }
}

auto Session::process_received_datagram(std::span<const std::byte> data) -> bool {
    if(verbose) {
        print(">>> ", data.size(), " bytes");
    }
    auto decrypted = std::vector<std::byte>();
    switch(args.enc_method) {
    case EncMethod::None:
        break;
    case EncMethod::AES: {
        assert_b(data.size() > crypto::aes::iv_len, "packet too short");
        const auto [iv, enc] = split_iv_enc(data, crypto::aes::iv_len);
        unwrap_ob_mut(dec, crypto::aes::decrypt(dec_context.get(), key, iv, enc));
        decrypted = std::move(dec);
        data      = decrypted;
    } break;
    case EncMethod::C20P1305: {
        assert_b(data.size() > crypto::c20p1305::iv_len, "packet too short");
        const auto [iv, enc] = split_iv_enc(data, crypto::c20p1305::iv_len);
        unwrap_ob_mut(dec, crypto::c20p1305::decrypt(dec_context.get(), key, iv, enc));
        decrypted = std::move(dec);
        data      = decrypted;
    } break;
    }
    assert_b(size_t(write(dev.as_handle(), data.data(), data.size())) == data.size(), strerror(errno));
    return true;
}

auto Session::send_packet_p2p_retry(const std::span<const std::byte> payload) -> bool {
loop:
    if(send_packet_p2p(payload)) {
        return true;
    }
    switch(errno) {
    case EMSGSIZE:
        return false;
    case EAGAIN:
        std::this_thread::yield();
        goto loop;
    default:
        assert_b(false, errno, " ", strerror(errno));
    }
}

auto Session::start() -> bool {
    if(args.key_file != nullptr) {
        unwrap_ob(key_b, read_file(args.key_file));
        assert_b(key_b.size() == key.size());
        std::memcpy(key.data(), key_b.data(), key.size());
    }

    auto plink_user_cert = std::string();
    if(args.peer_linker_user_cert_path != nullptr) {
        unwrap_ob(cert, read_file(args.peer_linker_user_cert_path), "failed to read user certificate");
        plink_user_cert = from_span(cert);
    }
    const auto server_pad_name = build_string(args.username, "_server");
    const auto client_pad_name = build_string(args.username, "_client");
    const auto plink_params    = p2p::plink::PeerLinkerSessionParams{
           .peer_linker                   = p2p::wss::ServerLocation{args.peer_linker_addr, args.peer_linker_port},
           .pad_name                      = args.server ? server_pad_name : client_pad_name,
           .target_pad_name               = args.server ? "" : std::string_view(server_pad_name),
           .user_certificate              = plink_user_cert,
           .peer_linker_allow_self_signed = true,
    };

    if(args.server) {
        print("waiting for client");
    }
    assert_b(p2p::plink::PeerLinkerSession::start(plink_params));

    if(args.server) {
        assert_b(send_packet(proto::Type::ServerParameters, int(args.enc_method), uint16_t(args.mtu), uint8_t(args.ws_only), uint8_t(args.tap)));
    } else {
        assert_b(wait_for_event(EventKind::ServerParameters));
    }
    if(args.enc_method != EncMethod::None) {
        enc_context.reset(crypto::alloc_cipher_context());
        dec_context.reset(crypto::alloc_cipher_context());
    } else {
        warn("no private key provided, continuing without encryption");
    }

    unwrap_ob(dev, setup_virtual_nic({
                       .address = args.address,
                       .mask    = args.mask,
                       .mtu     = args.mtu,
                       .tap     = args.tap,
                   }));
    this->dev = FileDescriptor(dev);

    if(args.ws_only) {
        return true;
    }

    assert_b(p2p::ice::IceSession::start_ice({{"stun.l.google.com", 19302}, {}}, plink_params));

    print("adjusting mtu");
    juice_set_log_level(JUICE_LOG_LEVEL_ERROR); // supress logs to preserve errno inside libjuice
    unwrap_ob_mut(mtu, get_mtu(dev));
    const auto overhead = get_packet_overhead(args);
    const auto buffer   = std::vector<std::byte>(mtu + overhead);
    while(mtu > 500) {
        if(send_packet_p2p_retry(p2p::proto::build_packet(proto::Type::Nop, 0, std::span{buffer.data(), mtu + overhead}))) {
            break;
        }
        assert_b(errno == EMSGSIZE, errno, " ", strerror(errno));
        mtu -= 1;
        assert_b(set_mtu(dev, mtu));
    }
    juice_set_log_level(JUICE_LOG_LEVEL_WARN);
    print("mtu adjusted to ", mtu);

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
        switch(args.enc_method) {
        case EncMethod::None:
            break;
        case EncMethod::AES: {
            const auto iv = random_engine.generate<crypto::aes::iv_len>();
            unwrap_ob_mut(enc, crypto::aes::encrypt(enc_context.get(), key, iv, payload));
            encrypted = concat(iv, enc);
            payload   = encrypted;
        } break;
        case EncMethod::C20P1305: {
            const auto iv = random_engine.generate<crypto::c20p1305::iv_len>();
            unwrap_ob_mut(enc, crypto::c20p1305::encrypt(enc_context.get(), key, iv, payload));
            encrypted = concat(iv, enc);
            payload   = encrypted;
        } break;
        }

        if(args.ws_only) {
            send_generic_packet(proto::Type::Datagram, 0, payload);
        } else {
            send_packet_p2p(p2p::proto::build_packet(proto::Type::Datagram, 0, payload));
        }
    }
    if(fds[1].revents & POLLIN) {
        return true;
    }
    goto loop;
}

Session::Session(Args args)
    : args(args) {
}

auto run(const int argc, const char* const argv[]) -> bool {
    unwrap_ob(args, Args::parse(argc, argv));

    ws::set_log_level(0b11);
    // juice_set_log_level(JUICE_LOG_LEVEL_INFO);
    auto session = Session(args);
    session.set_ws_debug_flags(false, false);
    assert_b(session.start());
    print("ready");
    assert_b(session.run());
    return true;
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    return run(argc, argv) ? 0 : 1;
}
