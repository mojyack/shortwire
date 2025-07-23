#include <coop/generator.hpp>
#include <coop/task-injector.hpp>
#include <coop/thread.hpp>

#include "args.hpp"
#include "common.hpp"
#include "crypto/aes.hpp"
#include "crypto/c20p1305.hpp"
#include "macros/coop-unwrap.hpp"
#include "p2p/conn.hpp"
#include "p2p/net/discord/client.hpp"
#include "p2p/net/packet-parser.hpp"
#include "plink/peer-linker-client.hpp"
#include "protocol.hpp"
#include "util/cleaner.hpp"
#include "util/concat.hpp"
#include "util/fd.hpp"
#include "util/file-io.hpp"
#include "util/random.hpp"
#include "util/span.hpp"
#include "util/timer-event.hpp"

namespace {
constexpr auto key_len = 32;
static_assert(crypto::c20p1305::key_len == key_len);
using Key = std::array<std::byte, key_len>;

auto split_iv_enc(const std::span<const std::byte> data, const size_t iv_len) -> std::array<std::span<const std::byte>, 2> {
    const auto iv  = data.subspan(0, iv_len);
    const auto enc = data.subspan(iv_len);
    return {iv, enc};
}

auto get_packet_overhead(const bool tap, const EncMethod enc) -> size_t {
    const auto header_len = (tap ? 14 : 0) + sizeof(proto::P2PPacketType::Payload);
    switch(enc) {
    case EncMethod::None:
        return header_len;
    case EncMethod::AES:
        return header_len + crypto::aes::iv_len + crypto::aes::block_len; // +block_len is worst case
    case EncMethod::C20P1305:
        return header_len + crypto::c20p1305::iv_len + crypto::c20p1305::tag_len;
    }
}

struct ShortWire {
    Args                      args;
    net::PacketParser         parser;
    p2p::Connection           p2p;
    FileDescriptor            vnic;
    crypto::AutoCipherContext dec_context;
    Key                       key;
    TimerEvent                conn_test_responded;

    auto handle_parsed(net::Header header, net::BytesRef payload) -> coop::Async<bool>;
    auto calibrate_mtu() -> bool;
    auto handle_payload_datagram(net::BytesRef data) -> bool;
    auto handle_datagram(net::BytesRef data) -> bool;
    auto vnic_reader_main() -> bool;

    auto connect(coop::TaskInjector& injector) -> coop::Async<bool>;
};

auto ShortWire::handle_parsed(net::Header header, net::BytesRef payload) -> coop::Async<bool> {
    switch(header.type) {
    case proto::Signaling::pt:
        coop_ensure(co_await p2p.push_signaling_data(payload));
        break;
    default:
        coop_ensure(co_await parser.callbacks.invoke(header, payload));
        break;
    }
    co_return true;
}

auto ShortWire::calibrate_mtu() -> bool {
    juice_set_log_level(JUICE_LOG_LEVEL_ERROR);
    const auto log_level_cleaner = Cleaner{[] { juice_set_log_level(JUICE_LOG_LEVEL_WARN); }};

    unwrap_mut(mtu, get_mtu(vnic.as_handle()));
    const auto overhead = get_packet_overhead(args.tap, args.enc);
    auto       dummy    = net::BytesArray{proto::P2PPacketType::ConnectivityTest};
loop:
    ensure(mtu >= 500);
    dummy.resize(mtu + overhead);
    conn_test_responded.clear();
    const auto ret = p2p.send_data(dummy);
    switch(ret) {
    case p2p::SendResult::Success:
        if(conn_test_responded.wait_for(std::chrono::seconds(1))) {
            goto finish;
        }
        [[fallthrough]];
    case p2p::SendResult::MessageTooLarge:
        mtu -= 10;
        ensure(set_mtu(vnic.as_handle(), mtu));
        break;
    case p2p::SendResult::WouldBlock:
        break;
    case p2p::SendResult::UnknownError:
        bail("send failed");
    }
    goto loop;
finish:
    std::println("mtu calibrate to {}", mtu);
    return true;
}

auto ShortWire::handle_payload_datagram(net::BytesRef data) -> bool {
    auto decrypted = std::vector<std::byte>();
    switch(args.enc) {
    case EncMethod::None:
        break;
    case EncMethod::AES: {
        ensure(data.size() > crypto::aes::iv_len, "packet too short");
        const auto [iv, enc] = split_iv_enc(data, crypto::aes::iv_len);
        unwrap_mut(dec, crypto::aes::decrypt(dec_context.get(), key, iv, enc));
        decrypted = std::move(dec);
        data      = decrypted;
    } break;
    case EncMethod::C20P1305: {
        ensure(data.size() > crypto::c20p1305::iv_len, "packet too short");
        const auto [iv, enc] = split_iv_enc(data, crypto::c20p1305::iv_len);
        unwrap_mut(dec, crypto::c20p1305::decrypt(dec_context.get(), key, iv, enc));
        decrypted = std::move(dec);
        data      = decrypted;
    } break;
    }
    ensure(size_t(write(vnic.as_handle(), data.data(), data.size())) == data.size(), "{}", strerror(errno));
    return true;
}

auto ShortWire::handle_datagram(net::BytesRef data) -> bool {
    ensure(!data.empty());
    switch(data[0]) {
    case proto::P2PPacketType::Payload: {
        ensure(handle_payload_datagram(data.subspan(1)));
    } break;
    case proto::P2PPacketType::ConnectivityTest: {
        p2p.send_data(std::array{proto::P2PPacketType::ConnectivityResponse});
    } break;
    case proto::P2PPacketType::ConnectivityResponse: {
        conn_test_responded.notify();
    } break;
    default:
        bail("invalid p2p packet: type={:02X}", uint8_t(data[0]));
    }
    return true;
}

auto ShortWire::vnic_reader_main() -> bool {
    auto buf           = std::array<std::byte, 1 /*pt*/ + 1536>{proto::P2PPacketType::Payload};
    auto enc_context   = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    auto random_engine = RandomEngine();
    auto cleaner       = Cleaner{[] { PANIC("vnic reader panicked"); }};
loop:
    static const auto pt = std::array{proto::P2PPacketType::Payload};

    const auto len = read(vnic.as_handle(), buf.data() + 1, buf.size() - 1);
    ensure(len > 0);

    auto payload   = net::BytesRef();
    auto encrypted = net::BytesArray();

    switch(args.enc) {
    case EncMethod::None:
        payload = net::BytesRef{buf.data(), size_t(len) + 1};
        break;
    case EncMethod::AES: {
        const auto data = net::BytesRef{buf.data() + 1, size_t(len)};
        const auto iv   = random_engine.generate<crypto::aes::iv_len>();
        unwrap_mut(enc, crypto::aes::encrypt(enc_context.get(), key, iv, data));
        encrypted = concat(concat(pt, iv), enc);
        payload   = encrypted;
    } break;
    case EncMethod::C20P1305: {
        const auto data = net::BytesRef{buf.data() + 1, size_t(len)};
        const auto iv   = random_engine.generate<crypto::c20p1305::iv_len>();
        unwrap_mut(enc, crypto::c20p1305::encrypt(enc_context.get(), key, iv, data));
        encrypted = concat(concat(pt, iv), enc);
        payload   = encrypted;
    } break;
    }

    if(const auto ret = p2p.send_data(payload); ret != p2p::SendResult::Success) {
        WARN("send failed: {}", std::to_underlying(ret));
        if(ret == p2p::SendResult::MessageTooLarge) {
            ensure(calibrate_mtu());
        }
    }
    goto loop;
}

auto ShortWire::connect(coop::TaskInjector& injector) -> coop::Async<bool> {
    constexpr auto error_value = false;

    auto backend = std::unique_ptr<net::ClientBackend>();

    // setup parser
    auto server_params_received = coop::SingleEvent();
    auto signaling_ready        = coop::SingleEvent();

    parser.send_data = [&](net::BytesRef data) -> coop::Async<bool> {
        return backend->send(data);
    };
    parser.callbacks.by_type[proto::StartSignaling::pt] = [this, &signaling_ready](net::Header header, net::BytesRef /*payload*/) -> coop::Async<bool> {
        signaling_ready.notify();
        return parser.send_packet(proto::Success(), header.id);
    };
    parser.callbacks.by_type[proto::ServerParameters::pt] = [this, &server_params_received](net::Header header, net::BytesRef payload) -> coop::Async<bool> {
        co_unwrap_v_mut(request, (serde::load<net::BinaryFormat, proto::ServerParameters>(payload)));
        args.enc = request.enc;
        args.tap = request.tap;
        server_params_received.notify();
        co_ensure_v(co_await parser.send_packet(proto::Success(), header.id));
        co_return true;
    };

    // setup backend
    if(args.sig_method.get<PeerLinkerArgs>() != nullptr) {
        auto impl             = new plink::PeerLinkerClientBackend();
        impl->on_auth_request = [this](std::string_view name, net::BytesRef) { return name == std::format("{}_client", args.username); };
        backend.reset(impl);
    } else {
        auto impl = new net::discord::DiscordClient();
        backend.reset(impl);
    }
    backend->on_closed   = []() { std::quick_exit(1); };
    backend->on_received = [this](net::BytesRef data) -> coop::Async<void> {
        const auto parsed = parser.parse_received(data);
        if(!parsed) {
            co_return;
        }
        const auto& [header, payload] = *parsed;
        if(!co_await handle_parsed(header, payload) && header.type != proto::Error::pt) {
            co_await parser.send_packet(proto::Error(), header.id);
        }
    };

    // start backend
    const auto server_name = std::format("{}_server", args.username);
    const auto client_name = std::format("{}_client", args.username);
    std::println("waiting for peer");
    if(const auto method = args.sig_method.get<PeerLinkerArgs>()) {
        auto plink_user_cert = std::string();
        if(method->user_cert_path != nullptr) {
            coop_unwrap(cert, read_file(method->user_cert_path), "failed to read user certificate");
            plink_user_cert = from_span(cert);
        }
        auto params = plink::PeerLinkerClientBackend::Params{
            .peer_linker_addr = method->addr,
            .peer_linker_port = method->port,
            .user_certificate = std::move(plink_user_cert),
        };
        if(args.server) {
            params.pad_name = server_name;
        } else {
            params.pad_name  = client_name;
            params.peer_info = plink::PeerLinkerClientBackend::Params::PeerInfo{
                .pad_name = server_name,
            };
        }
        coop_ensure(co_await std::bit_cast<plink::PeerLinkerClientBackend*>(backend.get())->connect(std::move(params)));
    } else if(const auto method = args.sig_method.get<DiscordArgs>()) {
        auto& name_1 = args.server ? server_name : client_name;
        auto& name_2 = args.server ? client_name : server_name;
        coop_ensure(co_await std::bit_cast<net::discord::DiscordClient*>(backend.get())->connect(name_1, name_2, method->channel_id, method->bot_token, injector));
    } else {
        PANIC();
    }
    std::println("backend ready");

    // exchange parameters
    if(args.server) {
        coop_ensure(co_await parser.receive_response<proto::Success>(proto::ServerParameters{args.enc, args.tap}));
    } else {
        co_await server_params_received;
    }
    if(args.enc != EncMethod::None) {
        dec_context.reset(crypto::alloc_cipher_context());
        coop_ensure(args.key_file != nullptr, "private key required");
        coop_unwrap(key_b, read_file(args.key_file));
        coop_ensure(key_b.size() == key.size());
        std::memcpy(key.data(), key_b.data(), key.size());
    } else {
        WARN("continuing without encryption");
    }

    // create virtual nic
    coop_unwrap(dev, setup_virtual_nic({
                         .address = args.address,
                         .mask    = args.mask,
                         .mtu     = 1500,
                         .tap     = args.tap,
                     }));
    this->vnic = FileDescriptor(dev);

    // setup p2p
    p2p.on_received      = [this](net::BytesRef data) { handle_datagram(data); };
    p2p.on_disconnected  = []() { std::quick_exit(1); };
    p2p.parser.send_data = [this](net::BytesRef data) -> coop::Async<bool> {
        return parser.send_packet(proto::Signaling::pt, data.data(), data.size());
    };
    coop_ensure(co_await p2p.connect({
        .start_backend = [&] -> coop::Async<bool> {
            co_ensure_v(co_await parser.receive_response<proto::Success>(proto::StartSignaling{}));
            co_await signaling_ready; // wait for remote start_backend
            co_return true;
        },
        .stun_addr   = "stun.l.google.com",
        .stun_port   = 19302,
        .controlling = !args.server,
    }));
    std::println("connected");

    // backend is no longer used
    parser.send_data = [&](net::BytesRef) -> coop::Async<bool> {
        co_bail_v("no more data expected");
    };
    backend->on_closed = [] {};

    // calibrate mtu
    coop_ensure(calibrate_mtu());
    std::println("ready");

    co_return true;
}
} // namespace

auto main(const int argc, const char* const* const argv) -> int {
    unwrap(args, Args::parse(argc, argv));
    auto shortwire = ShortWire{args};
    {
        auto runner   = coop::Runner();
        auto injector = coop::TaskInjector(runner);
        auto setup    = [&] -> coop::Async<void> {
            ASSERT(co_await shortwire.connect(injector));
            injector.blocker.stop();
        };
        runner.push_task(setup());
        runner.run();
    }
    shortwire.vnic_reader_main();
    return 0;
}
