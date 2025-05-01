#include <coop/generator.hpp>
#include <coop/thread.hpp>

#include "args.hpp"
#include "common.hpp"
#include "crypto/aes.hpp"
#include "crypto/c20p1305.hpp"
#include "macros/coop-unwrap.hpp"
#include "p2p/conn.hpp"
#include "p2p/net/packet-parser.hpp"
#include "plink/peer-linker-client.hpp"
#include "protocol.hpp"
#include "util/cleaner.hpp"
#include "util/concat.hpp"
#include "util/fd.hpp"
#include "util/file-io.hpp"
#include "util/random.hpp"
#include "util/span.hpp"

namespace {
constexpr auto key_len = 32;
static_assert(crypto::c20p1305::key_len == key_len);
using Key = std::array<std::byte, key_len>;

auto split_iv_enc(const std::span<const std::byte> data, const size_t iv_len) -> std::array<std::span<const std::byte>, 2> {
    const auto iv  = data.subspan(0, iv_len);
    const auto enc = data.subspan(iv_len);
    return {iv, enc};
}

struct ShortWire {
    Args                                args;
    std::unique_ptr<net::ClientBackend> backend;
    net::PacketParser                   parser;
    p2p::Connection                     p2p;
    FileDescriptor                      vnic;
    crypto::AutoCipherContext           dec_context;
    Key                                 key;

    auto handle_parsed(net::Header header, net::BytesRef payload) -> coop::Async<bool>;
    auto handle_datagram(net::BytesRef data) -> bool;
    auto vnic_reader_main() -> bool;

    auto run(coop::TaskInjector& injector) -> coop::Async<bool>;
};

auto ShortWire::handle_parsed(net::Header header, net::BytesRef payload) -> coop::Async<bool> {
    switch(header.type) {
    case proto::Signaling::pt:
        coop_ensure(co_await p2p.push_signaling_data(payload));
        break;
    case proto::Nop::pt:
        break;
    default:
        coop_ensure(co_await parser.callbacks.invoke(header, payload));
        break;
    }
    co_return true;
}

auto ShortWire::handle_datagram(net::BytesRef data) -> bool {
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

auto ShortWire::vnic_reader_main() -> bool {
    auto buf           = std::array<std::byte, 1536>();
    auto enc_context   = crypto::AutoCipherContext(crypto::alloc_cipher_context());
    auto random_engine = RandomEngine();
    auto cleaner       = Cleaner{[] { PANIC("vnic reader panicked"); }};
loop:
    const auto len = read(vnic.as_handle(), buf.data(), buf.size());
    ensure(len > 0);

    auto payload   = net::BytesRef{buf.data(), size_t(len)};
    auto encrypted = net::BytesArray();
    switch(args.enc) {
    case EncMethod::None:
        break;
    case EncMethod::AES: {
        const auto iv = random_engine.generate<crypto::aes::iv_len>();
        unwrap_mut(enc, crypto::aes::encrypt(enc_context.get(), key, iv, payload));
        encrypted = concat(iv, enc);
        payload   = encrypted;
    } break;
    case EncMethod::C20P1305: {
        const auto iv = random_engine.generate<crypto::c20p1305::iv_len>();
        unwrap_mut(enc, crypto::c20p1305::encrypt(enc_context.get(), key, iv, payload));
        encrypted = concat(iv, enc);
        payload   = encrypted;
    } break;
    }

    if(const auto ret = p2p.send_data(payload); ret != p2p::SendResult::Success) {
        WARN("send failed: {}", std::to_underlying(ret));
    }
    goto loop;
}

auto ShortWire::run(coop::TaskInjector& injector) -> coop::Async<bool> {
    // setup parser
    auto server_params_received = coop::SingleEvent();
    auto signaling_ready        = coop::SingleEvent();

    parser.send_data = [this](net::BytesRef data) -> coop::Async<bool> {
        return backend->send(data);
    };
    parser.callbacks.by_type[proto::StartSignaling::pt] = [this, &signaling_ready](net::Header header, net::BytesRef /*payload*/) -> coop::Async<bool> {
        constexpr auto error_value = false;
        signaling_ready.notify();
        co_ensure_v(co_await parser.send_packet(proto::Success(), header.id));
        co_return true;
    };
    parser.callbacks.by_type[proto::ServerParameters::pt] = [this, &server_params_received](net::Header header, net::BytesRef payload) -> coop::Async<bool> {
        constexpr auto error_value = false;
        co_unwrap_v_mut(request, (serde::load<net::BinaryFormat, proto::ServerParameters>(payload)));
        args.enc = request.enc;
        args.mtu = request.mtu;
        args.tap = request.tap;
        server_params_received.notify();
        co_ensure_v(co_await parser.send_packet(proto::Success(), header.id));
        co_return true;
    };

    // setup backend
    auto backend = new plink::PeerLinkerClientBackend();
    this->backend.reset(backend);
    backend->on_auth_request = [this](std::string_view name, net::BytesRef) { return name == std::format("{}_client", args.username); };
    backend->on_closed       = []() { std::quick_exit(1); };
    backend->on_received     = [this](net::BytesRef data) -> coop::Async<void> {
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
    auto plink_user_cert = std::string();
    if(args.peer_linker_user_cert_path != nullptr) {
        coop_unwrap(cert, read_file(args.peer_linker_user_cert_path), "failed to read user certificate");
        plink_user_cert = from_span(cert);
    }
    auto params = plink::PeerLinkerClientBackend::Params{
        .peer_linker_addr = args.peer_linker_addr,
        .peer_linker_port = args.peer_linker_port,
        .user_certificate = std::move(plink_user_cert),
    };
    if(args.server) {
        params.pad_name = std::format("{}_server", args.username);
    } else {
        params.pad_name  = std::format("{}_client", args.username);
        params.peer_info = plink::PeerLinkerClientBackend::Params::PeerInfo{
            .pad_name = std::format("{}_server", args.username),
        };
    }
    std::println("waiting for peer");
    coop_ensure(co_await backend->connect(std::move(params)));
    std::println("backend ready");

    // exchange parameters
    if(args.server) {
        coop_ensure(co_await parser.receive_response<proto::Success>(proto::ServerParameters{args.enc, args.mtu, args.tap}))
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

    // setup p2p
    p2p.on_disconnected  = []() { std::quick_exit(1); };
    p2p.on_received      = [this](net::BytesRef data) { handle_datagram(data); };
    p2p.parser.send_data = [this](net::BytesRef data) -> coop::Async<bool> {
        return parser.send_packet(proto::Signaling::pt, data.data(), data.size());
    };
    coop_ensure(co_await p2p.connect({
        .injector      = &injector,
        .start_backend = [&] -> coop::Async<bool> {
            constexpr auto error_value = false;
            co_ensure_v(co_await parser.receive_response<proto::Success>(proto::StartSignaling{}));
            co_await signaling_ready; // wait for remote start_backend
            co_return true;
        },
        .stun_addr   = "stun.l.google.com",
        .stun_port   = 19302,
        .controlling = !args.server,
    }));
    std::println("connected");

    coop_unwrap(dev, setup_virtual_nic({
                         .address = args.address,
                         .mask    = args.mask,
                         .mtu     = args.mtu,
                         .tap     = args.tap,
                     }));
    this->vnic = FileDescriptor(dev);

    co_await coop::run_blocking([this] { vnic_reader_main(); });

    co_return true;
}

auto async_main(const int argc, const char* const* argv) -> coop::Async<void> {
    coop_unwrap(args, Args::parse(argc, argv));
    auto shortwire = ShortWire{args};
    auto injector  = coop::TaskInjector(*co_await coop::reveal_runner());
    if(!co_await shortwire.run(injector)) {
        PANIC("connection failed");
    }
}
} // namespace

auto main(const int argc, const char* const* argv) -> int {
    auto runner = coop::Runner();
    runner.push_task(async_main(argc, argv));
    runner.run();
    return 0;
}
