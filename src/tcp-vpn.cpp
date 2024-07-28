#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "macros/unwrap.hpp"
#include "util/charconv.hpp"
#include "util/fd.hpp"

namespace {
auto print_mac_addr(const uint8_t* addr) -> void {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

auto to_inet_addr(uint8_t a, const uint8_t b, const uint8_t c, const uint8_t d) -> uint32_t {
    return a << 24 | b << 16 | c << 8 | d;
}

auto to_inet_addr(const char* const str) -> std::optional<uint32_t> {
    auto addr = in_addr();
    assert_o(inet_aton(str, &addr) == 1);
    return ntohl(addr.s_addr);
}

auto setup_tap_dev(const uint32_t address) -> std::optional<FileDescriptor> {
    auto dev = FileDescriptor(open("/dev/net/tun", O_RDWR));
    assert_o(dev.as_handle() >= 0);

    // create device
    auto ifr      = ifreq();
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
    assert_o(ioctl(dev.as_handle(), TUNSETIFF, &ifr) == 0);
    print("interface created: ", ifr.ifr_name);

    // dummy socket for setting parameters
    const auto sock = FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));

    // set address
    ifr.ifr_addr.sa_family                         = AF_INET;
    ((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr = htonl(address);
    assert_o(ioctl(sock.as_handle(), SIOCSIFADDR, &ifr) == 0, strerror(errno));

    // set address mask
    ((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr = htonl(to_inet_addr(255, 255, 255, 0));
    assert_o(ioctl(sock.as_handle(), SIOCSIFNETMASK, &ifr) == 0);

    // set flag
    assert_o(ioctl(sock.as_handle(), SIOCGIFFLAGS, &ifr) == 0);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    assert_o(ioctl(sock.as_handle(), SIOCSIFFLAGS, &ifr) == 0);

    return dev;
}

auto run_mainloop(const int dev, const int sock) -> bool {
    auto buf = std::array<char, 1536>();

    auto fds = std::array{
        pollfd{.fd = dev, .events = POLLIN},
        pollfd{.fd = sock, .events = POLLIN},
    };
loop:
    assert_b(poll(fds.data(), fds.size(), -1) != -1);
    for(auto i = 0; i < 2; i += 1) {
        assert_b(!(fds[i].revents & POLLHUP));
        assert_b(!(fds[i].revents & POLLERR));
        if(fds[i].revents & POLLIN) {
            const auto len = read(fds[i].fd, buf.data(), buf.size());
            print(i, " -> ", !i, " ", len);
            assert_b(len >= 0);
            if(len == 0) {
                print("disconnected");
                return true;
            }
            assert_b(write(fds[!i].fd, buf.data(), len) == len, strerror(errno));
        }
    }
    goto loop;
}

auto run_server(const uint16_t port) -> bool {
    unwrap_ob(dev, setup_tap_dev(to_inet_addr(192, 168, 2, 1)));

    auto sock = FileDescriptor(socket(AF_INET, SOCK_STREAM, 0));
    assert_b(sock.as_handle() >= 0);

    const auto server_addr = sockaddr_in{
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = {
              .s_addr = htonl(to_inet_addr(0, 0, 0, 0)),
        },
    };
    {
        auto val = 1;
        assert_b(setsockopt(sock.as_handle(), SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) == 0);
    }
    assert_b(bind(sock.as_handle(), (sockaddr*)&server_addr, sizeof(server_addr)) == 0);
    assert_b(listen(sock.as_handle(), 1) == 0);

    auto       client_addr     = sockaddr_in();
    auto       client_addr_len = socklen_t();
    const auto client_sock     = FileDescriptor(accept(sock.as_handle(), (sockaddr*)&client_addr, &client_addr_len));
    assert_b(client_sock.as_handle() >= 0);

    return run_mainloop(dev.as_handle(), client_sock.as_handle());
}

auto run_client(const uint32_t address, const uint16_t port) -> bool {
    unwrap_ob(dev, setup_tap_dev(to_inet_addr(192, 168, 2, 2)));

    const auto sock = FileDescriptor(socket(AF_INET, SOCK_STREAM, 0));
    assert_b(sock.as_handle() >= 0);

    const auto server_addr = sockaddr_in{
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr   = {
              .s_addr = htonl(address),
        },
    };
    assert_b(connect(sock.as_handle(), (sockaddr*)&server_addr, sizeof(server_addr)) == 0);

    return run_mainloop(dev.as_handle(), sock.as_handle());
}

auto run(const int argc, const char* const argv[]) -> bool {
    assert_b(argc >= 2);
    const auto command = std::string_view(argv[1]);
    if(command == "server") {
        assert_b(argc == 3);
        unwrap_ob(port, from_chars<uint16_t>(argv[2]));
        assert_b(run_server(port));
        return true;
    } else if(command == "client") {
        assert_b(argc == 4);
        unwrap_ob(addr, to_inet_addr(argv[2]));
        unwrap_ob(port, from_chars<uint16_t>(argv[3]));
        assert_b(run_client(addr, port));
        return true;
    } else {
        assert_b(false, "unknown command");
    }
}
} // namespace

auto main(const int argc, const char* const argv[]) -> int {
    return run(argc, argv) ? 0 : 1;
}
