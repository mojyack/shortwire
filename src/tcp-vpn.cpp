#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.hpp"
#include "macros/unwrap.hpp"
#include "util/charconv.hpp"
#include "util/fd.hpp"

namespace {
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
    unwrap_ob(dev, setup_tap_dev(to_inet_addr(192, 168, 2, 1), 1518));
    const auto auto_dev = FileDescriptor(dev);

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

    return run_mainloop(dev, client_sock.as_handle());
}

auto run_client(const uint32_t address, const uint16_t port) -> bool {
    unwrap_ob(dev, setup_tap_dev(to_inet_addr(192, 168, 2, 2), 1518));
    const auto auto_dev = FileDescriptor(dev);

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

    return run_mainloop(dev, sock.as_handle());
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
