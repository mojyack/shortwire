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

#include "macros/assert.hpp"
#include "util/fd.hpp"

auto print_mac_addr(const uint8_t* const addr) -> void {
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

auto setup_tap_dev(const uint32_t address) -> std::optional<int> {
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

    return dev.release();
}
