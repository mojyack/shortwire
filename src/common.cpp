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

#include "common.hpp"
#include "macros/assert.hpp"
#include "util/fd.hpp"

auto print_mac_addr(const uint8_t* const addr) -> void {
    std::println("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
}

auto to_inet_addr(const char* const str) -> std::optional<uint32_t> {
    auto addr = in_addr();
    ensure(inet_aton(str, &addr) == 1);
    return ntohl(addr.s_addr);
}

auto setup_virtual_nic(const VNICParams& params) -> std::optional<int> {
    auto dev = FileDescriptor(open("/dev/net/tun", O_RDWR));
    ensure(dev.as_handle() >= 0);

    // create device
    auto ifr      = ifreq();
    ifr.ifr_flags = (params.tap ? IFF_TAP : IFF_TUN) | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun%d", IFNAMSIZ);
    ensure(ioctl(dev.as_handle(), TUNSETIFF, &ifr) == 0);
    std::println("interface created: {}", ifr.ifr_name);

    // dummy socket for setting parameters
    const auto sock = FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));

    // set address
    ifr.ifr_addr.sa_family                         = AF_INET;
    ((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr = htonl(params.address);
    ensure(ioctl(sock.as_handle(), SIOCSIFADDR, &ifr) == 0, "{}", strerror(errno));

    // set address mask
    ((sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr = htonl(params.mask);
    ensure(ioctl(sock.as_handle(), SIOCSIFNETMASK, &ifr) == 0);

    // set mtu
    ifr.ifr_mtu = params.mtu;
    ensure(ioctl(sock.as_handle(), SIOCSIFMTU, &ifr) == 0);

    // set flag
    ensure(ioctl(sock.as_handle(), SIOCGIFFLAGS, &ifr) == 0);
    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);
    ensure(ioctl(sock.as_handle(), SIOCSIFFLAGS, &ifr) == 0);

    return dev.release();
}

auto get_mtu(const int dev) -> std::optional<uint32_t> {
    auto ifr = ifreq();
    ensure(ioctl(dev, TUNGETIFF, &ifr) == 0);

    const auto sock = FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));
    ensure(ioctl(sock.as_handle(), SIOCGIFMTU, &ifr) == 0);
    return ifr.ifr_mtu;
}

auto set_mtu(const int dev, const uint32_t mtu) -> bool {
    auto ifr = ifreq();
    ensure(ioctl(dev, TUNGETIFF, &ifr) == 0);
    ifr.ifr_mtu = mtu;

    const auto sock = FileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));
    ensure(ioctl(sock.as_handle(), SIOCSIFMTU, &ifr) == 0);
    return true;
}
