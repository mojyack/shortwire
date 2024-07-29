#include <openssl/evp.h>

#include "aes.hpp"
#include "macros/autoptr.hpp"
#include "macros/unwrap.hpp"

namespace {
declare_autoptr(CipherContext, EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);

auto is_valid_key(const std::span<const std::byte> key) -> bool {
    return key.size() == 128 / 8 || key.size() == 192 / 8 || key.size() == 256 / 8;
}

auto cipher_suite_from_key_size(const size_t size) -> const EVP_CIPHER* {
    switch(size) {
    case 128 / 8:
        return EVP_aes_128_cbc();
    case 192 / 8:
        return EVP_aes_192_cbc();
    case 256 / 8:
        return EVP_aes_256_cbc();
    default:
        return nullptr;
    }
}
} // namespace

namespace aes {
auto encrypt(std::span<const std::byte> key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>> {
    assert_o(is_valid_key(key));
    auto ctx = AutoCipherContext(EVP_CIPHER_CTX_new());
    assert_o(ctx.get() != NULL);

    unwrap_po(suite, cipher_suite_from_key_size(key.size()));
    assert_o(EVP_EncryptInit(ctx.get(), &suite, (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    auto ret = std::vector<std::byte>((data.size() / block_size + 1) * block_size); // padding required(even if data.size() % block_size == 0)
    auto len = 0;
    assert_o(EVP_EncryptUpdate(ctx.get(), (unsigned char*)ret.data(), &len, (unsigned char*)data.data(), data.size()) != 0);
    assert_o(EVP_EncryptFinal(ctx.get(), (unsigned char*)ret.data() + len, &len) != 0);
    return ret;
}

auto decrypt(std::span<const std::byte> key, const IV& iv, std::span<const std::byte> data) -> std::optional<std::vector<std::byte>> {
    assert_o(is_valid_key(key));
    auto ctx = AutoCipherContext(EVP_CIPHER_CTX_new());
    assert_o(ctx.get() != NULL);

    unwrap_po(suite, cipher_suite_from_key_size(key.size()));
    assert_o(EVP_DecryptInit(ctx.get(), &suite, (unsigned char*)key.data(), (unsigned char*)iv.data()) != 0);

    auto ret        = std::vector<std::byte>(data.size());
    auto body_len   = 0;
    auto remain_len = 0;
    assert_o(EVP_DecryptUpdate(ctx.get(), (unsigned char*)ret.data(), &body_len, (unsigned char*)data.data(), data.size()) != 0);
    assert_o(EVP_DecryptFinal(ctx.get(), (unsigned char*)ret.data() + body_len, &remain_len) != 0);
    ret.resize(body_len + remain_len);
    return ret;
}
} // namespace aes
