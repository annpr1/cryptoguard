#include "crypto_guard_ctx.h"

#include <algorithm>
#include <array>
#include <climits>
#include <iomanip>
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {
namespace {

constexpr int BUFFER_SIZE = 4096;
constexpr int SALT_SIZE = 16;

struct AesCipherParams {
    std::array<unsigned char, 32> key{};
    std::array<unsigned char, 16> iv{};
};

void CheckOpenSSL(bool success, const std::string &message) {
    if (success) {
        return;
    }
    std::string details = message;
    unsigned long code;
    while ((code = ERR_get_error()) != 0) {
        std::array<char, 256> buffer{};
        ERR_error_string_n(code, buffer.data(), buffer.size());
        details += ": ";
        details += buffer.data();
    }
    throw std::runtime_error(details);
}

void CheckInput(std::iostream &input) {
    if (!input.good()) {
        throw std::runtime_error("Input stream is not ready");
    }
}

void CheckOutput(std::iostream &output) {
    if (!output.good()) {
        throw std::runtime_error("Output stream is not ready");
    }
}

int ReadBlock(std::iostream &input, unsigned char *buffer, int size) {
    input.read(reinterpret_cast<char *>(buffer), size);
    if (input.bad() || (input.fail() && !input.eof())) {
        throw std::runtime_error("Failed to read input stream");
    }
    return static_cast<int>(input.gcount());
}

void WriteBlock(std::iostream &output, const unsigned char *buffer, int size) {
    output.write(reinterpret_cast<const char *>(buffer), size);
    if (!output) {
        throw std::runtime_error("Failed to write output stream");
    }
}

}  // namespace

class CryptoGuardCtx::Impl {
public:
    Impl() {
        CheckOpenSSL(OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr) == 1,
                     "Failed to initialize OpenSSL");
    }

    ~Impl() { EVP_cleanup(); }

    void EncryptFile(std::iostream &input, std::iostream &output, std::string_view password) {
        Process(input, output, password, true);
    }

    void DecryptFile(std::iostream &input, std::iostream &output, std::string_view password) {
        Process(input, output, password, false);
    }

    std::string CalculateChecksum(std::iostream &input) {
        CheckInput(input);
        ERR_clear_error();
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        CheckOpenSSL(ctx != nullptr, "Failed to create digest context");
        CheckOpenSSL(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1, "EVP_DigestInit_ex failed");

        std::array<unsigned char, BUFFER_SIZE> buffer{};
        while (!input.eof()) {
            int size = ReadBlock(input, buffer.data(), buffer.size());
            CheckOpenSSL(EVP_DigestUpdate(ctx.get(), buffer.data(), size) == 1, "EVP_DigestUpdate failed");
        }

        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int size = 0;
        CheckOpenSSL(EVP_DigestFinal_ex(ctx.get(), digest.data(), &size) == 1, "EVP_DigestFinal_ex failed");

        std::stringstream result;
        result << std::hex << std::setfill('0');
        for (unsigned int i = 0; i < size; ++i) {
            result << std::setw(2) << static_cast<unsigned int>(digest[i]);
        }
        if (!result) {
            throw std::runtime_error("Failed to format checksum");
        }
        return result.str();
    }

private:
    AesCipherParams CreateChiperParamsFromPassword(std::string_view password,
                                                   const std::array<unsigned char, SALT_SIZE> &salt) {
        if (password.empty() || password.size() > INT_MAX) {
            throw std::runtime_error("Password must be non-empty and fit into int");
        }
        std::array<unsigned char, 48> bytes{};
        CheckOpenSSL(PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()), salt.data(), salt.size(),
                                       600000, EVP_sha256(), bytes.size(), bytes.data()) == 1,
                     "Failed to derive key and IV from password");
        AesCipherParams params;
        std::copy_n(bytes.begin(), params.key.size(), params.key.begin());
        std::copy_n(bytes.begin() + params.key.size(), params.iv.size(), params.iv.begin());
        OPENSSL_cleanse(bytes.data(), bytes.size());
        return params;
    }

    void Process(std::iostream &input, std::iostream &output, std::string_view password, bool encrypt) {
        CheckInput(input);
        CheckOutput(output);
        if (&input == &output) {
            throw std::runtime_error("Input and output must be different streams");
        }
        ERR_clear_error();
        std::array<unsigned char, SALT_SIZE> salt{};
        if (encrypt) {
            CheckOpenSSL(RAND_bytes(salt.data(), salt.size()) == 1, "Failed to generate salt");
        } else if (ReadBlock(input, salt.data(), salt.size()) != SALT_SIZE) {
            throw std::runtime_error("Encrypted input is too short: missing salt");
        }

        auto params = CreateChiperParamsFromPassword(password, salt);
        std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
        CheckOpenSSL(ctx != nullptr, "Failed to create cipher context");
        int initialized = EVP_CipherInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, params.key.data(), params.iv.data(),
                                            encrypt ? 1 : 0);
        OPENSSL_cleanse(params.key.data(), params.key.size());
        CheckOpenSSL(initialized == 1, "EVP_CipherInit_ex failed");
        if (encrypt) {
            WriteBlock(output, salt.data(), salt.size());
        }

        std::array<unsigned char, BUFFER_SIZE> inBuffer{};
        std::array<unsigned char, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH> outBuffer{};
        int outSize = 0;
        while (!input.eof()) {
            int inSize = ReadBlock(input, inBuffer.data(), inBuffer.size());
            CheckOpenSSL(EVP_CipherUpdate(ctx.get(), outBuffer.data(), &outSize, inBuffer.data(), inSize) == 1,
                         "EVP_CipherUpdate failed");
            WriteBlock(output, outBuffer.data(), outSize);
        }
        CheckOpenSSL(EVP_CipherFinal_ex(ctx.get(), outBuffer.data(), &outSize) == 1,
                     encrypt ? "Encryption finalization failed" : "Decryption failed: wrong password or damaged data");
        WriteBlock(output, outBuffer.data(), outSize);
        output.flush();
        CheckOutput(output);
    }
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}
CryptoGuardCtx::~CryptoGuardCtx() = default;
CryptoGuardCtx::CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
CryptoGuardCtx &CryptoGuardCtx::operator=(CryptoGuardCtx &&) noexcept = default;

void CryptoGuardCtx::EncryptFile(std::iostream &input, std::iostream &output, std::string_view password) {
    if (!pImpl_) {
        throw std::runtime_error("CryptoGuardCtx has been moved from");
    }
    pImpl_->EncryptFile(input, output, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &input, std::iostream &output, std::string_view password) {
    if (!pImpl_) {
        throw std::runtime_error("CryptoGuardCtx has been moved from");
    }
    pImpl_->DecryptFile(input, output, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &input) {
    if (!pImpl_) {
        throw std::runtime_error("CryptoGuardCtx has been moved from");
    }
    return pImpl_->CalculateChecksum(input);
}

}  // namespace CryptoGuard
