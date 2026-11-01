#pragma once

#include <iosfwd>
#include <memory>
#include <string>
#include <string_view>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx(CryptoGuardCtx &&) noexcept;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept;

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

}  // namespace CryptoGuard
