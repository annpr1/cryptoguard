#include "crypto_guard_ctx.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <utility>

using CryptoGuard::CryptoGuardCtx;

TEST(Encrypt, ChangesData) {
    CryptoGuardCtx ctx;
    std::stringstream input("hello"), output;
    ctx.EncryptFile(input, output, "pass");
    EXPECT_NE(output.str(), "hello");
    EXPECT_EQ(output.str().size(), 32u);
}

TEST(Encrypt, EmptyInput) {
    CryptoGuardCtx ctx;
    std::stringstream input, output;
    ctx.EncryptFile(input, output, "pass");
    EXPECT_EQ(output.str().size(), 32u);
}

TEST(Encrypt, BadInput) {
    CryptoGuardCtx ctx;
    std::stringstream input, output;
    input.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.EncryptFile(input, output, "pass"), std::runtime_error);
}

TEST(Encrypt, BadOutput) {
    CryptoGuardCtx ctx;
    std::stringstream input("hello"), output;
    output.setstate(std::ios::failbit);
    ASSERT_THROW(ctx.EncryptFile(input, output, "pass"), std::runtime_error);
}

TEST(Encrypt, EmptyPassword) {
    CryptoGuardCtx ctx;
    std::stringstream input("hello"), output;
    ASSERT_THROW(ctx.EncryptFile(input, output, ""), std::runtime_error);
}

TEST(Encrypt, RandomSalt) {
    CryptoGuardCtx ctx;
    std::stringstream input1("hello"), input2("hello"), output1, output2;
    ctx.EncryptFile(input1, output1, "pass");
    ctx.EncryptFile(input2, output2, "pass");
    EXPECT_NE(output1.str(), output2.str());
}

TEST(Decrypt, RestoresText) {
    CryptoGuardCtx ctx;
    std::stringstream input("Hello, world!"), encrypted, decrypted;
    ctx.EncryptFile(input, encrypted, "pass");
    ctx.DecryptFile(encrypted, decrypted, "pass");
    EXPECT_EQ(decrypted.str(), "Hello, world!");
}

TEST(Decrypt, RestoresEmptyInput) {
    CryptoGuardCtx ctx;
    std::stringstream input, encrypted, decrypted;
    ctx.EncryptFile(input, encrypted, "pass");
    ctx.DecryptFile(encrypted, decrypted, "pass");
    EXPECT_TRUE(decrypted.str().empty());
}

TEST(Decrypt, TruncatedCiphertext) {
    CryptoGuardCtx ctx;
    std::stringstream input("hello"), encrypted, output;
    ctx.EncryptFile(input, encrypted, "pass");
    auto data = encrypted.str();
    data.pop_back();
    std::stringstream broken(data);
    ASSERT_THROW(ctx.DecryptFile(broken, output, "pass"), std::runtime_error);
}

TEST(Decrypt, MissingSalt) {
    CryptoGuardCtx ctx;
    std::stringstream input("short"), output;
    ASSERT_THROW(ctx.DecryptFile(input, output, "pass"), std::runtime_error);
}

TEST(Decrypt, BadInput) {
    CryptoGuardCtx ctx;
    std::stringstream input, output;
    input.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.DecryptFile(input, output, "pass"), std::runtime_error);
}

TEST(Decrypt, BadOutput) {
    CryptoGuardCtx ctx;
    std::stringstream input, output;
    output.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.DecryptFile(input, output, "pass"), std::runtime_error);
}

TEST(Checksum, KnownString) {
    CryptoGuardCtx ctx;
    std::stringstream input("abc");
    EXPECT_EQ(ctx.CalculateChecksum(input), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Checksum, EmptyInput) {
    CryptoGuardCtx ctx;
    std::stringstream input;
    EXPECT_EQ(ctx.CalculateChecksum(input), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Checksum, BadInput) {
    CryptoGuardCtx ctx;
    std::stringstream input;
    input.setstate(std::ios::badbit);
    ASSERT_THROW(ctx.CalculateChecksum(input), std::runtime_error);
}

TEST(CryptoGuardCtx, BinaryDataAndBufferBoundaries) {
    CryptoGuardCtx ctx;
    for (int size : {15, 16, 17, 4095, 4096, 4097, 10000}) {
        SCOPED_TRACE(size);
        std::string data(size, '\0');
        for (int i = 0; i < size; ++i) {
            data[i] = static_cast<char>(i % 256);
        }
        std::stringstream original(data), input(data), encrypted, decrypted;
        auto checksum = ctx.CalculateChecksum(original);
        ctx.EncryptFile(input, encrypted, "pass");
        ctx.DecryptFile(encrypted, decrypted, "pass");
        EXPECT_EQ(decrypted.str(), data);
        EXPECT_EQ(ctx.CalculateChecksum(decrypted), checksum);
    }
}

TEST(CryptoGuardCtx, MoveOperations) {
    CryptoGuardCtx first;
    CryptoGuardCtx second(std::move(first));
    CryptoGuardCtx third;
    third = std::move(second);
    std::stringstream input("abc");
    EXPECT_EQ(third.CalculateChecksum(input), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    std::stringstream another("abc");
    ASSERT_THROW(first.CalculateChecksum(another), std::runtime_error);
    ASSERT_THROW(second.CalculateChecksum(another), std::runtime_error);
}

TEST(CryptoGuardCtx, SameStream) {
    CryptoGuardCtx ctx;
    std::stringstream input("abc");
    ASSERT_THROW(ctx.EncryptFile(input, input, "pass"), std::runtime_error);
}

TEST(Decrypt, KnownCiphertext) {
    CryptoGuardCtx ctx;
    const unsigned char data[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xf0, 0x26, 0x02, 0xf3, 0x70, 0xe5,
                                  0xc0, 0x26, 0x77, 0x0a, 0x48, 0xa2, 0xc3, 0xe0, 0x4a, 0x21};
    std::string ciphertext(reinterpret_cast<const char *>(data), sizeof(data));
    std::stringstream input(ciphertext), output;
    ctx.DecryptFile(input, output, "pass");
    EXPECT_EQ(output.str(), "hello");
    std::stringstream wrongInput(ciphertext), wrongOutput;
    ASSERT_THROW(ctx.DecryptFile(wrongInput, wrongOutput, "wrong"), std::runtime_error);
}

class FailingWriteBuffer : public std::stringbuf {
protected:
    std::streamsize xsputn(const char *, std::streamsize) override { return 0; }
};

TEST(Encrypt, WriteFailureDuringProcessing) {
    CryptoGuardCtx ctx;
    std::stringstream input("hello"), output;
    FailingWriteBuffer buffer;
    auto *previous = static_cast<std::iostream &>(output).rdbuf(&buffer);
    EXPECT_THROW(ctx.EncryptFile(input, output, "pass"), std::runtime_error);
    static_cast<std::iostream &>(output).rdbuf(previous);
}
