#include "cmd_options.h"

#include <gtest/gtest.h>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

using CryptoGuard::ProgramOptions;
using Command = ProgramOptions::COMMAND_TYPE;

void Parse(ProgramOptions &options, std::vector<std::string> args) {
    args.insert(args.begin(), "CryptoGuard");
    std::vector<char *> argv;
    for (auto &arg : args) {
        argv.push_back(arg.data());
    }
    int argc = static_cast<int>(argv.size());
    argv.push_back(nullptr);
    options.Parse(argc, argv.data());
}

TEST(ProgramOptions, Encrypt) {
    ProgramOptions options;
    Parse(options, {"--command", "encrypt", "--input", "in", "--output", "out", "--password", "pass"});
    EXPECT_EQ(options.GetCommand(), Command::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "in");
    EXPECT_EQ(options.GetOutputFile(), "out");
    EXPECT_EQ(options.GetPassword(), "pass");
    EXPECT_FALSE(options.IsHelp());
}

TEST(ProgramOptions, DecryptShortOptions) {
    ProgramOptions options;
    Parse(options, {"-c", "decrypt", "-i", "in", "-o", "out", "-p", "pass"});
    EXPECT_EQ(options.GetCommand(), Command::DECRYPT);
    EXPECT_EQ(options.GetPassword(), "pass");
}

TEST(ProgramOptions, Checksum) {
    ProgramOptions options;
    Parse(options, {"--command", "checksum", "--input", "in"});
    EXPECT_EQ(options.GetCommand(), Command::CHECKSUM);
    EXPECT_TRUE(options.GetOutputFile().empty());
}

TEST(ProgramOptions, ChecksumToFile) {
    ProgramOptions options;
    Parse(options, {"-c", "checksum", "-i", "in", "-o", "hash.txt"});
    EXPECT_EQ(options.GetOutputFile(), "hash.txt");
}

TEST(ProgramOptions, Help) {
    ProgramOptions options;
    EXPECT_NO_THROW(Parse(options, {"--help"}));
    EXPECT_TRUE(options.IsHelp());
}

TEST(ProgramOptions, MissingCommand) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {}), std::runtime_error);
}

TEST(ProgramOptions, UnknownCommand) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "remove", "-i", "in"}), std::runtime_error);
}

TEST(ProgramOptions, MissingInput) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "checksum"}), std::runtime_error);
}

TEST(ProgramOptions, MissingOutput) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "encrypt", "-i", "in", "-p", "pass"}), std::runtime_error);
}

TEST(ProgramOptions, MissingPassword) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "decrypt", "-i", "in", "-o", "out"}), std::runtime_error);
}

TEST(ProgramOptions, EmptyValues) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "checksum", "-i", ""}), std::runtime_error);
    ASSERT_THROW(Parse(options, {"-c", "encrypt", "-i", "in", "-o", "out", "-p", ""}), std::runtime_error);
    ASSERT_THROW(Parse(options, {"-c", "checksum", "-i", "in", "-o", ""}), std::runtime_error);
}

TEST(ProgramOptions, SamePaths) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "encrypt", "-i", "in", "-o", "in", "-p", "pass"}), std::runtime_error);
}

TEST(ProgramOptions, UnknownOption) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"--unknown"}), std::runtime_error);
}

TEST(ProgramOptions, MissingOptionValue) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"--input"}), std::runtime_error);
}

TEST(ProgramOptions, DuplicateOption) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "checksum", "-c", "encrypt", "-i", "in"}), std::runtime_error);
}

TEST(ProgramOptions, PasswordForChecksum) {
    ProgramOptions options;
    ASSERT_THROW(Parse(options, {"-c", "checksum", "-i", "in", "-p", "pass"}), std::runtime_error);
}

TEST(ProgramOptions, ParseAgain) {
    ProgramOptions options;
    Parse(options, {"-c", "encrypt", "-i", "in", "-o", "out", "-p", "pass"});
    Parse(options, {"-c", "checksum", "-i", "another"});
    EXPECT_TRUE(options.GetPassword().empty());
    EXPECT_TRUE(options.GetOutputFile().empty());
    EXPECT_EQ(options.GetInputFile(), "another");
}
