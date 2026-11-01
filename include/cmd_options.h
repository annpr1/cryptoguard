#pragma once

#include <boost/program_options.hpp>
#include <string>
#include <string_view>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions();

    enum class COMMAND_TYPE { ENCRYPT, DECRYPT, CHECKSUM };

    void Parse(int argc, char *argv[]);

    COMMAND_TYPE GetCommand() const { return command_; }
    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }
    bool IsHelp() const { return help_; }

private:
    COMMAND_TYPE command_ = COMMAND_TYPE::CHECKSUM;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"encrypt", COMMAND_TYPE::ENCRYPT},
        {"decrypt", COMMAND_TYPE::DECRYPT},
        {"checksum", COMMAND_TYPE::CHECKSUM},
    };
    std::string inputFile_;
    std::string outputFile_;
    std::string password_;
    bool help_ = false;
    boost::program_options::options_description desc_;
};

}  // namespace CryptoGuard
