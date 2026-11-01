#include "cmd_options.h"
#include "crypto_guard_ctx.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>

namespace fs = std::filesystem;

class TemporaryOutput {
public:
    explicit TemporaryOutput(const fs::path &target) : directory_(target.string() + ".tmp") {
        if (!fs::create_directory(directory_)) {
            throw std::runtime_error("Temporary directory already exists: " + directory_.string());
        }
    }

    ~TemporaryOutput() {
        std::error_code error;
        fs::remove(GetPath(), error);
        fs::remove(directory_, error);
    }

    TemporaryOutput(const TemporaryOutput &) = delete;
    TemporaryOutput &operator=(const TemporaryOutput &) = delete;

    fs::path GetPath() const { return directory_ / "result"; }

private:
    fs::path directory_;
};

void CloseInput(std::fstream &input) {
    input.clear();
    input.close();
    if (input.fail()) {
        throw std::runtime_error("Failed to close input file");
    }
}

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;
        options.Parse(argc, argv);
        if (options.IsHelp()) {
            return 0;
        }

        std::fstream input(options.GetInputFile(), std::ios::in | std::ios::binary);
        if (!input.is_open()) {
            throw std::runtime_error("Cannot open input: " + options.GetInputFile());
        }
        if (!fs::is_regular_file(options.GetInputFile())) {
            throw std::runtime_error("Input must be a regular file");
        }

        CryptoGuard::CryptoGuardCtx crypto;
        using Command = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        auto command = options.GetCommand();
        auto outputPath = options.GetOutputFile();
        if (command == Command::CHECKSUM && outputPath.empty()) {
            auto checksum = crypto.CalculateChecksum(input);
            CloseInput(input);
            std::cout << checksum << '\n';
            std::cout.flush();
            if (!std::cout) {
                throw std::runtime_error("Failed to print checksum");
            }
            return 0;
        }

        if (fs::exists(fs::symlink_status(outputPath))) {
            throw std::runtime_error("Output already exists: choose another path");
        }
        TemporaryOutput temporary(outputPath);
        fs::permissions(temporary.GetPath().parent_path(), fs::perms::owner_all);
        std::fstream output(temporary.GetPath(), std::ios::out | std::ios::binary | std::ios::trunc);
        if (!output.is_open()) {
            throw std::runtime_error("Cannot open output file");
        }

        switch (command) {
        case Command::ENCRYPT:
            crypto.EncryptFile(input, output, options.GetPassword());
            break;
        case Command::DECRYPT:
            crypto.DecryptFile(input, output, options.GetPassword());
            break;
        case Command::CHECKSUM:
            output << crypto.CalculateChecksum(input) << '\n';
            break;
        }
        output.flush();
        if (!output) {
            throw std::runtime_error("Failed to flush output file");
        }
        output.close();
        if (output.fail()) {
            throw std::runtime_error("Failed to close output file");
        }
        CloseInput(input);
        fs::create_hard_link(temporary.GetPath(), outputPath);
        std::cout << "Done\n";
    } catch (const std::exception &error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 1;
    }
}
