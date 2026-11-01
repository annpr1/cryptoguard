#include "cmd_options.h"

#include <iostream>
#include <stdexcept>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;
    auto add = desc_.add_options();
    add("help,h", "Show help");
    add("command,c", po::value<std::string>(), "encrypt, decrypt or checksum");
    add("input,i", po::value<std::string>(), "Input file");
    add("output,o", po::value<std::string>(), "Output file");
    add("password,p", po::value<std::string>(), "Password");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;
    help_ = false;
    inputFile_.clear();
    outputFile_.clear();
    password_.clear();
    command_ = COMMAND_TYPE::CHECKSUM;

    po::variables_map values;
    try {
        auto parser = po::command_line_parser(argc, argv).options(desc_);
        parser.style(po::command_line_style::default_style & ~po::command_line_style::allow_guessing);
        po::store(parser.run(), values);
        po::notify(values);
    } catch (const po::error &error) {
        throw std::runtime_error(error.what());
    }

    if (values.count("help")) {
        help_ = true;
        std::cout << desc_ << '\n';
        return;
    }

    if (!values.count("command")) {
        throw std::runtime_error("Specify --command");
    }
    auto command = values["command"].as<std::string>();
    auto it = commandMapping_.find(command);
    if (it == commandMapping_.end()) {
        throw std::runtime_error("Unknown command: " + command);
    }
    command_ = it->second;

    if (!values.count("input") || values["input"].as<std::string>().empty()) {
        throw std::runtime_error("Specify a non-empty --input");
    }
    inputFile_ = values["input"].as<std::string>();

    if (values.count("output")) {
        outputFile_ = values["output"].as<std::string>();
        if (outputFile_.empty()) {
            throw std::runtime_error("--output cannot be empty");
        }
    }
    if (values.count("password")) {
        password_ = values["password"].as<std::string>();
    }

    if (command_ == COMMAND_TYPE::CHECKSUM) {
        if (values.count("password")) {
            throw std::runtime_error("checksum does not use --password");
        }
        return;
    }
    if (outputFile_.empty()) {
        throw std::runtime_error("Specify --output for encrypt/decrypt");
    }
    if (password_.empty()) {
        throw std::runtime_error("Specify a non-empty --password for encrypt/decrypt");
    }
    if (inputFile_ == outputFile_) {
        throw std::runtime_error("Input and output must be different files");
    }
}

}  // namespace CryptoGuard
