#include "fuzz_seed_data.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

namespace {

bool WriteSeed(const std::filesystem::path &root, const wgnx::fuzz::FuzzSeed &seed) {
    const std::filesystem::path path = root / std::filesystem::path{seed.relative_path};
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    if (error) {
        std::cerr << "failed to create " << path.parent_path() << ": " << error.message()
                  << '\n';
        return false;
    }

    std::ofstream output{path, std::ios::binary | std::ios::trunc};
    if (!output) {
        std::cerr << "failed to open " << path << '\n';
        return false;
    }

    output.write(seed.bytes.data(), static_cast<std::streamsize>(seed.bytes.size()));
    if (!output) {
        std::cerr << "failed to write " << path << '\n';
        return false;
    }
    return true;
}

} // namespace

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "usage: fuzz_seed_writer <output-directory>\n";
        return 1;
    }

    const std::filesystem::path output_directory{argv[1]};
    for (const wgnx::fuzz::FuzzSeed &seed : wgnx::fuzz::kBinaryFuzzSeeds) {
        if (!WriteSeed(output_directory, seed)) {
            return 1;
        }
    }
    return 0;
}
