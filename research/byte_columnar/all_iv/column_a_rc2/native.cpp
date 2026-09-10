#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
extern "C" {
int rc2_LTX__mcrypt_set_key(uint16_t*, const unsigned char*, unsigned int);
void rc2_LTX__mcrypt_encrypt(const uint16_t*, uint16_t*);
}
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error("invalid hex");
}
static std::vector<unsigned char> unhex(const std::string& value) {
    if (value.size() % 2) throw std::runtime_error("odd hex");
    std::vector<unsigned char> output;
    output.reserve(value.size() / 2);
    for (size_t i = 0; i < value.size(); i += 2)
        output.push_back(static_cast<unsigned char>((hex_value(value[i]) << 4) | hex_value(value[i + 1])));
    return output;
}
static std::string hex(const unsigned char* data, size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string output;
    output.reserve(2 * size);
    for (size_t i = 0; i < size; ++i) {
        output.push_back(digits[data[i] >> 4]);
        output.push_back(digits[data[i] & 15]);
    }
    return output;
}
static std::string hex(const std::vector<unsigned char>& data) { return hex(data.data(), data.size()); }
struct ECB {
    std::string name;
    std::array<uint16_t, 64> schedule{};
    explicit ECB(const std::string& requested) : name(requested) {
        const unsigned char key[7] = {'Z','o','m','b','i','e','s'};
        if (name != "rc2") throw std::runtime_error("backend must be rc2");
        if (rc2_LTX__mcrypt_set_key(schedule.data(), key, 7))
            throw std::runtime_error("RC2 key setup failed");
    }
    void encrypt(const unsigned char* input, unsigned char* output) const {
        std::array<uint16_t, 4> words{};
        std::memcpy(words.data(), input, 8);
        rc2_LTX__mcrypt_encrypt(schedule.data(), words.data());
        std::memcpy(output, words.data(), 8);
    }
    unsigned char first(const unsigned char* input) const {
        unsigned char output[8];
        encrypt(input, output);
        return output[0];
    }
};

static bool allowed(unsigned char value) {
    return value == 9 || value == 10 || value == 13 ||
           (value >= 32 && value <= 126) ||
           value == 0xe2 || value == 0x80 || value == 0x93 ||
           value == 0x94 || value == 0x98 || value == 0x99 || value == 0xa6;
}
static uint64_t permutation_count(int n, int k) {
    uint64_t value = 1;
    for (int i = 0; i < k; ++i) value *= static_cast<uint64_t>(n - i);
    return value;
}
static uint64_t factorial(int n) {
    uint64_t value = 1;
    for (int i = 2; i <= n; ++i) value *= static_cast<uint64_t>(i);
    return value;
}

struct Survivor {
    std::array<int, 8> prefix{};
    uint64_t candidates = 0;
};
struct Search {
    ECB ecb;
    const std::vector<unsigned char>& observed;
    int width;
    int rows;
    uint64_t limit;
    bool retain;
    std::array<int, 8> prefix{};
    uint64_t used = 0;
    uint64_t examined = 0;
    uint64_t rejected = 0;
    uint64_t survivor_count = 0;
    uint64_t block_calls = 0;
    uint64_t rows_checked = 0;
    uint64_t candidate_tests = 0;
    uint64_t survivor_digest = 14695981039346656037ULL;
    std::vector<Survivor> survivors;

    Search(const std::string& backend, const std::vector<unsigned char>& input,
           int requested_width, uint64_t requested_limit, bool requested_retain)
        : ecb(backend), observed(input), width(requested_width), rows(0),
          limit(requested_limit), retain(requested_retain) {
        if (width <= 8 || width > 20) throw std::runtime_error("width must be 9..20");
        if (observed.empty() || observed.size() % static_cast<size_t>(width))
            throw std::runtime_error("nonempty rectangular observed bytes required");
        if (!limit) throw std::runtime_error("prefix limit must be positive");
        rows = static_cast<int>(observed.size()) / width;
    }
    void digest_byte(unsigned char value) {
        survivor_digest ^= value;
        survivor_digest *= 1099511628211ULL;
    }
    void evaluate() {
        ++examined;
        uint64_t candidates = ((uint64_t{1} << width) - 1) & ~used;
        unsigned char block[8];
        for (int row = 0; row < rows && candidates; ++row) {
            for (int natural = 0; natural < 8; ++natural)
                block[natural] = observed[static_cast<size_t>(prefix[natural]) * rows + row];
            unsigned char key_byte = ecb.first(block);
            ++block_calls;
            ++rows_checked;
            uint64_t retained = 0;
            for (int rank = 0; rank < width; ++rank) {
                if (!(candidates & (uint64_t{1} << rank))) continue;
                ++candidate_tests;
                unsigned char ciphertext = observed[static_cast<size_t>(rank) * rows + row];
                if (allowed(static_cast<unsigned char>(ciphertext ^ key_byte)))
                    retained |= uint64_t{1} << rank;
            }
            candidates = retained;
        }
        if (!candidates) {
            ++rejected;
            return;
        }
        ++survivor_count;
        for (int value : prefix) digest_byte(static_cast<unsigned char>(value));
        for (int rank = 0; rank < width; ++rank)
            if (candidates & (uint64_t{1} << rank)) digest_byte(static_cast<unsigned char>(rank));
        digest_byte(0xff);
        if (retain) survivors.push_back({prefix, candidates});
    }
    void recurse(int depth) {
        if (examined >= limit) return;
        if (depth == 8) {
            evaluate();
            return;
        }
        for (int rank = 0; rank < width; ++rank) {
            uint64_t bit = uint64_t{1} << rank;
            if (used & bit) continue;
            prefix[depth] = rank;
            used |= bit;
            recurse(depth + 1);
            used &= ~bit;
            if (examined >= limit) return;
        }
    }
};

static std::vector<unsigned char> cfb8(const ECB& ecb, const std::vector<unsigned char>& input,
                                        const std::vector<unsigned char>& iv, bool decrypt) {
    if (iv.size() != 8) throw std::runtime_error("IV must be 8 bytes");
    std::array<unsigned char, 8> register_bytes{};
    std::copy(iv.begin(), iv.end(), register_bytes.begin());
    std::vector<unsigned char> output;
    output.reserve(input.size());
    for (unsigned char value : input) {
        unsigned char transformed[8];
        ecb.encrypt(register_bytes.data(), transformed);
        unsigned char result = static_cast<unsigned char>(value ^ transformed[0]);
        unsigned char ciphertext = decrypt ? value : result;
        output.push_back(result);
        for (size_t i = 1; i < register_bytes.size(); ++i) register_bytes[i - 1] = register_bytes[i];
        register_bytes.back() = ciphertext;
    }
    return output;
}

int main(int argc, char** argv) {
    try {
        if (argc == 4 && std::string(argv[1]) == "--block") {
            ECB ecb(argv[2]);
            auto input = unhex(argv[3]);
            if (input.size() != 8) throw std::runtime_error("block must be 8 bytes");
            unsigned char output[8];
            ecb.encrypt(input.data(), output);
            std::cout << hex(output, 8) << "\n";
            return 0;
        }
        if (argc == 5 && (std::string(argv[1]) == "--cfb-encrypt" ||
                          std::string(argv[1]) == "--cfb-decrypt")) {
            ECB ecb(argv[2]);
            auto iv = unhex(argv[3]);
            auto input = unhex(argv[4]);
            auto output = cfb8(ecb, input, iv, std::string(argv[1]) == "--cfb-decrypt");
            std::cout << hex(output) << "\n";
            return 0;
        }
        if (argc < 6 || std::string(argv[1]) != "--search")
            throw std::runtime_error("usage: --block BACKEND BLOCKHEX | --cfb-{encrypt,decrypt} BACKEND IVHEX DATAHEX | --search BACKEND WIDTH PREFIX_LIMIT OBSERVEDHEX [--count-only]");
        std::string backend = argv[2];
        int width = std::stoi(argv[3]);
        uint64_t limit = std::stoull(argv[4]);
        auto observed = unhex(argv[5]);
        bool retain = true;
        if (argc == 7) {
            if (std::string(argv[6]) != "--count-only") throw std::runtime_error("unknown search option");
            retain = false;
        } else if (argc != 6) {
            throw std::runtime_error("bad search arguments");
        }
        auto start = std::chrono::steady_clock::now();
        Search search(backend, observed, width, limit, retain);
        search.recurse(0);
        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        uint64_t total_prefixes = permutation_count(width, 8);
        uint64_t completion_weight = factorial(width - 8);
        uint64_t rejected_weight = search.rejected * completion_weight;
        uint64_t unresolved_weight = search.survivor_count * completion_weight;
        uint64_t unexamined = total_prefixes - search.examined;
        uint64_t unexamined_weight = unexamined * completion_weight;
        if (search.examined > total_prefixes) throw std::runtime_error("prefix accounting overflow");
        if (rejected_weight + unresolved_weight + unexamined_weight != factorial(width))
            throw std::runtime_error("factorial partition failed");
        std::ostringstream digest;
        digest << std::hex << std::setw(16) << std::setfill('0') << search.survivor_digest;
        std::cout << "{\"identity\":\"ASTRA\",\"backend\":\"" << backend
                  << "\",\"width\":" << width << ",\"rows\":" << search.rows
                  << ",\"prefix_limit\":" << limit
                  << ",\"total_prefixes\":" << total_prefixes
                  << ",\"prefixes_examined\":" << search.examined
                  << ",\"rejected_prefixes\":" << search.rejected
                  << ",\"survivor_prefix_count\":" << search.survivor_count
                  << ",\"completion_weight_per_prefix\":" << completion_weight
                  << ",\"rejected_completion_weight\":" << rejected_weight
                  << ",\"unresolved_examined_completion_weight\":" << unresolved_weight
                  << ",\"unexamined_prefixes\":" << unexamined
                  << ",\"unexamined_completion_weight\":" << unexamined_weight
                  << ",\"expected_completion_weight\":" << factorial(width)
                  << ",\"factorial_partition_complete\":true"
                  << ",\"complete_scan\":" << (search.examined == total_prefixes ? "true" : "false")
                  << ",\"block_calls\":" << search.block_calls
                  << ",\"rows_checked\":" << search.rows_checked
                  << ",\"candidate_tests\":" << search.candidate_tests
                  << ",\"survivor_digest_fnv1a64\":\"" << digest.str() << "\""
                  << ",\"survivors_retained\":" << (retain ? "true" : "false")
                  << ",\"elapsed_seconds\":" << seconds << ",\"survivor_prefixes\":[";
        if (retain) {
            for (size_t index = 0; index < search.survivors.size(); ++index) {
                if (index) std::cout << ",";
                const auto& row = search.survivors[index];
                std::cout << "{\"first_slots\":[";
                for (int j = 0; j < 8; ++j) {
                    if (j) std::cout << ",";
                    std::cout << row.prefix[j];
                }
                std::cout << "],\"surviving_ninth_ranks\":[";
                bool first = true;
                for (int rank = 0; rank < width; ++rank) {
                    if (!(row.candidates & (uint64_t{1} << rank))) continue;
                    if (!first) std::cout << ",";
                    first = false;
                    std::cout << rank;
                }
                std::cout << "]}";
            }
        }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
