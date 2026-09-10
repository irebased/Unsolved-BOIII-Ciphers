#include <openssl/blowfish.h>
#include <openssl/des.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

extern "C" {
int rc2_LTX__mcrypt_set_key(uint16_t*, const unsigned char*, unsigned int);
void rc2_LTX__mcrypt_encrypt(const uint16_t*, uint16_t*);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::runtime_error("invalid hex");
}
static std::vector<unsigned char> unhex(const std::string& value) {
    if (value.size() % 2) throw std::runtime_error("odd hex");
    std::vector<unsigned char> out;
    out.reserve(value.size() / 2);
    for (size_t i = 0; i < value.size(); i += 2)
        out.push_back(static_cast<unsigned char>((hex_value(value[i]) << 4) | hex_value(value[i + 1])));
    return out;
}
static std::string hex(const unsigned char* data, size_t size) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 15]);
    }
    return out;
}
static void reverse_words(const unsigned char* input, unsigned char* output) {
    for (int word = 0; word < 2; ++word)
        for (int byte = 0; byte < 4; ++byte)
            output[4 * word + byte] = input[4 * word + 3 - byte];
}

struct ECB {
    std::string name;
    DES_key_schedule des{};
    BF_KEY blowfish{};
    std::array<uint16_t, 64> rc2{};
    explicit ECB(const std::string& requested) : name(requested) {
        const unsigned char key7[7] = {'Z','o','m','b','i','e','s'};
        if (name == "des") {
            DES_cblock key{};
            std::memcpy(key, key7, 7);
            DES_set_key_unchecked(&key, &des);
        } else if (name == "blowfish" || name == "blowfish_compat") {
            BF_set_key(&blowfish, 7, key7);
        } else if (name == "rc2") {
            if (rc2_LTX__mcrypt_set_key(rc2.data(), key7, 7))
                throw std::runtime_error("RC2 key setup failed");
        } else {
            throw std::runtime_error("backend must be des, blowfish, blowfish_compat, or rc2");
        }
    }
    void encrypt(const unsigned char* input, unsigned char* output) const {
        if (name == "des") {
            DES_cblock in{}, out{};
            std::memcpy(in, input, 8);
            DES_ecb_encrypt(&in, &out, const_cast<DES_key_schedule*>(&des), DES_ENCRYPT);
            std::memcpy(output, out, 8);
        } else if (name == "blowfish") {
            BF_ecb_encrypt(input, output, const_cast<BF_KEY*>(&blowfish), BF_ENCRYPT);
        } else if (name == "blowfish_compat") {
            unsigned char transformed_input[8], transformed_output[8];
            reverse_words(input, transformed_input);
            BF_ecb_encrypt(transformed_input, transformed_output, const_cast<BF_KEY*>(&blowfish), BF_ENCRYPT);
            reverse_words(transformed_output, output);
        } else {
            std::array<uint16_t, 4> words{};
            std::memcpy(words.data(), input, 8);
            rc2_LTX__mcrypt_encrypt(rc2.data(), words.data());
            std::memcpy(output, words.data(), 8);
        }
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
static std::vector<int> parse_csv(const std::string& value) {
    std::vector<int> out;
    std::stringstream stream(value);
    std::string item;
    while (std::getline(stream, item, ',')) {
        if (item.empty()) throw std::runtime_error("empty assignment item");
        out.push_back(std::stoi(item));
    }
    return out;
}

struct Survivor {
    std::array<int, 6> assignment{};
    std::vector<unsigned char> plaintext_ninth;
};

struct Search {
    ECB ecb;
    const std::vector<unsigned char>& observed;
    int width;
    int start_size;
    int rows;
    int chunk;
    uint64_t limit;
    bool retain;
    std::vector<std::array<int, 13>> offsets;
    std::vector<std::array<int, 13>> sizes;
    std::array<int, 6> assignment{};
    uint64_t used = 0;
    uint64_t examined = 0;
    uint64_t rejected = 0;
    uint64_t survivor_count = 0;
    uint64_t block_calls = 0;
    uint64_t rows_checked = 0;
    uint64_t survivor_digest = 14695981039346656037ULL;
    std::vector<Survivor> survivors;

    Search(const std::string& backend, const std::vector<unsigned char>& input,
           int requested_width, int requested_start, uint64_t requested_limit, bool requested_retain)
        : ecb(backend), observed(input), width(requested_width), start_size(requested_start),
          rows(0), chunk(0), limit(requested_limit), retain(requested_retain) {
        if (width < 7 || width > 13 || width % 2 == 0)
            throw std::runtime_error("width must be odd and 7..13");
        if (start_size != 1 && start_size != 2)
            throw std::runtime_error("start must be 1 or 2");
        if (observed.empty() || (2 * observed.size()) % static_cast<size_t>(3 * width))
            throw std::runtime_error("input must contain complete AMSCO rows");
        rows = static_cast<int>(2 * observed.size() / (3 * width));
        if (rows <= 0 || rows % 2)
            throw std::runtime_error("row count must be positive and even");
        chunk = 3 * rows / 2;
        if (chunk * width != static_cast<int>(observed.size()))
            throw std::runtime_error("equal chunk partition failed");
        if (!limit) throw std::runtime_error("prefix limit must be positive");
        offsets.resize(rows);
        sizes.resize(rows);
        for (int row = 0; row < rows; ++row) {
            for (int column = 0; column < width; ++column) {
                sizes[row][column] = ((row + column) % 2 == 0) ? start_size : 3 - start_size;
                offsets[row][column] = 3 * (row / 2) +
                    (row % 2) * ((column % 2 == 0) ? start_size : 3 - start_size);
            }
            int first_six = 0;
            for (int column = 0; column < 6; ++column) first_six += sizes[row][column];
            if (first_six != 9) throw std::runtime_error("first six cells not nine bytes");
        }
    }
    void digest_byte(unsigned char value) {
        survivor_digest ^= value;
        survivor_digest *= 1099511628211ULL;
    }
    void evaluate() {
        ++examined;
        std::vector<unsigned char> ninth;
        ninth.reserve(rows);
        unsigned char first9[9];
        for (int row = 0; row < rows; ++row) {
            int out = 0;
            for (int column = 0; column < 6; ++column) {
                int rank = assignment[column];
                int source = rank * chunk + offsets[row][column];
                int take = sizes[row][column];
                for (int j = 0; j < take; ++j) first9[out++] = observed[source + j];
            }
            if (out != 9) throw std::runtime_error("row reconstruction failed");
            unsigned char plain = static_cast<unsigned char>(first9[8] ^ ecb.first(first9));
            ++block_calls;
            ++rows_checked;
            ninth.push_back(plain);
            if (!allowed(plain)) {
                ++rejected;
                return;
            }
        }
        ++survivor_count;
        for (int value : assignment) digest_byte(static_cast<unsigned char>(value));
        for (unsigned char value : ninth) digest_byte(value);
        digest_byte(0xff);
        if (retain) survivors.push_back({assignment, ninth});
    }
    void recurse(int depth) {
        if (examined >= limit) return;
        if (depth == 6) {
            evaluate();
            return;
        }
        for (int rank = 0; rank < width; ++rank) {
            uint64_t bit = uint64_t{1} << rank;
            if (used & bit) continue;
            assignment[depth] = rank;
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
    std::array<unsigned char, 8> reg{};
    std::copy(iv.begin(), iv.end(), reg.begin());
    std::vector<unsigned char> output;
    output.reserve(input.size());
    for (unsigned char value : input) {
        unsigned char transformed[8];
        ecb.encrypt(reg.data(), transformed);
        unsigned char result = static_cast<unsigned char>(value ^ transformed[0]);
        unsigned char ciphertext = decrypt ? value : result;
        output.push_back(result);
        for (size_t i = 1; i < reg.size(); ++i) reg[i - 1] = reg[i];
        reg.back() = ciphertext;
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
            std::cout << hex(output.data(), output.size()) << "\n";
            return 0;
        }
        if (argc == 7 && std::string(argv[1]) == "--evaluate") {
            std::string backend = argv[2];
            int width = std::stoi(argv[3]);
            int start = std::stoi(argv[4]);
            auto observed = unhex(argv[5]);
            auto values = parse_csv(argv[6]);
            if (values.size() != 6) throw std::runtime_error("assignment must contain six ranks");
            Search search(backend, observed, width, start, 1, true);
            uint64_t used = 0;
            for (int i = 0; i < 6; ++i) {
                if (values[i] < 0 || values[i] >= width || (used & (uint64_t{1} << values[i])))
                    throw std::runtime_error("assignment must contain six distinct in-range ranks");
                used |= uint64_t{1} << values[i];
                search.assignment[i] = values[i];
            }
            search.evaluate();
            std::cout << "{\"identity\":\"ASTRA\",\"accepted\":" << (search.survivor_count == 1 ? "true" : "false");
            if (search.survivor_count == 1)
                std::cout << ",\"plaintext_ninth_hex\":\"" << hex(search.survivors[0].plaintext_ninth.data(), search.survivors[0].plaintext_ninth.size()) << "\"";
            std::cout << ",\"block_calls\":" << search.block_calls << "}\n";
            return 0;
        }
        if (argc < 7 || std::string(argv[1]) != "--search")
            throw std::runtime_error("usage: --block BACKEND BLOCKHEX | --cfb-{encrypt,decrypt} BACKEND IVHEX DATAHEX | --evaluate BACKEND WIDTH START OBSERVEDHEX ASSIGNMENT_CSV | --search BACKEND WIDTH START PREFIX_LIMIT OBSERVEDHEX [--count-only]");
        std::string backend = argv[2];
        int width = std::stoi(argv[3]);
        int start = std::stoi(argv[4]);
        uint64_t limit = std::stoull(argv[5]);
        auto observed = unhex(argv[6]);
        bool retain = true;
        if (argc == 8) {
            if (std::string(argv[7]) != "--count-only") throw std::runtime_error("unknown search option");
            retain = false;
        } else if (argc != 7) {
            throw std::runtime_error("bad search arguments");
        }
        auto began = std::chrono::steady_clock::now();
        Search search(backend, observed, width, start, limit, retain);
        search.recurse(0);
        double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - began).count();
        uint64_t total = permutation_count(width, 6);
        if (search.examined > total) throw std::runtime_error("prefix accounting overflow");
        uint64_t weight = factorial(width - 6);
        uint64_t unexamined = total - search.examined;
        uint64_t rejected_weight = search.rejected * weight;
        uint64_t survivor_weight = search.survivor_count * weight;
        uint64_t unexamined_weight = unexamined * weight;
        if (rejected_weight + survivor_weight + unexamined_weight != factorial(width))
            throw std::runtime_error("factorial partition failed");
        std::ostringstream digest;
        digest << std::hex << std::setw(16) << std::setfill('0') << search.survivor_digest;
        std::cout << "{\"identity\":\"ASTRA\",\"backend\":\"" << backend
                  << "\",\"width\":" << width << ",\"start\":" << start
                  << ",\"rows\":" << search.rows << ",\"chunk_bytes\":" << search.chunk
                  << ",\"prefix_limit\":" << limit << ",\"total_prefixes\":" << total
                  << ",\"prefixes_examined\":" << search.examined
                  << ",\"rejected_prefixes\":" << search.rejected
                  << ",\"survivor_prefix_count\":" << search.survivor_count
                  << ",\"completion_weight_per_prefix\":" << weight
                  << ",\"rejected_completion_weight\":" << rejected_weight
                  << ",\"unresolved_examined_completion_weight\":" << survivor_weight
                  << ",\"unexamined_prefixes\":" << unexamined
                  << ",\"unexamined_completion_weight\":" << unexamined_weight
                  << ",\"expected_completion_weight\":" << factorial(width)
                  << ",\"factorial_partition_complete\":true"
                  << ",\"complete_scan\":" << (search.examined == total ? "true" : "false")
                  << ",\"block_calls\":" << search.block_calls
                  << ",\"rows_checked\":" << search.rows_checked
                  << ",\"survivor_digest_fnv1a64\":\"" << digest.str() << "\""
                  << ",\"survivors_retained\":" << (retain ? "true" : "false")
                  << ",\"elapsed_seconds\":" << seconds << ",\"survivor_prefixes\":[";
        if (retain) {
            for (size_t i = 0; i < search.survivors.size(); ++i) {
                if (i) std::cout << ",";
                const auto& row = search.survivors[i];
                std::cout << "{\"assignment\":[";
                for (int j = 0; j < 6; ++j) {
                    if (j) std::cout << ",";
                    std::cout << row.assignment[j];
                }
                std::cout << "],\"plaintext_ninth_hex\":\"" << hex(row.plaintext_ninth.data(), row.plaintext_ninth.size()) << "\"}";
            }
        }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << "\n";
        return 1;
    }
}
