#include <iostream>
#include <vector>
#include <fstream>
#include <cmath>
#include <algorithm>
#include <cassert>

// Read characters (hex representation) from file to vector of int values of characters and return it.
auto parse_to_int(std::ifstream input_file)
{
    assert(input_file);
    std::vector<int> ciphered_message;
    std::string digits{"0123456789ABCDEF"};
    char first, second;

    while (input_file >> first) {
        input_file >> second;
        ciphered_message.push_back(digits.find(toupper(first)) * 16 + digits.find(toupper(second)));
    }

    return std::move(ciphered_message);
}

// Find key length by calculating sum of distribution of characters for every possible key length:
auto find_key_length (const std::vector<int>& ciphered_message)
{
    std::pair<int, double> maximal_distribution = {0, 0.0};

    for (int key = 1; key < 13; key++) {

        std::vector<int> counts(256, 0);
        int index = 0;
        int how_many_characters = 0;
        while (index < ciphered_message.size()) {
            ++how_many_characters;
            ++counts[ciphered_message[index]];
            index += key;
        }

        auto sum = 0.0;
        for(auto && c : counts)
            sum += pow((static_cast<double>(c) / how_many_characters), 2);

        if (sum > maximal_distribution.second)
            maximal_distribution = {key, sum};
    }

    return maximal_distribution.first;
}

// Find key for every cipherstream (subset of characters starting at ith < ciphered_message.size() position
// by checking which of 256 possible values to xor gives most "normal" deciphered set of characters.
auto find_key(const std::vector<int>& ciphered_message, const int key_length)
{
    // try to decipher first cipherstream: every key_length character starting from 0
    auto charset_lower = std::string("abcdefghijklmnopqrstuvwxyz ");
    auto charset_upper = std::string("ABCDEFGHIJKLMNOPQRSTUVWXYZ ");
    auto charset_punctuation = std::string(",.;?!':");

    std::vector<int> key_vector(key_length);
    for (int key = 0; key < key_length; key++) {

        // calculate distribution when xoring with every possible key character for this cipherstream:
        std::vector<double> distributions(256, 0);
        std::vector<int> most_frequent_lowercase_letter(256, 0);
        for (int b = 0; b < 256; b++) {
            bool aborted = false;
            int how_many_lowercases = 0;
            std::vector<int> lowercases(26, 0);
            int length_of_stream = 0;
            for (int index = key; index < ciphered_message.size() && !aborted; index += key_length) {
                ++length_of_stream;
                int xored = ciphered_message[index] ^b;

                // sum how many "normal" characters appeared in text
                if (charset_lower.find((char) xored) != std::string::npos ||
                    charset_upper.find((char) xored) != std::string::npos ||
                    charset_punctuation.find((char) xored) != std::string::npos) {
                    how_many_lowercases++;
                }
            }

            distributions[b] = static_cast<double>(how_many_lowercases) / static_cast<double> (length_of_stream);
        }

        // choose this cipherstream, which has the greatest number of "normal" characters (as for english text)
        auto it = std::max_element(distributions.begin(), distributions.end());
        auto max_distr_value = *it;
        auto max_distr_index = std::distance(distributions.begin(), it);
        key_vector[key] = max_distr_index;
    }

    return std::move(key_vector);
}

// Function used to convert ciphered_message by xoring with key_vector to undo Vigenere enciphering.
auto decipher_message(const std::vector<int>& ciphered_message, const std::vector<int>& key_vector)
{
    std::vector<char> deciphered_message(ciphered_message.size());
    auto key_index = 0;
    for (auto i = 0; i < ciphered_message.size(); i++) {
        deciphered_message[i] = ciphered_message[i] ^ key_vector[key_index];
        key_index = (key_index + 1) % key_vector.size();
    }

    return deciphered_message;
}

const auto filename = std::string("ciphered_message.txt");

// Read Vigenere-encrypted (by xoring with some key of unknown length) message from file and print
// encrypted to stdout. File format: extended ASCII characters in hex representation.
int main() {
    auto ciphered_message = parse_to_int(std::ifstream(filename));

    auto key_length = find_key_length(ciphered_message);
    std::cout << "Most probable key length is: " << key_length << std::endl;

    auto key_vector = find_key(ciphered_message, key_length);
    std::cout << std::endl << "Key is most likely:" << std::endl;
    for (auto&& k : key_vector)
        std::cout << k << " ";
    std::cout << std::endl;

    auto deciphered_message = decipher_message(ciphered_message, key_vector);
    std::cout << std::endl << "Deciphered message is:" << std::endl;
    for (auto&& c : deciphered_message)
        std::cout << c;
}
