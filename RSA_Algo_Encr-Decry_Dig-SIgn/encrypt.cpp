#include <iostream>
#include <fstream>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

// Function to load the public key from a file
void LoadPublicKey(const std::string& filename, Integer& e, Integer& n) {
    FileSource file(filename.c_str(), true); // true = throw on error
    e.BERDecode(file); // Use BERDecode for the public exponent
    n.BERDecode(file); // Use BERDecode for the modulus
}

// Function to apply PKCS#1 v1.5 padding
std::string ApplyPadding(const std::string& plaintext, size_t modulusSize) {
    std::string padded(modulusSize, '\0'); // Create a padded string
    padded[0] = 0x00; // First byte
    padded[1] = 0x02; // Padding type
    AutoSeededRandomPool rng;
    
    // Fill the padding with random non-zero bytes
    for (size_t i = 2; i < modulusSize - plaintext.size() - 1; ++i) {
        byte randByte;
        do {
            rng.GenerateBlock(&randByte, sizeof(randByte));
        } while (randByte == 0);
        padded[i] = randByte;
    }
    
    padded[modulusSize - plaintext.size() - 1] = 0x00; // Separator
    std::copy(plaintext.begin(), plaintext.end(), padded.begin() + modulusSize - plaintext.size());
    
    return padded;
}

// Function to encrypt plaintext
void Encrypt(const Integer& e, const Integer& n, const std::string& plaintext, std::string& ciphertext) {
    // Apply padding
    std::string paddedPlaintext = ApplyPadding(plaintext, n.ByteCount());
    Integer mPadded((const byte*)paddedPlaintext.data(), paddedPlaintext.size());

    // Encrypt using mPadded
    Integer c = a_exp_b_mod_c(mPadded, e, n); // C = mPadded^e mod n

    // Encode the ciphertext into a byte array
    size_t size = c.ByteCount();
    byte* encoded = new byte[size];
    c.Encode(encoded, size);

    // Convert the byte array to a string
    ciphertext.assign((const char*)encoded, size);
    delete[] encoded; // Clean up

    std::cout << "Padded Plaintext size: " << paddedPlaintext.size() << std::endl;
    std::cout << "Encoded ciphertext size: " << ciphertext.size() << std::endl;
}

// Main encryption function
void RSAEncrypt(const std::string& publicKeyFile, const std::string& dataFile, const std::string& ciphertextFile) {
    Integer e, n;

    // Load the public key
    LoadPublicKey(publicKeyFile, e, n);

    // Read the plaintext from the file
    std::string plaintext;
    {
        std::ifstream inFile(dataFile);
        if (!inFile) {
            std::cerr << "Error opening input data file." << std::endl;
            return;
        }
        std::getline(inFile, plaintext);
    }

    // Encrypt the plaintext
    std::string ciphertext;
    Encrypt(e, n, plaintext, ciphertext);

    // Save the ciphertext to a file
    {
        FileSink file(ciphertextFile.c_str());
        file.Put((const byte*)ciphertext.data(), ciphertext.size());
    }

    std::cout << "Encryption complete. Ciphertext saved to " << ciphertextFile << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public_key_file> <data_file> <ciphertext_file>" << std::endl;
        return 1;
    }

    RSAEncrypt(argv[1], argv[2], argv[3]);
    return 0;
}



