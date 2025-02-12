#include <iostream>
#include <fstream>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

// Function to load the private key from a file
void LoadPrivateKey(const std::string& filename, Integer& d, Integer& n) {
    FileSource file(filename.c_str(), true); // true = throw on error
    d.BERDecode(file); // Decode the private exponent
    n.BERDecode(file); // Decode the modulus
}

// Function to decrypt ciphertext
void Decrypt(const Integer& d, const Integer& n, const std::string& ciphertext, std::string& plaintext) {
    // Convert ciphertext string to Integer
    Integer c((const byte*)ciphertext.data(), ciphertext.size());

    // Decrypt using m = C^d mod n
    Integer m = a_exp_b_mod_c(c, d, n); // m = c^d mod n

    // Convert Integer back to string
    size_t paddedSize = m.ByteCount();
    byte* decoded = new byte[paddedSize];
    m.Encode(decoded, paddedSize);

    // Remove padding (PKCS#1 v1.5)
    std::string paddedPlaintext((const char*)decoded, paddedSize);
    size_t pos = paddedPlaintext.find('\0', 2); // Look for the first 0x00 after padding type
    if (pos != std::string::npos) {
        plaintext = paddedPlaintext.substr(pos + 1); // Extract the original plaintext
    } else {
        std::cerr << "Invalid padding in decrypted message." << std::endl;
    }

    delete[] decoded; // Clean up
}

// Main decryption function
void RSADecrypt(const std::string& privateKeyFile, const std::string& ciphertextFile, const std::string& plaintextFile) {
    Integer d, n;

    // Load the private key
    LoadPrivateKey(privateKeyFile, d, n);

    // Read the ciphertext from the file
    std::string ciphertext;
    {
        FileSource file(ciphertextFile.c_str(), true);
        ciphertext.resize(file.MaxRetrievable());
        file.Get((byte*)ciphertext.data(), ciphertext.size());
    }

    // Decrypt the ciphertext
    std::string plaintext;
    Decrypt(d, n, ciphertext, plaintext);

    // Save the plaintext to a file
    {
        std::ofstream outFile(plaintextFile);
        if (!outFile) {
            std::cerr << "Error opening output plaintext file." << std::endl;
            return;
        }
        outFile << plaintext;
    }

    std::cout << "Decryption complete. Plaintext saved to " << plaintextFile << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <private_key_file> <ciphertext_file> <plaintext_file>" << std::endl;
        return 1;
    }

    RSADecrypt(argv[1], argv[2], argv[3]);
    return 0;
}
