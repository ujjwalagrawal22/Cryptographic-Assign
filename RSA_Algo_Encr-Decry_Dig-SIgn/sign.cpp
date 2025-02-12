#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <vector>
#include <fstream>
#include <iostream>
#include <string>

using namespace CryptoPP;

// Function to load an Integer from a binary file
Integer loadIntegerFromBinaryFile(std::ifstream& file, size_t length) {
    std::vector<byte> buffer(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    return Integer(buffer.data(), buffer.size());
}

// Function to perform modular exponentiation
Integer modularExponentiation(const Integer& base, const Integer& exponent, const Integer& modulus) {
    Integer result = 1;
    Integer b = base % modulus; // Ensure base is within modulus

    for (Integer exp = exponent; exp > 0; exp = exp >> 1) { // Right shift for division by 2
        if ((exp & 1) == 1) { // Check if the last bit is set
            result = (result * b) % modulus;
        }
        b = (b * b) % modulus;
    }
    return result;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: ./sign private_key_file data_file signature_file" << std::endl;
        return 1;
    }

    // Load private key components from the binary file
    Integer d, n;
    std::ifstream privateKeyFile(argv[1], std::ios::binary);
    if (privateKeyFile.is_open()) {
        d = loadIntegerFromBinaryFile(privateKeyFile, 128); // Adjust size as needed
        n = loadIntegerFromBinaryFile(privateKeyFile, 128); // Adjust size as needed
        privateKeyFile.close();
    } else {
        std::cerr << "Error opening private key file." << std::endl;
        return 1;
    }

    // Read the data file (message)
    std::string message;
    std::ifstream dataFile(argv[2]);
    if (dataFile.is_open()) {
        message.assign((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());
        dataFile.close();
    } else {
        std::cerr << "Error opening data file." << std::endl;
        return 1;
    }

    // Compute the hash of the message (using SHA-256)
    SHA256 hash;
    std::string digest;
    StringSource(message, true, new HashFilter(hash, new StringSink(digest)));

    // Convert the digest to an Integer using its byte representation
    Integer m(reinterpret_cast<const byte*>(digest.data()), digest.size());

    // Sign the message hash using the private key (m^d mod n)
    Integer signature = modularExponentiation(m, d, n);

    // Save the signature to a file
    std::ofstream signatureFile(argv[3], std::ios::binary);
    if (signatureFile.is_open()) {
        byte* signatureBuffer = new byte[signature.ByteCount()];
        signature.Encode(signatureBuffer, signature.ByteCount());
        signatureFile.write(reinterpret_cast<char*>(signatureBuffer), signature.ByteCount());
        delete[] signatureBuffer;
        signatureFile.close();
    } else {
        std::cerr << "Error opening signature file." << std::endl;
        return 1;
    }

    std::cout << "Signature created successfully." << std::endl;
    return 0;
}


/*#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/pssr.h> // For padding
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace CryptoPP;

// Function to load an Integer from a binary file
Integer loadIntegerFromBinaryFile(std::ifstream& file, size_t length) {
    std::vector<byte> buffer(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    return Integer(buffer.data(), buffer.size());
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./sign private_key_file data_file" << std::endl;
        return 1;
    }

    AutoSeededRandomPool rng;

    // Load private key components from the binary file
    Integer d, n;
    std::ifstream privateKeyFile(argv[1], std::ios::binary);

    if (privateKeyFile.is_open()) {
        d = loadIntegerFromBinaryFile(privateKeyFile, 128);
        n = loadIntegerFromBinaryFile(privateKeyFile, 128);
        privateKeyFile.close();
    } else {
        std::cerr << "Error opening private key file." << std::endl;
        return 1;
    }

    // Read the data file (message) to be signed
    std::string message;
    std::ifstream dataFile(argv[2]);
    if (dataFile.is_open()) {
        message.assign((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());
        dataFile.close();
    } else {
        std::cerr << "Error opening data file." << std::endl;
        return 1;
    }

    // Compute the hash of the message (using SHA-256)
    SHA256 hash;
    std::string digest;
    StringSource(message, true, new HashFilter(hash, new StringSink(digest)));

    // Perform the RSA signature with padding
    PSSR<SHA256>::Signer signer(d, n);
    SecByteBlock signature(signer.MaxSignatureLength());
    size_t signatureLength = signer.SignMessage(rng, (const byte*)digest.data(), digest.size(), signature);

    // Save the signature to a file
    std::ofstream signatureFile("signature_file.bin", std::ios::binary);
    if (signatureFile.is_open()) {
        signatureFile.write((char*)signature.data(), signatureLength);
        signatureFile.close();
        std::cout << "Signature saved to signature_file.bin" << std::endl;
    } else {
        std::cerr << "Error opening signature file." << std::endl;
        return 1;
    }

    return 0;
} */

/*
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

using namespace CryptoPP;

// Function to load an Integer from binary data
Integer loadIntegerFromBinaryFile(std::ifstream& file, size_t length) {
    std::vector<byte> buffer(length);
    file.read(reinterpret_cast<char*>(buffer.data()), length);
    return Integer(buffer.data(), buffer.size());
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: ./sign private_key_file data_file" << std::endl;
        return 1;
    }

    // Load private key components from the binary file
    Integer d, n;
    std::ifstream privateKeyFile(argv[1], std::ios::binary);

    if (privateKeyFile.is_open()) {
        // Load the private exponent (d) first and then the modulus (n)
        d = loadIntegerFromBinaryFile(privateKeyFile,128);
        n = loadIntegerFromBinaryFile(privateKeyFile,128);
        privateKeyFile.close();
    } else {
        std::cerr << "Error opening private key file." << std::endl;
        return 1;
    }

    // Debugging output
    std::cout << "Private key exponent (d): " << d << std::endl;
    std::cout << "Modulus (n): " << n << std::endl;

    // Check if d or n is zero
    if (d.IsZero() || n.IsZero()) {
        std::cerr << "Error: Private key exponent or modulus is zero." << std::endl;
        return 1;
    }

    // Read the data file (message) to be signed
    std::string message;
    std::ifstream dataFile(argv[2]);
    if (dataFile.is_open()) {
        message.assign((std::istreambuf_iterator<char>(dataFile)), std::istreambuf_iterator<char>());
        dataFile.close();
    } else {
        std::cerr << "Error opening data file." << std::endl;
        return 1;
    }

    // Compute the hash of the message (using SHA-256)
    SHA256 hash;
    std::string digest;
    StringSource(message, true, new HashFilter(hash, new StringSink(digest)));

    // Convert digest to an Integer
    Integer m((const byte*)digest.data(), digest.size());

    // Perform the RSA signature: S = m^d mod n
    Integer signature = a_exp_b_mod_c(m, d, n);

    // Save the signature to a file
    std::ofstream signatureFile("signature_file.bin", std::ios::binary);
    if (signatureFile.is_open()) {
        size_t size = signature.MinEncodedSize();
        std::vector<byte> buffer(size);
        signature.Encode(buffer.data(), buffer.size());
        signatureFile.write((char*)buffer.data(), buffer.size());
        signatureFile.close();
        std::cout << "Signature saved to signature_file.bin" << std::endl;
    } else {
        std::cerr << "Error opening signature file." << std::endl;
        return 1;
    }

    return 0;
}
*/
