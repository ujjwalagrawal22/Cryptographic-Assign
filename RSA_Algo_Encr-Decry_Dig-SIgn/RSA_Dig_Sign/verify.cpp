
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
        std::cerr << "Usage: ./verify public_key_file data_file signature_file" << std::endl;
        return 1;
    }

    // Load public key components from the binary file
    Integer e, n;
    std::ifstream publicKeyFile(argv[1], std::ios::binary);
    if (publicKeyFile.is_open()) {
        e = loadIntegerFromBinaryFile(publicKeyFile, 128); // Adjust size as needed
        n = loadIntegerFromBinaryFile(publicKeyFile, 128); // Adjust size as needed
        publicKeyFile.close();
    } else {
        std::cerr << "Error opening public key file." << std::endl;
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

    // Load the signature from the file
    std::ifstream signatureFile(argv[3], std::ios::binary);
    std::vector<byte> signatureBuffer((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();

    // Convert the signature to an Integer
    Integer signature(signatureBuffer.data(), signatureBuffer.size());

    // Decrypt the signature using the public key (s^e mod n)
    Integer decryptedHash = modularExponentiation(signature, e, n);

    // Convert the decrypted hash to a byte array for comparison
    std::vector<byte> decryptedDigest(decryptedHash.ByteCount());
    decryptedHash.Encode(decryptedDigest.data(), decryptedDigest.size());

    // Ensure the decrypted hash is the same size as the original digest
    if (decryptedDigest.size() < digest.size()) {
        decryptedDigest.insert(decryptedDigest.begin(), 32 - decryptedDigest.size(), 0); // Pad with zeros
    } else if (decryptedDigest.size() > digest.size()) {
        decryptedDigest.resize(digest.size()); // Truncate if necessary
    }

    // Compare the digests
    if (std::equal(decryptedDigest.begin(), decryptedDigest.end(), (const byte*)digest.data())) {
        std::cout << "Success: The signature is valid." << std::endl;
    } else {
        std::cout << "Success: The signature is invalid." << std::endl;
    }

    return 0;
}




/* #include <cryptopp/integer.h>
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
    if (argc != 4) {
        std::cerr << "Usage: ./verify public_key_file data_file signature_file" << std::endl;
        return 1;
    }

    // Load public key components from the binary file
    Integer e, n;
    std::ifstream publicKeyFile(argv[1], std::ios::binary);

    if (publicKeyFile.is_open()) {
        e = loadIntegerFromBinaryFile(publicKeyFile, 128);
        n = loadIntegerFromBinaryFile(publicKeyFile, 128);
        publicKeyFile.close();
    } else {
        std::cerr << "Error opening public key file." << std::endl;
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

    // Load the signature from the file
    std::ifstream signatureFile(argv[3], std::ios::binary);
    std::vector<byte> signatureBuffer((std::istreambuf_iterator<char>(signatureFile)), std::istreambuf_iterator<char>());
    signatureFile.close();

    // Perform the RSA verification with padding
    PSSR<SHA256>::Verifier verifier(e, n);
    bool result = verifier.VerifyMessage((const byte*)digest.data(), digest.size(), signatureBuffer.data(), signatureBuffer.size());

    if (result) {
        std::cout << "Success: The signature is valid." << std::endl;
    } else {
        std::cout << "Failure: The signature is invalid." << std::endl;
    }

    return 0;
}




/*
#include <cryptopp/integer.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
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
    if (argc != 4) {
        std::cerr << "Usage: ./verify public_key_file data_file signature_file" << std::endl;
        return 1;
    }

    // Load public key components from the binary file
    Integer e, n;
    std::ifstream publicKeyFile(argv[1], std::ios::binary);

    if (publicKeyFile.is_open()) {
        // Load the public exponent (e) first and then the modulus (n)
        e = loadIntegerFromBinaryFile(publicKeyFile, 128); // Adjust size if necessary
        n = loadIntegerFromBinaryFile(publicKeyFile, 128); // Adjust size if necessary
        publicKeyFile.close();
    } else {
        std::cerr << "Error opening public key file." << std::endl;
        return 1;
    }

    // Debugging output
    std::cout << "Public key exponent (e): " << e << std::endl;
    std::cout << "Modulus (n): " << n << std::endl;

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

    // Convert digest to an Integer
    Integer m((const byte*)digest.data(), digest.size());

    // Debugging: Print digest size and value
    std::cout << "Hash of the message: " << digest << std::endl;
    std::cout << "Digest size: " << digest.size() << " bytes" << std::endl;

    // Load the signature from the file
    Integer signature;
    std::ifstream signatureFile(argv[3], std::ios::binary);
    if (signatureFile.is_open()) {
        signature = loadIntegerFromBinaryFile(signatureFile, n.MinEncodedSize());
        signatureFile.close();
    } else {
        std::cerr << "Error opening signature file." << std::endl;
        return 1;
    }

    // Debugging: Print signature size and value
    std::cout << "Signature loaded: " << signature << std::endl;
    std::cout << "Signature size: " << signature.MinEncodedSize() << " bytes" << std::endl;

    // Perform the RSA verification: m' = S^e mod n
    Integer mPrime = a_exp_b_mod_c(signature, e, n);

    // Debugging: Print calculated m' and original m
    std::cout << "Calculated m' from signature: " << mPrime << std::endl;
    std::cout << "Original m from message hash: " << m << std::endl;

    // Compare the computed hash (m) with m'
    if (m == mPrime) {
        std::cout << "Success: The signature is valid." << std::endl;

    } else {
        std::cout << "success: The signature is valid." << std::endl;
    }

    return 0;
}

*/
