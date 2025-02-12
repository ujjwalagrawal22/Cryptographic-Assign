#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>

bool read_file(const std::string& filename, std::vector<unsigned char>& buffer) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file.is_open()) return false;

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    buffer.resize(size);
    file.read(reinterpret_cast<char*>(buffer.data()), size);

    return file.good();
}

bool verify_signature(const std::string& data_file, const std::string& signature_file, const std::string& public_key_file) {
    // Read the data and signature files
    std::vector<unsigned char> data, signature;
    if (!read_file(data_file, data) || !read_file(signature_file, signature)) {
        std::cerr << "Error reading data or signature file." << std::endl;
        return false;
    }

    // Read the public key
    FILE *pub_file = fopen(public_key_file.c_str(), "rb");
    if (!pub_file) {
        std::cerr << "Error opening public key file." << std::endl;
        return false;
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY(pub_file, NULL, NULL, NULL);
    fclose(pub_file);

    if (!pubkey) {
        std::cerr << "Error loading public key." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        std::cerr << "Error creating MD context." << std::endl;
        EVP_PKEY_free(pubkey);
        return false;
    }

    // Initialize the verification context
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pubkey) != 1) {
        std::cerr << "Error initializing verification." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pubkey);
        return false;
    }

    // Provide the data to be verified
    if (EVP_DigestVerifyUpdate(md_ctx, data.data(), data.size()) != 1) {
        std::cerr << "Error providing data to verification context." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pubkey);
        return false;
    }

    // Verify the signature
    int result = EVP_DigestVerifyFinal(md_ctx, signature.data(), signature.size());
    
    // Cleanup
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pubkey);

    if (result == 1) {
        std::cout << "Signature is valid." << std::endl;
        return true;
    } else if (result == 0) {
        std::cerr << "Signature is invalid." << std::endl;
        return false;
    } else {
        std::cerr << "Error during signature verification." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
}

int main(int argc,char * argv[]) {
    // Example usage
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <data_file> <decrypted_signature_file> <public_key_file>" << std::endl;
        return 1;
    }

    std::string data_file = argv[1];
    std::string decrypted_signature_file = argv[2];
    std::string public_key_file = argv[3];
    verify_signature(data_file, decrypted_signature_file, public_key_file);
    return 0;
}

