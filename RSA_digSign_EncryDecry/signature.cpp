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

    // Check if the read operation was successful
    return file.good();
}

bool sign_message(const std::string& data_file, const std::string& private_key_file, const std::string& signature_file) {
    // Load the private key
    FILE *priv_file = fopen(private_key_file.c_str(), "rb");
    if (!priv_file) {
        std::cerr << "Error opening private key file." << std::endl;
        return false;
    }
    EVP_PKEY *pkey = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);

    if (!pkey) {
        std::cerr << "Error loading private key." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Read data from the file
    std::vector<unsigned char> data;
    if (!read_file(data_file, data)) {
        std::cerr << "Error reading data file." << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    // Create and initialize the signing context
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "Error creating EVP_MD_CTX." << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        std::cerr << "Error initializing digest sign context." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // Update the signing context with the data
    if (EVP_DigestSignUpdate(mdctx, data.data(), data.size()) != 1) {
        std::cerr << "Error updating digest sign context." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // Finalize the signature
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, NULL, &sig_len) != 1) {
        std::cerr << "Error finalizing digest sign context." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(mdctx, signature.data(), &sig_len) != 1) {
        std::cerr << "Error generating signature." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // Write the signature to a file
    std::ofstream sig_file(signature_file, std::ios::binary);
    if (!sig_file) {
        std::cerr << "Error opening signature file for writing." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }
    sig_file.write(reinterpret_cast<const char*>(signature.data()), signature.size());
    if (!sig_file) {
        std::cerr << "Error writing signature to file." << std::endl;
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        return false;
    }

    // Clean up
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    std::cout << "Message signed and signature saved to '" << signature_file << "'." << std::endl;
    return true;
}

int main(int argc,char* argv[]) {
    // Example usage
     // Check for correct number of arguments
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <private_key.pem> <data_file>" << std::endl;
        return 1;
    }

    // Get file names from command-line arguments
    std::string private_key_file = argv[1];
    std::string data_file = argv[2];
    sign_message(data_file, private_key_file, "signature.bin");
    return 0;
}

