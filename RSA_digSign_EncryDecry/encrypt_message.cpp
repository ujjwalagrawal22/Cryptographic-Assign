#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
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

bool write_file(const std::string& filename, const std::vector<unsigned char>& buffer) {
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) return false;

    file.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    return file.good();
}

bool encrypt_message(const std::string& data_file, const std::string& signature_file, 
                     const std::string& public_key_file, const std::string& encrypted_data_file,
                     const std::string& encrypted_key_file) {
    // Read the data and signature files
    std::vector<unsigned char> data, signature;
    if (!read_file(data_file, data) || !read_file(signature_file, signature)) {
        std::cerr << "Error reading data or signature file." << std::endl;
        return false;
    }

    // Concatenate signature with data
    std::vector<unsigned char> concatenated_data;
    concatenated_data.reserve(data.size() + signature.size());
    concatenated_data.insert(concatenated_data.end(), signature.begin(), signature.end());
    concatenated_data.insert(concatenated_data.end(), data.begin(), data.end());

    // Generate a random AES-256 session key
    std::vector<unsigned char> session_key(32); // 256 bits / 8 bits per byte = 32 bytes
    if (RAND_bytes(session_key.data(), session_key.size()) != 1) {
        std::cerr << "Error generating session key." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // Encrypt the concatenated data using the AES session key
    std::vector<unsigned char> encrypted_data(concatenated_data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len, len;

    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        std::cerr << "Error creating cipher context." << std::endl;
        return false;
    }

    if (EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, session_key.data(), NULL) != 1) {
        std::cerr << "Error initializing encryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return false;
    }

    if (EVP_EncryptUpdate(cipher_ctx, encrypted_data.data(), &out_len, concatenated_data.data(), concatenated_data.size()) != 1) {
        std::cerr << "Error during encryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return false;
    }

    int ciphertext_len = out_len;

    if (EVP_EncryptFinal_ex(cipher_ctx, encrypted_data.data() + out_len, &len) != 1) {
        std::cerr << "Error finalizing encryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return false;
    }

    ciphertext_len += len;
    encrypted_data.resize(ciphertext_len);

    EVP_CIPHER_CTX_free(cipher_ctx);

    // Encrypt the session key with the recipient's RSA public key
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

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!pkey_ctx) {
        std::cerr << "Error creating context for key encryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pubkey);
        return false;
    }

    if (EVP_PKEY_encrypt_init(pkey_ctx) <= 0) {
        std::cerr << "Error initializing encryption of session key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pubkey);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Error setting RSA padding." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pubkey);
        return false;
    }

    size_t encrypted_key_len;
    if (EVP_PKEY_encrypt(pkey_ctx, NULL, &encrypted_key_len, session_key.data(), session_key.size()) <= 0) {
        std::cerr << "Error determining buffer length for encrypted key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pubkey);
        return false;
    }

    std::vector<unsigned char> encrypted_key(encrypted_key_len);
    if (EVP_PKEY_encrypt(pkey_ctx, encrypted_key.data(), &encrypted_key_len, session_key.data(), session_key.size()) <= 0) {
        std::cerr << "Error encrypting session key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(pubkey);
        return false;
    }

    encrypted_key.resize(encrypted_key_len);

    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(pubkey);

    // Write encrypted data and encrypted session key to files
    if (!write_file(encrypted_data_file, encrypted_data) || !write_file(encrypted_key_file, encrypted_key)) {
        std::cerr << "Error writing encrypted data or key to file." << std::endl;
        return false;
    }

    std::cout << "Data encrypted and saved to '" << encrypted_data_file << "' and key saved to '" << encrypted_key_file << "'." << std::endl;
    return true;
}

int main(int argc,char* argv[]) {
   // Check for correct number of arguments
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <public_key.pem> <data_file> <signature_file>" << std::endl;
        return 1;
    }

    // Get file names from command-line arguments
    std::string public_key_file = argv[1];
    std::string data_file = argv[2];
    std::string signature_file = argv[3];
    encrypt_message(data_file, signature_file, public_key_file, "encrypted_data.bin", "encrypted_key.bin");
    return 0;
}

