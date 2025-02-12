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

bool decrypt_message(const std::string& encrypted_data_file, const std::string& encrypted_key_file,
                     const std::string& private_key_file, const std::string& decrypted_data_file,
                     const std::string& decrypted_signature_file) {
    // Read the encrypted data and encrypted session key files
    std::vector<unsigned char> encrypted_data, encrypted_key;
    if (!read_file(encrypted_data_file, encrypted_data) || !read_file(encrypted_key_file, encrypted_key)) {
        std::cerr << "Error reading encrypted data or key file." << std::endl;
        return false;
    }

    // Decrypt the session key with the recipient's RSA private key
    FILE *priv_file = fopen(private_key_file.c_str(), "rb");
    if (!priv_file) {
        std::cerr << "Error opening private key file." << std::endl;
        return false;
    }

    EVP_PKEY *privkey = PEM_read_PrivateKey(priv_file, NULL, NULL, NULL);
    fclose(priv_file);

    if (!privkey) {
        std::cerr << "Error loading private key." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!pkey_ctx) {
        std::cerr << "Error creating context for key decryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(privkey);
        return false;
    }

    if (EVP_PKEY_decrypt_init(pkey_ctx) <= 0) {
        std::cerr << "Error initializing decryption of session key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(privkey);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        std::cerr << "Error setting RSA padding." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(privkey);
        return false;
    }

    size_t session_key_len;
    if (EVP_PKEY_decrypt(pkey_ctx, NULL, &session_key_len, encrypted_key.data(), encrypted_key.size()) <= 0) {
        std::cerr << "Error determining buffer length for decrypted session key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(privkey);
        return false;
    }

    std::vector<unsigned char> session_key(session_key_len);
    if (EVP_PKEY_decrypt(pkey_ctx, session_key.data(), &session_key_len, encrypted_key.data(), encrypted_key.size()) <= 0) {
        std::cerr << "Error decrypting session key." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pkey_ctx);
        EVP_PKEY_free(privkey);
        return false;
    }

    session_key.resize(session_key_len);
    EVP_PKEY_CTX_free(pkey_ctx);
    EVP_PKEY_free(privkey);

    // Decrypt the data using the AES session key
    EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) {
        std::cerr << "Error creating cipher context." << std::endl;
        return false;
    }

    if (EVP_DecryptInit_ex(cipher_ctx, EVP_aes_256_cbc(), NULL, session_key.data(), NULL) != 1) {
        std::cerr << "Error initializing decryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return false;
    }

    std::vector<unsigned char> decrypted_data(encrypted_data.size() + EVP_MAX_BLOCK_LENGTH);
    int out_len, len;

    if (EVP_DecryptUpdate(cipher_ctx, decrypted_data.data(), &out_len, encrypted_data.data(), encrypted_data.size()) != 1) {
        std::cerr << "Error during decryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return false;
    }

    int decrypted_len = out_len;

    if (EVP_DecryptFinal_ex(cipher_ctx, decrypted_data.data() + out_len, &len) != 1) {
        std::cerr << "Error finalizing decryption." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(cipher_ctx);
        return false;
    }

    decrypted_len += len;
    decrypted_data.resize(decrypted_len);

    EVP_CIPHER_CTX_free(cipher_ctx);

    // Extract the digital signature and plaintext data
    if (decrypted_data.size() < 256) {
        std::cerr << "Decrypted data is too short to extract signature and data." << std::endl;
        return false;
    }

    std::vector<unsigned char> extracted_signature(decrypted_data.begin(), decrypted_data.begin() + 256);
    std::vector<unsigned char> extracted_plaintext(decrypted_data.begin() + 256, decrypted_data.end());

    // Write the decrypted data and signature to files
    if (!write_file(decrypted_data_file, extracted_plaintext) || !write_file(decrypted_signature_file, extracted_signature)) {
        std::cerr << "Error writing decrypted data or signature to file." << std::endl;
        return false;
    }

    std::cout << "Data and signature decrypted and saved to '" << decrypted_data_file << "' and '" << decrypted_signature_file << "'." << std::endl;
    return true;
}

int main(int argc,char* argv[]) {
    // Example usage
if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <private_key.pem> <encrypted_data_file> <encrypted_key_file>" << std::endl;
        return 1;
    }

    std::string private_key_file = argv[1];
    std::string encrypted_data_file = argv[2];
    std::string encrypted_key_file = argv[3];

    decrypt_message(encrypted_data_file, encrypted_key_file, private_key_file, "decrypted_data.txt", "decrypted_signature.bin");
    return 0;
}


