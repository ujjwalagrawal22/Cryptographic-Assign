#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>

bool generate_keys(const std::string& private_key_file, const std::string& public_key_file) {
    // Create a new RSA key pair
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "Error creating context for key generation." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing key generation." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Error setting RSA key size." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating RSA key pair." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);

    // Save the private key to a PEM file
    FILE *priv_file = fopen(private_key_file.c_str(), "wb");
    if (!priv_file) {
        std::cerr << "Error opening private key file for writing." << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }
    if (PEM_write_PrivateKey(priv_file, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        std::cerr << "Error writing private key to PEM file." << std::endl;
        ERR_print_errors_fp(stderr);
        fclose(priv_file);
        EVP_PKEY_free(pkey);
        return false;
    }
    fclose(priv_file);

    // Save the public key to a PEM file
    FILE *pub_file = fopen(public_key_file.c_str(), "wb");
    if (!pub_file) {
        std::cerr << "Error opening public key file for writing." << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }
    if (PEM_write_PUBKEY(pub_file, pkey) != 1) {
        std::cerr << "Error writing public key to PEM file." << std::endl;
        ERR_print_errors_fp(stderr);
        fclose(pub_file);
        EVP_PKEY_free(pkey);
        return false;
    }
    fclose(pub_file);

    // Clean up
    EVP_PKEY_free(pkey);

    std::cout << "RSA keys generated and saved to '" << private_key_file << "' and '" << public_key_file << "'." << std::endl;
    return true;
}

int main(int argc,char * argv[]) {
    // Example usage
if (argc != 3) {
        std::cerr << "Enter: " << argv[0] << " <private_key.pem> <public_key.pem>>" << std::endl;
        return 1;
    }

    std::string private_key_file = argv[1];
    std::string public_key_file = argv[2];

    generate_keys(private_key_file, public_key_file);
    return 0;
}

