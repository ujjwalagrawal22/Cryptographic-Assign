# Step For Encryption and Decryption of Data File using RSA Key and openssl Library.

## Key Generation

- Two pairs of RSA Keys (public and private) using command.

```bash
./keyGen Bob_privateKey.pem Bob_publicKey.pem
./keyGen Alice_privateKey.pem Alice_publicKey.pem
```

- Each Key will be stored as separate files.

## Digital Signature

- Take the data file and create a digital signature of the data using the Alice RSA private key.

```bash
./signature Alice_privateKey.pem data.txt
```

## Message Encryption

- Encrypte the data file using Bob(Recipient's) RSA public key and digital Signature Generated.

```bash
./encrypt_message Bob_publicKey.pem data.txt signature.bin
```

## Message Decryption

- Decrypt the data file using the Bob(Recipient's) RSA private key.

```bash
./decrypt_message Bob_privateKey.pem encrypted_data.bin encrypted_key.bin
```

## Signature Verification

- Verify the integrity of the data by checking the signature using the sender's RSA public key.

```bash
 ./verify_signature data.txt decrypted_signature.bin Alice_publicKey.pem
```

# Result

Successfully able to decrypt the data file and verify the signature.

```bash
Signature is valid.
```
