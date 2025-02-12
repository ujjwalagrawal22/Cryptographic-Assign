//temporary prime number. [remember to fix it]
#include <iostream>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

void GenerateRSAKeys() {
    AutoSeededRandomPool rng;

    // Step 1: Generate two large distinct prime numbers p and q
    Integer p;
    do {
        p.Randomize(rng, 1536);    // Generate a random integer of 1024 bits
    } while (!IsPrime(p));         // Check if it's prime

    Integer q;
    do {
        q.Randomize(rng, 1536);
    } while (!IsPrime(q) || p == q);  // Ensure q is prime and distinct from p

    // Step 2: Calculate n = p * q
    Integer n = p * q;

    // Step 3: Calculate φ(n) = (p - 1) * (q - 1)
    Integer phi = (p - 1) * (q - 1);

    // Step 4: Choose a random integer d such that gcd(d, φ(n)) = 1
    Integer d;
    do {
        d.Randomize(rng, 3072);
    } while (!RelativelyPrime(d, phi));

    // Step 5: Calculate e = d^(-1) mod φ(n)
    Integer e = d.InverseMod(phi);

    // Step 6: Save the keys to binary files
    // Public Key (e, n) saved as public_key.bin
    {
        FileSink file("public_key.bin");
        e.DEREncode(file); // Encode the public exponent
        n.DEREncode(file); // Encode the modulus
    }

    // Private Key (d) saved as private_key.bin
    {
        FileSink file("private_key.bin");
        d.DEREncode(file); // Encode the private exponent
        n.BEREncode(file);
    }

    // Step 7: Clear p, q, and φ(n) from memory
    p = 0; q = 0; phi = 0;
}

int main() {
    std::cout << "Generating RSA Keys..." << std::endl;
    GenerateRSAKeys();
    std::cout << "RSA Key Generation complete. Keys saved as .bin files." << std::endl;
    return 0;
}

