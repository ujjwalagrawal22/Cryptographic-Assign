#Compilation Commands
g++ -o keyGen keyGen.cpp -lcryptopp
g++ -o encrypt encrypt.cpp -lcryptopp
g++ -o decrypt decrypt.cpp -lcryptopp

#Running Commands

./keyGen
./encrypt <public_key_file> <data_file> <ciphertext_file>
./decrypt <private_key_file> <ciphertext_file> <plaintext_file>



