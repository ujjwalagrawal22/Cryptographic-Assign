#Compilation commands
g++ -o keyGen keyGen.cpp -lcryptopp
g++ -o sign sign.cpp -lcryptopp
g++ -o verify verify.cpp -lcryptopp

#Running commands

./keyGen
./sign private_key_file data_file signature_file
./verify public_key_file data_file signature_file

