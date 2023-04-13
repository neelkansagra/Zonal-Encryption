# Getting Started

1. Downloading g++
  `$ sudo apt update
   $ sudo apt install build-essential
   $ g++ --version`
g++ is successfully installed if the last command runs successfully

2. Downloading and installing GMP library

- Go to this [link](https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz) to download GMP library
- Unzip the folder then type the following command
   `$ sudo ./configure
    $ sudo make
    $ sudo make check
    $ sudo make install`

3. Downloading and Installing PBC

- Go to this [link](https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz) to download PBC library.
- Unzip the folder then type the following commands.

    `$ sudo ./configure`

    `$ sudo make`

    `$ sudo make install`
  
4. Downloading qnd Installing Crypto++ library

    `$ sudo apt-get install libcrypto++8 libcrypto++8-dbg libcrypto++-dev`
    `$ sudo make static dynamic cryptest.exe`
    `$ sudo make libcryptopp.a libcryptopp.so cryptest.exe`
    `$ sudo make install PREFIX=/usr/local`
    `$ sudo mkdir -p /usr/local/include/cryptopp`
    `$ sudo cp *.h /usr/local/include/cryptopp`
    `$ sudo chmod 755 /usr/local/include/cryptopp`
    `$ sudo chmod 644 /usr/local/include/cryptopp/*.h`
    `$ sudo mkdir -p /usr/local/lib`
    `$ sudo cp libcryptopp.a /usr/local/lib`
    `$ sudo chmod 644 /usr/local/lib/libcryptopp.a`
    `$ sudo mkdir -p /usr/local/bin`
    `$ sudo cp cryptest.exe /usr/local/bin`
    `$ sudo chmod 755 /usr/local/bin/cryptest.exe`
    `$ sudo mkdir -p /usr/local/share/cryptopp`
    `$ sudo cp -r TestData /usr/local/share/cryptopp`
    `$ sudo cp -r TestVectors /usr/local/share/cryptopp`
    `$ sudo chmod 755 /usr/local/share/cryptopp`
    `$ sudo chmod 755 /usr/local/share/cryptopp/TestData`
    `$ sudo chmod 755 /usr/local/share/cryptopp/TestVectors`
    `$ sudo chmod 644 /usr/local/share/cryptopp/TestData/*.dat`
    `$ sudo chmod 644 /usr/local/share/cryptopp/TestVectors/*.txt`

If you face any error while installing go to this [link](https://www.cryptopp.com/wiki/Linux#Build_and_Install_the_Library) for trobleshooting and other compiling information

4. Compiling qnd executing the file

    `$ g++ zonal_enc.cc -I <path to the place where you downloaded PBC library>/include/ -L. -lpbc -lgmp -l:libcryptopp.a`
   For example, if I downloaded the PBC library in the same directory where zonal encryption file is present, then I would write:
    `$ g++ zonal_enc.cc -I ./pbc-0.5.14/include/ -L. -lpbc -lgmp -l:libcryptopp.a`
   The above command should runs successfully without errors (warnings are fine).
     `$ ./a.out`
