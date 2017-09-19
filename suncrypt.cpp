//
//  main.cpp
//  suncrypt
//
//  Created by Jason Ho on 8/30/17.
//  Copyright © 2017 JasonHo. All rights reserved.
//

#include <iostream>
#include <gcrypt.h>
#include <string>
#include <iomanip>
#include <fstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

using namespace std;

// data structure to contain data to be transmitted
struct container {
    unsigned long data_len;
    unsigned char buffer[5000000];
};

int transfer_mode(const char file_name[], const char host_addr[]);
int local_mode(const char file_name[]);
int key_gen(unsigned char key[]);
int encrypt(unsigned char key[], const unsigned char *plaintext, unsigned char **ciphertext, unsigned char **mac, long cipher_len);
int read_file(const char file_name[], unsigned char **plaintext, long *cipher_len);
int write_file(const char file_name[], unsigned char *ciphertext, unsigned char *mac, long cipher_len);
int parse_addr(const char addr[]);

int main(int argc, const char * argv[]) {
    gcry_check_version(NULL);
    gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
    gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
    
    int error_code = 0;
    
    if(argv[2][1] == 'd')
        error_code = transfer_mode(argv[1], argv[3]);
    else if(argv[2][1] == 'l')
        error_code = local_mode(argv[1]);
    else {
        cout << "No such commend." << endl;
        return 1;
    }
    
    return error_code;
}

// -d option
int transfer_mode(const char file_name[], const char host_addr[]) {
    int error_code = 0;
    
    // file handling and encryption
    
    unsigned char key[gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128)];
    
    error_code = key_gen(key);
    if(error_code) {
        cout << "Key generation failed." << endl;
        return error_code;
    }
    
    unsigned char *plaintext;
    long cipher_len;
    error_code = read_file(file_name, &plaintext, &cipher_len);
    if(error_code)
        return 2;
    
    unsigned char *ciphertext = new unsigned char[cipher_len];
    unsigned char *mac = new unsigned char[gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
    error_code = encrypt(key, plaintext, &ciphertext, &mac, cipher_len);
    if(error_code) {
        cout << "Encryption failed." << endl;
        delete[] plaintext;
        delete[] ciphertext;
        delete[] mac;
        return error_code;
    }
    
    // setup socket connection
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) {
        cout << "Failed to create socket." << endl;
        return 3;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, '0', sizeof(sockaddr_in));
    serv_addr.sin_family = AF_INET;
    
    string addr(host_addr);
    unsigned long sep = addr.find(':');
    
    serv_addr.sin_port = htons(atoi(addr.substr(sep + 1, addr.length() - sep - 1).c_str()));
    
    error_code = inet_pton(AF_INET, addr.substr(0, sep).c_str(), &serv_addr.sin_addr);
    if(error_code != 1) {
        cout << "Invalid IP address." << endl;
        return 3;
    }
    
    error_code = connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(sockaddr_in));
    if(error_code < 0) {
        cout << "Failed to connect to server." << endl;
        return 3;
    }
    
    // sending data
    
    struct container package;
    unsigned char *buf_ptr = package.buffer;
    
    package.data_len = cipher_len + gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    for(int i = 0; i < cipher_len; i++)
        *(buf_ptr++) = ciphertext[i];
    for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++)
        *(buf_ptr++) = mac[i];
    
    // keep sending till all data is transmitted
    unsigned int out_bytes = 0;
    unsigned char *ptr = (unsigned char *)&package;
    while(out_bytes < sizeof(unsigned long) + sizeof(unsigned char) * package.data_len) {
        long bytes_sent = send(sockfd, ptr + out_bytes, sizeof(unsigned long) + sizeof(unsigned char) * package.data_len - out_bytes, 0);
        if(bytes_sent < 0) {
            cout << "Unable to send file." << endl;
            close(sockfd);
            return 3;
        }
        else {
            out_bytes += bytes_sent;
            cout << bytes_sent << " bytes sent." << endl;
        }
    }
    cout << "Successfully sent file to " << host_addr << endl;
    
    delete[] plaintext;
    delete[] ciphertext;
    delete[] mac;
    
    return 0;
}

// -l option
int local_mode(const char file_name[]) {
    int error_code = 0;
    unsigned char key[gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128)];
    
    error_code = key_gen(key);
    if(error_code) {
        cout << "Key generation failed." << endl;
        return error_code;
    }
    
    unsigned char *plaintext;
    long cipher_len;
    error_code = read_file(file_name, &plaintext, &cipher_len);
    if(error_code)
        return 2;
    
    unsigned char *ciphertext = new unsigned char[cipher_len];
    unsigned char *mac = new unsigned char[gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
    error_code = encrypt(key, plaintext, &ciphertext, &mac, cipher_len);
    if(error_code) {
        cout << "Encryption failed." << endl;
        delete[] plaintext;
        delete[] ciphertext;
        delete[] mac;
        return error_code;
    }
    
    error_code = write_file(file_name, ciphertext, mac, cipher_len);
    if(error_code)
        return error_code;
    
    delete[] plaintext;
    delete[] ciphertext;
    delete[] mac;
    
    return 0;
}

int key_gen(unsigned char key[]) {
    string password;
    
    cout << "Password: " << flush;
    cin >> password;
    
    gpg_error_t error_code = gcry_kdf_derive(password.c_str(), password.size(), GCRY_KDF_PBKDF2, GCRY_MD_SHA512, "NaCl", 4, 4096, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128), key);
    if(error_code)
        return error_code;
    
    // print key in hexadecimal format
    cout << "Key: " << hex << uppercase << flush;
    for(int i = 0; i < gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128); i++)
        cout << setw(2) << setfill('0') << short(key[i]) << ' ';
    cout << dec << endl;
    
    return 0;
}

int encrypt(unsigned char key[], const unsigned char *plaintext, unsigned char **ciphertext, unsigned char **mac, long cipher_len) {
    gcry_error_t error_code;
    
    // encryption
    
    gcry_cipher_hd_t encrypt_handle;
    error_code = gcry_cipher_open(&encrypt_handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
    if(error_code) {
        cout << "Failed to allocate encryption handle." << endl;
        return error_code;
    }
    
    error_code = gcry_cipher_setkey(encrypt_handle, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128));
    if(error_code) {
        cout << "Failed to set encryption key." << endl;
        return error_code;
    }
    
    // make IV to be the same length as AES block size
    unsigned long uint_count = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128) / sizeof(unsigned int);
    unsigned int *iv = new unsigned int[uint_count];
    memset(iv, 0, gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128));
    iv[uint_count - 1] = 5844;
    error_code = gcry_cipher_setiv(encrypt_handle, iv, gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128));
    if(error_code) {
        cout << "Failed to set IV." << endl;
        return error_code;
    }
    delete[] iv;
    
    error_code = gcry_cipher_encrypt(encrypt_handle, *ciphertext, cipher_len, plaintext, cipher_len);
    if(error_code) {
        cout << "Failed to encrypt." << endl;
        return error_code;
    }
    
    gcry_cipher_close(encrypt_handle);
    
    // MAC
    
    gcry_md_hd_t md_handle;
    error_code = gcry_md_open(&md_handle, GCRY_MD_SHA512, GCRY_MD_FLAG_HMAC);
    if(error_code) {
        cout << "Failed to allocate md handle." << endl;
        return error_code;
    }
    
    error_code = gcry_md_setkey(md_handle, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128));
    if(error_code) {
        cout << "Failed to set mac key." << endl;
        return error_code;
    }
    
    gcry_md_write(md_handle, *ciphertext, cipher_len);
    
    unsigned char *temp = gcry_md_read(md_handle, GCRY_MD_SHA512);
    for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++)
        (*mac)[i] = temp[i];
    
    gcry_md_close(md_handle);
    
    return 0;
}

// read file from disk
int read_file(const char file_name[], unsigned char **plaintext, long *cipher_len) {
    ifstream ifs;
    ifs.open(file_name, ios::binary);
    if(!ifs.good()) {
        cout << string(file_name) + " doesn't exist." << endl;
        return 1;
    }
    
    // get plaintext length
    ifs.seekg(0, ifs.end);
    long plain_len = ifs.tellg();
    ifs.seekg(0, ifs.beg);
    
    // make cipher_len multiple of AES block size
    *cipher_len = (plain_len / gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128) + 1) * gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128);
    
    *plaintext = new unsigned char[*cipher_len];
    for(int i = 0; i < plain_len; i++)
        ifs >> noskipws >> (*plaintext)[i];
    // PKCS7 padding
    long pad = *cipher_len - plain_len;
    for(long i = plain_len; i < *cipher_len; i++)
        (*plaintext)[i] = pad;
    
    ifs.close();
    
    return 0;
}

// write file to disk when -l option is used
int write_file(const char file_name[], unsigned char *ciphertext, unsigned char *mac, long cipher_len) {
    
    //check if output file already exists
    
    ifstream ifs;
    ifs.open((string(file_name) + ".uf").c_str(), ios::in);
    if(ifs.good()) {
        cout << string(file_name) + ".uf already exists!" << endl;
        return 33;
    }
    ifs.close();
    
    // write to file
    
    ofstream ofs;
    ofs.open((string(file_name) + ".uf").c_str(), ios::out);
    
    for(int i = 0; i < cipher_len; i++)
        ofs << noskipws << ciphertext[i];
    for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++)
        ofs << noskipws << mac[i];
    
    cout << "Successfully encrypted " << file_name << " to " << file_name << ".uf (" << ofs.tellp() << " bytes written)." << endl;
    
    ofs.close();
    
    return 0;
}
