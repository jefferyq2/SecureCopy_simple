//
//  main.cpp
//  sundec
//
//  Created by Jason Ho on 9/1/17.
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

int transfer_mode(const char file_name[], const char port[]);
int local_mode(const char file_name[]);
int key_gen(unsigned char key[]);
int decrypt(unsigned char key[], const unsigned char *ciphertext, unsigned char **plaintext, unsigned char *mac, long cipher_len);
int read_file(const char file_name[], unsigned char **ciphertext, unsigned char **mac, long *cipher_len);
int write_file(const char file_name[], unsigned char *plaintext, long cipher_len);

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
int transfer_mode(const char file_name[], const char port[]) {
    int error_code = 0;
    
    // setup socket connection
    
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(server_fd < 0) {
        cout << "Failed to create socket." << endl;
        return 3;
    }
    
    struct sockaddr_in serv_addr;
    int serv_addr_len = sizeof(sockaddr_in);
    memset(&serv_addr, '0', sizeof(sockaddr_in));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(atoi(string(port).c_str()));
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    
    error_code = ::bind(server_fd, (struct sockaddr *)&serv_addr, sizeof(sockaddr_in));
    if(error_code < 0) {
        cout << "Failed to bind." << endl;
        return 3;
    }
    
    error_code = listen(server_fd, 3);
    if(error_code < 0) {
        cout << "Listen failed." << endl;
        return 3;
    }
    cout << "Waiting for connections." << endl;
    
    int client_fd = accept(server_fd, (struct sockaddr *)&serv_addr, (socklen_t*)&serv_addr_len);
    if(client_fd < 0) {
        cout << "Failed to accept." << endl;
        return 3;
    }
    
    // receiving data
    
    unsigned char *ciphertext;
    unsigned char *mac = new unsigned char[gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
    long cipher_len;
    struct container package;
    unsigned char *buf_ptr = package.buffer;
    
    // keep receiving till all data is transmitted
    unsigned int in_bytes = 0;
    unsigned char *ptr = (unsigned char *)&package;
    do {
        long bytes_received = recv(client_fd, ptr + in_bytes, sizeof(container) - in_bytes, 0);
        if(bytes_received < 0) {
            cout << "Unable to receive file." << endl;
            close(client_fd);
            close(server_fd);
            return 3;
        }
        else if(bytes_received == 0) { // connection closed!
            cout << "Connection closed unexpectedly." << endl;
            close(client_fd);
            close(server_fd);
            return 3;
        }
        else {
            in_bytes += bytes_received;
            cout << bytes_received << " bytes received." << endl;
        }
    } while(in_bytes < sizeof(unsigned long) + sizeof(unsigned char) * package.data_len);
    close(client_fd);
    close(server_fd);
    cout << "Inbound file." << endl;
    
    cipher_len = package.data_len - gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    ciphertext = new unsigned char[cipher_len];
    for(int i = 0; i < cipher_len; i++)
        ciphertext[i] = *(buf_ptr++);
    for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++)
        mac[i] = *(buf_ptr++);

    // file handling and decryption
    
    unsigned char key[gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128)];
    
    error_code = key_gen(key);
    if(error_code) {
        cout << "Key generation failed." << endl;
        return error_code;
    }
    
    unsigned char *plaintext = new unsigned char[cipher_len];
    error_code = decrypt(key, ciphertext, &plaintext, mac, cipher_len);
    if(error_code) {
        cout << "Decryption failed." << endl;
        delete[] plaintext;
        delete[] ciphertext;
        delete[] mac;
        return error_code;
    }
    
    error_code = write_file(file_name, plaintext, cipher_len);
    if(error_code)
        return error_code;
    
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
    
    unsigned char *ciphertext;
    unsigned char *mac = new unsigned char[gcry_md_get_algo_dlen(GCRY_MD_SHA512)];
    long cipher_len;
    error_code = read_file(file_name, &ciphertext, &mac, &cipher_len);
    if(error_code)
        return 2;
    
    unsigned char *plaintext = new unsigned char[cipher_len];
    error_code = decrypt(key, ciphertext, &plaintext, mac, cipher_len);
    if(error_code) {
        cout << "Decryption failed." << endl;
        delete[] plaintext;
        delete[] ciphertext;
        delete[] mac;
        return error_code;
    }
    
    // truncate the ".uf" extension
    string out_file_name(file_name);
    out_file_name = out_file_name.substr(0, out_file_name.length() - 3);
    
    error_code = write_file(out_file_name.c_str(), plaintext, cipher_len);
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

int decrypt(unsigned char key[], const unsigned char *ciphertext, unsigned char **plaintext, unsigned char *mac, long cipher_len) {
    gcry_error_t error_code;
    
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
    
    gcry_md_write(md_handle, ciphertext, cipher_len);
    
    // get hash computed from the encrypted file part
    unsigned char *tag = gcry_md_read(md_handle, GCRY_MD_SHA512);
    
    // compare the hash and the HMAC
    for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++) {
        if(mac[i] != tag[i]) {
            cout << "MAC verification failed." << endl;
            return 62;
        }
    }
    
    gcry_md_close(md_handle);
    
    // decryption
    
    gcry_cipher_hd_t decrypt_handle;
    error_code = gcry_cipher_open(&decrypt_handle, GCRY_CIPHER_AES128, GCRY_CIPHER_MODE_CBC, 0);
    if(error_code) {
        cout << "Failed to allocate decryption handle." << endl;
        return error_code;
    }
    
    error_code = gcry_cipher_setkey(decrypt_handle, key, gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES128));
    if(error_code) {
        cout << "Failed to set decryption key." << endl;
        return error_code;
    }
    
    // make IV to be the same length as AES block size
    unsigned long uint_count = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128) / sizeof(unsigned int);
    unsigned int *iv = new unsigned int[uint_count];
    memset(iv, 0, gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128));
    iv[uint_count - 1] = 5844;
    error_code = gcry_cipher_setiv(decrypt_handle, iv, gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES128));
    if(error_code) {
        cout << "Failed to set IV." << endl;
        return error_code;
    }
    delete[] iv;
    
    error_code = gcry_cipher_decrypt(decrypt_handle, *plaintext, cipher_len, ciphertext, cipher_len);
    if(error_code) {
        cout << "Failed to decrypt." << endl;
        return error_code;
    }
    
    gcry_cipher_close(decrypt_handle);
    
    return 0;
}

// read file from disk when -l option is used
int read_file(const char file_name[], unsigned char **ciphertext, unsigned char **mac, long *cipher_len) {
    ifstream ifs;
    ifs.open(file_name, ios::binary);
    if(!ifs.good()) {
        cout << string(file_name) + " doesn't exist." << endl;
        return 1;
    }
    
    // get ciphertext length
    ifs.seekg(0, ifs.end);
    *cipher_len = int(ifs.tellg()) - gcry_md_get_algo_dlen(GCRY_MD_SHA512);
    ifs.seekg(0, ifs.beg);
    
    *ciphertext = new unsigned char[*cipher_len];
    for(int i = 0; i < *cipher_len; i++)
        ifs >> noskipws >> (*ciphertext)[i];
    for(int i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA512); i++)
        ifs >> noskipws >> (*mac)[i];
    
    ifs.close();
    
    return 0;
}

// write file to disk
int write_file(const char file_name[], unsigned char *plaintext, long cipher_len) {
    
    //check if output file already exists
    
    ifstream ifs;
    ifs.open(file_name, ios::in);
    if(ifs.good()) {
        cout << string(file_name) + " already exists!" << endl;
        return 33;
    }
    ifs.close();
    
    // write to file
    
    ofstream ofs;
    ofs.open(file_name, ios::out);
    
    // de-padding
    long plain_len = cipher_len - long(plaintext[cipher_len - 1]);
    
    for(int i = 0; i < plain_len; i++)
        ofs << noskipws << plaintext[i];
    
    cout << "Successfully decrypted " << file_name << " (" << ofs.tellp() << " bytes written)." << endl;
    
    ofs.close();
    
    return 0;
}
