/*
    pesC_server/src/test.cpp just a test
    Copyright (C) 2026 jhen123

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    3 any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
#include <iostream>
#include "crow.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
// 加密：返回密文长度，失败返回-1
// key: 32字节密钥（AES-256）
// iv: 16字节初始化向量（需随机生成，可附在密文前传输）
// plaintext: 输入明文
// plaintext_len: 明文长度
// ciphertext: 输出密文（缓冲区需至少 plaintext_len + 16 字节）
int aes_encrypt(const unsigned char* key, const unsigned char* iv,
    const unsigned char* plaintext, int plaintext_len,
    unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, ciphertext_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}
// 解密：返回明文长度，失败返回-1
// key: 32字节密钥（与加密一致）
// iv: 16字节初始化向量（与加密一致）
// ciphertext: 输入密文
// ciphertext_len: 密文长度
// plaintext: 输出明文（缓冲区需至少 ciphertext_len 字节）
int aes_decrypt(const unsigned char* key, const unsigned char* iv,
    const unsigned char* ciphertext, int ciphertext_len,
    unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int len = 0, plaintext_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
int main(){
    std::cout << "hello,world" << std::endl;
//    crow::SimpleApp app;
//    CROW_ROUTE(app,"/")([](){
//            return "ok";
//        });
//    app.port(18080).multithreaded().run();
    unsigned char* key = nullptr,*iv = nullptr,*encr = nullptr,*decr = nullptr;
    RAND_bytes(key, 32);
    RAND_bytes(iv, 16);
    std::string str;
    std::cin >> str;
    aes_encrypt(key,iv,str,str.length(),encr);
    aes_decrypt(key, iv, encr, strlen(encr), decr);
    std::cout << decr;
    return 0;
}
