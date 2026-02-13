#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <iostream>

#define PORT 4444

EVP_PKEY* load_key(const char* file, bool priv)
{
    FILE* f = fopen(file, "rb");
    EVP_PKEY* k = priv ?
        PEM_read_PrivateKey(f, NULL, NULL, NULL) :
        PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    return k;
}

void hkdf_derive(unsigned char* shared,
                 unsigned char* transcript,
                 unsigned char* aes_key)
{
    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_salt(ctx,
                                transcript, 128);
    EVP_PKEY_CTX_set1_hkdf_key(ctx,
                               shared, 32);

    size_t len = 32;
    EVP_PKEY_derive(ctx, aes_key, &len);
    EVP_PKEY_CTX_free(ctx);
}

void sign_data(EVP_PKEY* key,
               unsigned char* data,
               unsigned char* sig)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t len = 64;
    EVP_DigestSignInit(ctx, NULL, NULL, NULL, key);
    EVP_DigestSign(ctx, sig, &len, data, 128);
    EVP_MD_CTX_free(ctx);
}

bool verify_sig(EVP_PKEY* key,
                unsigned char* data,
                unsigned char* sig)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key);
    int ok = EVP_DigestVerify(ctx, sig, 64, data, 128);
    EVP_MD_CTX_free(ctx);
    return ok == 1;
}

#include <openssl/rand.h>

bool aes_gcm_encrypt(const unsigned char* key,
                     const unsigned char* plaintext,
                     int plaintext_len,
                     unsigned char* iv,
                     unsigned char* ciphertext,
                     unsigned char* tag)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;

    RAND_bytes(iv, 12);

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_EncryptUpdate(ctx, ciphertext, &len,
                      plaintext, plaintext_len);

    int ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                        16, tag);

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

bool aes_gcm_decrypt(const unsigned char* key,
                     const unsigned char* ciphertext,
                     int ciphertext_len,
                     unsigned char* iv,
                     unsigned char* tag,
                     unsigned char* plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len,
                      ciphertext, ciphertext_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                        16, tag);

    int ret = EVP_DecryptFinal_ex(ctx,
                                  plaintext + len,
                                  &len);

    EVP_CIPHER_CTX_free(ctx);

    return ret > 0;
}


int main()
{
    OpenSSL_add_all_algorithms();

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    connect(sock, (sockaddr*)&addr, sizeof(addr));

    EVP_PKEY* my_x = load_key("x25519_priv.pem", true);
    EVP_PKEY* my_ed = load_key("ed25519_priv.pem", true);

    unsigned char client_x[32];
    unsigned char client_ed[32];

    size_t len = 32;
    EVP_PKEY_get_raw_public_key(my_x,
                                client_x, &len);

    EVP_PKEY* pub_ed =
        load_key("ed25519_pub.pem", false);
    EVP_PKEY_get_raw_public_key(pub_ed,
                                client_ed, &len);

    send(sock, client_x, 32, 0);
    send(sock, client_ed, 32, 0);

    unsigned char server_x[32];
    unsigned char server_ed[32];

    recv(sock, server_x, 32, 0);
    recv(sock, server_ed, 32, 0);

    unsigned char transcript[128];
    memcpy(transcript, client_x, 32);
    memcpy(transcript+32, server_x, 32);
    memcpy(transcript+64, client_ed, 32);
    memcpy(transcript+96, server_ed, 32);

    unsigned char sig[64];
    sign_data(my_ed, transcript, sig);
    send(sock, sig, 64, 0);

    unsigned char server_sig[64];
    recv(sock, server_sig, 64, 0);

    EVP_PKEY* server_ed_key =
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_ED25519, NULL,
            server_ed, 32);

    if (!verify_sig(server_ed_key,
                    transcript, server_sig))
    {
        std::cout << "Server authentication failed\n";
        return 1;
    }

    std::cout << "Server authenticated\n";

    EVP_PKEY* peer_x =
        EVP_PKEY_new_raw_public_key(
            EVP_PKEY_X25519, NULL,
            server_x, 32);

    EVP_PKEY_CTX* ctx =
        EVP_PKEY_CTX_new(my_x, NULL);

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_x);

    unsigned char shared[32];
    size_t slen = 32;
    EVP_PKEY_derive(ctx, shared, &slen);

    unsigned char aes_key[32];
    hkdf_derive(shared, transcript, aes_key);

    std::cout << "Shared AES key derived\n";
    std::cout << "AES key: ";
    for (int i = 0; i < 32; i++)
        printf("%02x", aes_key[i]);
    std::cout << std::endl;
    // -------- AES-GCM Encrypt --------
    const char* msg = "Hello secure world!";
    unsigned char iv[12];
    unsigned char ciphertext[128];
    unsigned char tag[16];

    aes_gcm_encrypt(aes_key,
                (unsigned char*)msg,
                strlen(msg),
                iv,
                ciphertext,
                tag);

// Send: IV + ciphertext + tag
    send(sock, iv, 12, 0);
    send(sock, ciphertext, strlen(msg), 0);
    send(sock, tag, 16, 0);

    std::cout << "Encrypted message sent\n";

    close(sock);
}
