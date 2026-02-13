#include <openssl/evp.h>
#include <openssl/pem.h>
#include <iostream>

void generate(int type,
              const char* priv,
              const char* pub)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(type, NULL);
    EVP_PKEY* pkey = nullptr;

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &pkey);

    FILE* f = fopen(priv, "wb");
    PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    f = fopen(pub, "wb");
    PEM_write_PUBKEY(f, pkey);
    fclose(f);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
}

int main()
{
    OpenSSL_add_all_algorithms();

    generate(EVP_PKEY_X25519,
             "x25519_priv.pem",
             "x25519_pub.pem");

    generate(EVP_PKEY_ED25519,
             "ed25519_priv.pem",
             "ed25519_pub.pem");

    std::cout << "Keys generated\n";
}
