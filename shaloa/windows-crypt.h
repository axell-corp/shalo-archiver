#pragma once
#include <bcrypt.h>
#include <memory>
#include <vector>

struct cng_params_size {
	int aes_key_size;
	int aes_iv_size;
	int aes_nonce_size;
};

struct cng_encrypted {
	std::vector<uint8_t> encrypted_data;
	std::vector<uint8_t> aes_tag;
};

struct rsa_key {
    std::vector<uint8_t> public_exponent;
    std::vector<uint8_t> private_exponent;
    std::vector<uint8_t> modulus;
    std::vector<uint8_t> prime1;
    std::vector<uint8_t> prime2;
    std::vector<uint8_t> exponent1;
    std::vector<uint8_t> exponent2;
    std::vector<uint8_t> coefficient;
};

std::vector<uint8_t> cng_sha256(const std::vector<uint8_t>& vec);

std::unique_ptr<cng_params_size> get_cng_encrypt_params_size();

std::unique_ptr<cng_encrypted> cng_encrypt(const std::vector<uint8_t>& raw_vec, const std::vector<uint8_t>& aes_key, const std::vector<uint8_t>& aes_iv, const std::vector<uint8_t>& aes_nonce);
std::vector<uint8_t> cng_decrypt(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& aes_key, const std::vector<uint8_t>& aes_iv, const std::vector<uint8_t>& aes_nonce, const std::vector<uint8_t>& aes_tag);

BCRYPT_RSAKEY_BLOB *cng_generate_rsa_key_blob();
std::unique_ptr<rsa_key> cng_convert_rsa_key_from_blob(const BCRYPT_RSAKEY_BLOB *blob);
