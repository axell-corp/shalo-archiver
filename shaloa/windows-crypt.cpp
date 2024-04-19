#include "pch.h"
#include "windows-crypt.h"
#include "exceptions.h"
#include <string>
#include <boost/scope_exit.hpp>

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

std::vector<uint8_t> cng_sha256(const std::vector<uint8_t>& vec)
{
    std::string error_msg = "SHA256 ハッシュの計算に失敗しました";

    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    auto result = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&alg_handle) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    DWORD hash_length = 0, data = 0;
    result = BCryptGetProperty(alg_handle, BCRYPT_HASH_LENGTH, (PBYTE)&hash_length, sizeof(DWORD), &data, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    std::vector<uint8_t> ret(hash_length);
    result = BCryptHash(alg_handle, nullptr, 0, const_cast<PUCHAR>(vec.data()), vec.size(), ret.data(), ret.size());

    return ret;
}

std::unique_ptr<cng_params_size> get_cng_encrypt_params_size()
{
    std::string error_msg = "暗号化のためのパラメータの取得に失敗しました";

    auto ret = std::make_unique<cng_params_size>();

    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    auto result = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&alg_handle) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    result = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    DWORD iv_block_size = 0, data = 0;
    result = BCryptGetProperty(alg_handle, BCRYPT_BLOCK_LENGTH, (PBYTE)&iv_block_size, sizeof(DWORD), &data, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    ret->aes_iv_size = iv_block_size;
    ret->aes_key_size = 32;
    ret->aes_nonce_size = 12;

    return ret;
}

std::unique_ptr<cng_encrypted> cng_encrypt(const std::vector<uint8_t>& raw_vec, const std::vector<uint8_t>& aes_key, const std::vector<uint8_t>& aes_iv, const std::vector<uint8_t>& aes_nonce)
{
    std::string error_msg = "暗号化に失敗しました";

    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    auto result = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&alg_handle) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    result = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    auto auth_tag_length = std::make_unique<BCRYPT_AUTH_TAG_LENGTHS_STRUCT>();
    DWORD data = 0;
    result = BCryptGetProperty(alg_handle, BCRYPT_AUTH_TAG_LENGTH, (PBYTE)auth_tag_length.get(), sizeof(BCRYPT_AUTH_TAG_LENGTHS_STRUCT), &data, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BCRYPT_KEY_HANDLE key_handle = nullptr;
    result = BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, const_cast<PUCHAR>(aes_key.data()), aes_key.size(), 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&key_handle) {
        BCryptDestroyKey(key_handle);
    };

    auto auth_tag = std::vector<uint8_t>(auth_tag_length->dwMinLength);
    auto auth_info = std::make_unique<BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO>();
    BCRYPT_INIT_AUTH_MODE_INFO(*auth_info);
    auth_info->pbNonce = const_cast<PUCHAR>(aes_nonce.data());
    auth_info->cbNonce = aes_nonce.size();
    auth_info->pbTag = auth_tag.data();
    auth_info->cbTag = auth_tag.size();

    auto iv_buffer = std::vector<uint8_t>(aes_iv.size());
    std::copy(aes_iv.begin(), aes_iv.end(), iv_buffer.begin());

    DWORD cipher_data_size = 0;
    result = BCryptEncrypt(key_handle, const_cast<PUCHAR>(raw_vec.data()), raw_vec.size(), auth_info.get(), iv_buffer.data(), iv_buffer.size(), nullptr, 0, &cipher_data_size, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    std::copy(aes_iv.begin(), aes_iv.end(), iv_buffer.begin());

    auto ret = std::make_unique<cng_encrypted>();
    ret->encrypted_data.resize(cipher_data_size);

    result = BCryptEncrypt(key_handle, const_cast<PUCHAR>(raw_vec.data()), raw_vec.size(), auth_info.get(), iv_buffer.data(), iv_buffer.size(), ret->encrypted_data.data(), ret->encrypted_data.size(), &data, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    ret->aes_tag = auth_tag;

    return ret;
}

std::vector<uint8_t> cng_decrypt(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& aes_key, const std::vector<uint8_t>& aes_iv, const std::vector<uint8_t>& aes_nonce, const std::vector<uint8_t>& aes_tag)
{
    std::string error_msg = "復号に失敗しました";

    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    DWORD data = 0, key_object_size = 0;
    //aes_key.resize(0x20);

    auto status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, status, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&alg_handle) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    status = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, status, error_msg);
    }

    status = BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, aes_key.data(), aes_key.size(), 0);
    if (status < 0) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, status, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&key_handle) {
        BCryptDestroyKey(key_handle);
    };

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info{};
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = const_cast<PUCHAR>(aes_nonce.data());
    auth_info.cbNonce = aes_nonce.size();
    auth_info.pbTag = const_cast<PUCHAR>(aes_tag.data());
    auth_info.cbTag = aes_tag.size();

    auto iv_buffer = std::vector<uint8_t>(aes_iv.size());
    std::copy(aes_iv.begin(), aes_iv.end(), iv_buffer.begin());

    ULONG decrypted_data_len = 0;
    status = BCryptDecrypt(key_handle, const_cast<PUCHAR>(encrypted.data()), encrypted.size(), &auth_info, iv_buffer.data(), iv_buffer.size(),
        nullptr, 0, &decrypted_data_len, 0);
    if (status < 0) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, status, error_msg);
    }

    std::copy(aes_iv.begin(), aes_iv.end(), iv_buffer.begin());

    auto ret = std::vector<uint8_t>(decrypted_data_len);
    status = BCryptDecrypt(key_handle, const_cast<PUCHAR>(encrypted.data()), encrypted.size(), &auth_info, iv_buffer.data(), iv_buffer.size(),
        ret.data(), ret.size(), &decrypted_data_len, 0);
    if (status < 0) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, status, error_msg);
    }

    return ret;
}

std::vector<uint8_t> key_data_to_vector(const char* ptr, ULONG field_size) {
    auto ret = std::vector<uint8_t>(field_size);
    for (auto i = 0; i < field_size; i++) {
        ret[i] = ptr[i];
    }
    return ret;
}

BCRYPT_RSAKEY_BLOB *cng_generate_rsa_key_blob() {
    std::string error_msg = "RSA 鍵の生成に失敗しました";
    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;

    auto result = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&alg_handle) {
        BCryptCloseAlgorithmProvider(alg_handle, 0);
    };

    result = BCryptGenerateKeyPair(alg_handle, &key_handle, 4096, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    BOOST_SCOPE_EXIT_ALL(&key_handle) {
        BCryptDestroyKey(key_handle);
    };

    result = BCryptFinalizeKeyPair(key_handle, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    ULONG key_data_size = 0;
    result = BCryptExportKey(key_handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &key_data_size, 0);
    if (!NT_SUCCESS(result)) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    //auto blob = std::make_unique<BCRYPT_RSAKEY_BLOB>(key_data_size);
    auto blob = (BCRYPT_RSAKEY_BLOB *)LocalAlloc(LPTR, key_data_size);

    result = BCryptExportKey(key_handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)blob, key_data_size, &key_data_size, 0);
    if (!NT_SUCCESS(result)) {
        LocalFree(blob);
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, error_msg);
    }

    //return std::move(blob);
    return blob;
}

std::unique_ptr<rsa_key> cng_convert_rsa_key_from_blob(const BCRYPT_RSAKEY_BLOB *blob) {
    auto ret = std::make_unique<rsa_key>();
    char* ptr = (char*)blob + sizeof(BCRYPT_RSAKEY_BLOB);
    ret->public_exponent = key_data_to_vector(ptr, blob->cbPublicExp);
    ptr += blob->cbPublicExp;
    ret->modulus = key_data_to_vector(ptr, blob->cbModulus);
    ptr += blob->cbModulus;
    ret->prime1 = key_data_to_vector(ptr, blob->cbPrime1);
    ptr += blob->cbPrime1;
    ret->prime2 = key_data_to_vector(ptr, blob->cbPrime2);
    ptr += blob->cbPrime2;

    ret->exponent1 = key_data_to_vector(ptr, blob->cbPrime1);
    ptr += blob->cbPrime1;
    ret->exponent2 = key_data_to_vector(ptr, blob->cbPrime2);
    ptr += blob->cbPrime2;
    ret->coefficient = key_data_to_vector(ptr, blob->cbPrime1);
    ptr += blob->cbPrime1;
    ret->private_exponent = key_data_to_vector(ptr, blob->cbModulus);

    return std::move(ret);
}
