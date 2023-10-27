#include "pch.h"
#include "file-crypt.h"
#include "module.h"
#include "token.h"
#include "windows-crypt.h"
#include "exceptions.h"
#include "../common/pkcs11common.h"
#include <iostream>
#include <codecvt>
#include <optional>
#include <fstream>
#include <concepts>

#pragma comment(lib, "bcrypt.lib")

struct encrypt_data {
    std::string filename_extension;
    std::vector<uint8_t> encrypted_aes_key;
    std::vector<uint8_t> aes_iv;
    std::vector<uint8_t> aes_nonce;
    std::vector<uint8_t> aes_tag;
    std::vector<uint8_t> rsa_pubkey_modulus;
    std::vector<uint8_t> encrypted_file;
};

extern std::string last_error_message;

std::vector<uint8_t> open_file(std::filesystem::path file_path) {
    auto ifs = std::ifstream(file_path, std::ios::in | std::ios::binary);
    if (!ifs) {
        throw OtherException(SHALOA_RESULT_ERROR_FILE_IO, "指定されたファイルが開けません");
    }
    ifs.seekg(0, std::ios::end);
    size_t size = ifs.tellg();
    ifs.seekg(0);

    auto ret = std::vector<uint8_t>(size);
    ifs.read((char*)ret.data(), size);

    return ret;
}

std::vector<uint8_t> number_to_vector(int a, int size) {
    int k = log(a) / log(256) + 1;
    if (k > size) {
        throw OtherException(SHALOA_RESULT_ERROR_INTERNAL, "k > size");
    }

    std::vector<unsigned char> ret(size, 0);

    for (int i = 0; i < k; i++) {
        ret[i] = a % 256;
        a >>= 8;
    }

    return ret;
}

template <typename T>
constexpr auto vector_to_number(std::vector<uint8_t> v) requires std::unsigned_integral<T> {
    T ret = 0;
    for (int i = 0; i < (int)v.size(); i++) {
        ret += v[i] << 8 * i;
    }
    return ret;
}

constexpr void concat_vector(std::vector<uint8_t>& v1, const std::initializer_list<const std::vector<uint8_t>>& v_list) {
    for (const auto& v : v_list) {
        v1.insert(v1.end(), v.begin(), v.end());
    }
}

std::vector<uint8_t> generate_header(
    const std::filesystem::path file_path,
    const uint64_t encrypted_file_size,
    const std::vector<uint8_t>& encrypted_aes_key,
    const std::vector<uint8_t>& aes_iv,
    const std::vector<uint8_t>& aes_nonce,
    const std::vector<uint8_t>& aes_tag,
    const std::vector<uint8_t>& rsa_pubkey_modulus
) {
    /*
        signature("SHAA")                     | 4 bytes
        header length                         | 4 bytes
        entire file length                    | 8 bytes
        filename extension length             | 2 bytes
        filename extension                    | dynamic
        encrypted AES key length              | 2 bytes
        encrypted AES key                     | dynamic
        AES IV length                         | 1 byte
        AES IV                                | dynamic
        AES nonce length                      | 1 byte
        AES nonce                             | dynamic
        AES auth tag length                   | 1 byte
        AES auth tag                          | dynamic
        Hash of RSA public key modulus length | 2 bytes
        Hash of RSA public key modulus        | dynamic
    */

    auto filename_extension = file_path.extension().string();

    size_t header_length = sizeof(uint32_t) + sizeof(uint64_t)
        + sizeof(uint16_t) + filename_extension.size()
        + sizeof(uint16_t) + encrypted_aes_key.size()
        + sizeof(uint8_t) + aes_iv.size()
        + sizeof(uint8_t) + aes_nonce.size()
        + sizeof(uint8_t) + aes_tag.size()
        + sizeof(uint16_t) + rsa_pubkey_modulus.size();

    auto ret = std::vector<uint8_t>();
    ret.reserve(header_length + 4);

    concat_vector(ret, {
        std::vector<uint8_t>({'S', 'H', 'A', 'A'}),
        number_to_vector(header_length, sizeof(uint32_t)),
        number_to_vector(header_length + encrypted_file_size + 4, sizeof(uint64_t)),
        number_to_vector(filename_extension.size(), sizeof(uint16_t)), std::vector<uint8_t>(filename_extension.begin(), filename_extension.end()),
        number_to_vector(encrypted_aes_key.size(), sizeof(uint16_t)), encrypted_aes_key,
        number_to_vector(aes_iv.size(), sizeof(uint8_t)), aes_iv,
        number_to_vector(aes_nonce.size(), sizeof(uint8_t)), aes_nonce,
        number_to_vector(aes_tag.size(), sizeof(uint8_t)), aes_tag,
        number_to_vector(rsa_pubkey_modulus.size(), sizeof(uint16_t)), rsa_pubkey_modulus
        });

    return ret;
}

void save_file(const std::optional<std::vector<uint8_t>> header, const std::vector<uint8_t>& file, std::filesystem::path file_path, const std::optional<std::filesystem::path> extension) {
    if (extension.has_value()) {
        file_path.replace_extension(extension.value());
    }

    auto ofs = std::ofstream(file_path, std::ios::out | std::ios::binary);

    if (header.has_value()) {
        ofs.write((char*)header.value().data(), header.value().size());
    }
    ofs.write((char*)file.data(), file.size());
    ofs << std::flush;
}

std::vector<uint8_t> split_vector_from_head(std::vector<uint8_t>& v, int size) {
    if (v.size() < size) {
        throw OtherException(SHALOA_RESULT_ERROR_INTERNAL, "サイズが vector の長さを上回っています");
    }
    std::vector<uint8_t> ret = { v.begin(), v.begin() + size };
    v.erase(v.begin(), v.begin() + size);
    return ret;
}

std::unique_ptr<encrypt_data> parse_file(std::vector<uint8_t> file) {
    auto ret = std::make_unique<encrypt_data>();

    auto actual_file_size = file.size();

    auto signature_vector = split_vector_from_head(file, 4);
    auto signature = std::string(signature_vector.begin(), signature_vector.end());
    if (signature != "SHAA") {
        throw OtherException(SHALOA_RESULT_ERROR_INVALID_FILE, "ファイルのシグネチャが正しくありません");
    }

    auto header_length = vector_to_number<uint32_t>(split_vector_from_head(file, 4));
    std::vector<uint8_t> header_vector = split_vector_from_head(file, header_length - 4);
    ret->encrypted_file = file;

    auto expected_file_length = vector_to_number<uint64_t>(split_vector_from_head(header_vector, 8));
    if (actual_file_size != expected_file_length) {
        throw OtherException(SHALOA_RESULT_ERROR_INVALID_FILE, std::format("ファイルサイズが不正です, expected: {}, actual: {}", expected_file_length, actual_file_size).c_str());
    }

    auto filename_extension_length = vector_to_number<uint16_t>(split_vector_from_head(header_vector, 2));
    auto filename_extension_vector = split_vector_from_head(header_vector, filename_extension_length);
    ret->filename_extension = std::string(filename_extension_vector.begin(), filename_extension_vector.end());

    auto encrypted_aes_key_length = vector_to_number<uint16_t>(split_vector_from_head(header_vector, 2));
    ret->encrypted_aes_key = split_vector_from_head(header_vector, encrypted_aes_key_length);

    auto aes_iv_length = vector_to_number<uint8_t>(split_vector_from_head(header_vector, 1));
    ret->aes_iv = split_vector_from_head(header_vector, aes_iv_length);

    auto aes_nonce_length = vector_to_number<uint8_t>(split_vector_from_head(header_vector, 1));
    ret->aes_nonce = split_vector_from_head(header_vector, aes_nonce_length);

    auto aes_tag_length = vector_to_number<uint8_t>(split_vector_from_head(header_vector, 1));
    ret->aes_tag = split_vector_from_head(header_vector, aes_tag_length);

    auto pubkey_modulus_length = vector_to_number<uint16_t>(split_vector_from_head(header_vector, 2));
    ret->rsa_pubkey_modulus = split_vector_from_head(header_vector, pubkey_modulus_length);

    return std::move(ret);
}

int _shaloa_encode(const std::filesystem::path fnInp, const std::filesystem::path fnOutp, int key_id) {
    int ret = SHALOA_RESULT_ERROR_INTERNAL;

    try {
        auto file = open_file(fnInp);

        auto shalo_module = std::make_unique<Module>();
        auto token = std::make_unique<Token>(shalo_module->get_module_pointer());

        token->open_session(0);

        auto aes_params_size = get_cng_encrypt_params_size();
        auto aes_key = token->generate_random_data(aes_params_size->aes_key_size);
        auto aes_iv = token->generate_random_data(aes_params_size->aes_iv_size);
        auto aes_nonce = token->generate_random_data(aes_params_size->aes_nonce_size);

        auto encrypted_by_cng = cng_encrypt(file, aes_key, aes_iv, aes_nonce);

        auto encrypted_by_token = token->encrypt(aes_key, key_id);

        auto header = generate_header(fnInp, encrypted_by_cng->encrypted_data.size(), encrypted_by_token->encrypted_data, aes_iv, aes_nonce, encrypted_by_cng->aes_tag, encrypted_by_token->pubkey_modulus_hash);

        save_file(header, encrypted_by_cng->encrypted_data, fnOutp, std::nullopt);

        ret = SHALOA_RESULT_SUCCESS;
    }
    catch (TokenException& e) {
        last_error_message = e.get_error_message();
        ret = SHALOA_RESULT_ERROR_PKCS_TOKEN;
    }
    catch (OsException& e) {
        last_error_message = e.get_error_message();
        ret = e.get_shaloa_result();
    }
    catch (OtherException& e) {
        last_error_message = e.what();
        ret = e.get_shaloa_result();
    }

    return ret;
}

int _shaloa_decode(const std::filesystem::path fnInp, const std::filesystem::path fnOutp, const char* pin, int *key_id) {
    int ret = SHALOA_RESULT_ERROR_INTERNAL;

    try {
        auto file = open_file(fnInp);

        auto parsed_file = parse_file(file);

        auto shalo_module = std::make_unique<Module>();
        auto token = std::make_unique<Token>(shalo_module->get_module_pointer());

        token->open_session(0);

        token->login(pin);

        auto aes_key = token->decrypt(parsed_file->encrypted_aes_key, parsed_file->rsa_pubkey_modulus);

        auto decrypted = cng_decrypt(parsed_file->encrypted_file, aes_key, parsed_file->aes_iv, parsed_file->aes_nonce, parsed_file->aes_tag);

        save_file(std::nullopt, decrypted, fnOutp, parsed_file->filename_extension);

        if (key_id != nullptr) {
            auto id = token->find_key_id_from_modulus_hash(parsed_file->rsa_pubkey_modulus);
            *key_id = id;
        }

        ret = SHALOA_RESULT_SUCCESS;
    }
    catch (TokenException& e) {
        last_error_message = e.get_error_message();
        ret = SHALOA_RESULT_ERROR_PKCS_TOKEN;
    }
    catch (OsException& e) {
        last_error_message = e.get_error_message();
        ret = e.get_shaloa_result();
    }
    catch (OtherException& e) {
        last_error_message = e.what();
        ret = e.get_shaloa_result();
    }

    return ret;
}
