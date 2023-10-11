#include <iostream>
#include <Windows.h>
#include <memory>
#include <string>
#include <ShlObj.h>
#include <bcrypt.h>
#include <cstdlib>
#include <vector>
#include "pkcs11common.h"

#pragma comment(lib, "bcrypt.lib")

typedef CK_RV(*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
constexpr auto LIBRARY_NAME = "slpkcs11-vc";
constexpr auto LIBRARY_DIRECTORY = "\\shalo_pkcs11\\x64";
constexpr auto RANDOM_STRING_LEN = 20;
constexpr auto AES_KEY_LEN = 32;
constexpr auto AES_TAG_LEN = 16;
constexpr auto AES_NONCE_LEN = 12;

CK_BBOOL bbool_true = CK_TRUE;
CK_BBOOL bbool_false = CK_FALSE;
CK_BYTE object_id[] = { 'S','L','A','R','C','V','K','E','Y','#','1' };

CK_FUNCTION_LIST_PTR g_func_list = nullptr;
CK_SESSION_HANDLE g_session = CK_INVALID_HANDLE;

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

struct aes_cipher_struct {
    std::vector<uint8_t> cipher_data;
    std::vector<uint8_t> encrypted_aes_key;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
    std::vector<uint8_t> nonce;
};

constexpr std::string get_pkcs11err(CK_RV rv) {
    std::string str = "Undocumented error";

    switch (rv) {
    case CKR_OK:
        str = "Success";
        break;
    case CKR_ATTRIBUTE_SENSITIVE:
        str = "Sensitive ttribute cannot be exported";
        break;
    case CKR_ACTION_PROHIBITED:
        str = "Prohibited by cryptoki";
        break;
    case CKR_DATA_LEN_RANGE:
        str = "Input data length is out of range";
        break;
    case CKR_DATA_INVALID:
        str = "Input data is invalid";
        break;
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
        str = "Encrypted data length is out of range";
        break;
    case CKR_ENCRYPTED_DATA_INVALID:
        str = "Encrypted data is invalid";
        break;
    case CKR_SIGNATURE_LEN_RANGE:
        str = "Signature length is out of range";
        break;
    case CKR_SIGNATURE_INVALID:
        str = "Signature is invalid";
        break;
    case CKR_FUNCTION_NOT_SUPPORTED:
        str = "This function is not supported";
        break;
    case CKR_MECHANISM_INVALID:
        str = "Mechanism is invalid";
        break;
    case CKR_MECHANISM_PARAM_INVALID:
        str = "Mechanism parameter is invalid";
        break;
    case CKR_PIN_INCORRECT:
        str = "Incorrect PIN";
        break;
    case CKR_PIN_INVALID:
        str = "PIN was invalid";
        break;
    case CKR_PIN_LEN_RANGE:
        str = "PIN length is out of range";
        break;
    case CKR_PIN_LOCKED:
        str = "PIN has been locked";
        break;
    case CKR_FUNCTION_FAILED:
        str = "Function failed";
        break;
    case CKR_USER_PIN_NOT_INITIALIZED:
        str = "User PIN is not initialized";
        break;
    case CKR_DEVICE_ERROR:
        str = "Device communication error";
        break;
    case CKR_TOKEN_WRITE_PROTECTED:
        str = "Device is write-protected";
        break;
    case CKR_TOKEN_NOT_RECOGNIZED:
        str = "Token is not recognized";
        break;
    case CKR_TOKEN_NOT_PRESENT:
        str = "Token is not present";
        break;

        // Session error
    case CKR_SESSION_READ_ONLY:
        str = "Session read only";
        break;

    case CKR_USER_NOT_LOGGED_IN:
        str = "User not logged in";
        break;

    default:
        break;
    }

    return str;
}

std::string error_message(std::string operation_str, HRESULT result) {
    return operation_str + ": " + get_pkcs11err(result) + " (code: " + std::to_string(result) + ")";
}

void print_hex_vector(std::vector<uint8_t> vec) {
    std::cout << "{ " << std::hex << (int)vec[0] << ", " << (int)vec[1] << ", " << (int)vec[vec.size() - 2] << ", " << (int)vec[vec.size() - 1] << " }";
    std::cout << " (size: " << vec.size() << ")" << std::endl;
}

HMODULE load_module() {
    std::cout << "load module: ";

    HMODULE ret = nullptr;
    char lib_path[MAX_PATH];

    auto get_path_result = SHGetFolderPathA(nullptr, CSIDL_PROFILE, nullptr, 0, lib_path);
    if (get_path_result != S_OK) {
        throw std::runtime_error("failed to get user directory path");
    }

    strcat_s(lib_path, LIBRARY_DIRECTORY);

    auto set_result = SetDllDirectoryA(lib_path);
    if (!set_result) {
        throw std::runtime_error("failed to set dll directory");
    }

    ret = LoadLibraryA(LIBRARY_NAME);
    if (ret == nullptr) {
        throw std::runtime_error("failed to load library");
    }

    std::cout << "success" << std::endl;
    return ret;
}

void* get_func_addr(HMODULE library, std::string func_name) {
    auto ret = GetProcAddress(library, func_name.c_str());

    if (ret == nullptr) {
        throw std::runtime_error("failed to get address of " + func_name);
    }

    return ret;
}

CK_FUNCTION_LIST_PTR get_func_list(HMODULE library) {
    std::cout << "get functions list: ";

    CK_FUNCTION_LIST_PTR ret = nullptr;

    constexpr auto PROCNAME = "C_GetFunctionList";
    auto func = (CK_C_GetFunctionList)get_func_addr(library, PROCNAME);

    if (func == nullptr) {
        throw std::runtime_error("failed to get function address");
        return ret;
    }

    auto result = func(&ret);

    if (result != CKR_OK) {
        ret = nullptr;
        throw std::runtime_error("failed to get function list");
    }

    std::cout << "success" << std::endl;
    return ret;
}

HRESULT initialize() {
    std::cout << "initialize token: ";

    auto result = g_func_list->C_Initialize(nullptr);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to initialize token", result));
    }

    std::cout << "success" << std::endl;
    return result;
}

std::vector<CK_SLOT_ID> get_slot_id_list() {
    std::cout << "get slot IDs list: ";

    CK_ULONG slot_count = 0;

    auto result = g_func_list->C_GetSlotList(CK_TRUE, nullptr, &slot_count);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to get slot count", result));
    }

    auto slot_id_list = std::vector<CK_SLOT_ID>(slot_count);

    result = g_func_list->C_GetSlotList(CK_TRUE, slot_id_list.data(), &slot_count);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to get slot id list", result));
    }

    std::cout << "success" << std::endl;
    return slot_id_list;
}

HRESULT open_session(CK_SLOT_ID slot_id) {
    CK_TOKEN_INFO token_info{};
    auto result = g_func_list->C_GetTokenInfo(slot_id, &token_info);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to get token info", result));
    }

    if (!(token_info.flags & CKF_USER_PIN_INITIALIZED)) {
        throw std::runtime_error("User PIN has not been initialized.");
    }

    std::cout << "open session for id " << slot_id << ": ";

    result = g_func_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &g_session);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to open a session", result));
    }

    std::cout << "success" << std::endl;
    return result;
}

std::string get_password() {
    DWORD mode = 0;
    auto h_stdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(h_stdin, &mode);
    SetConsoleMode(h_stdin, mode & ~ENABLE_ECHO_INPUT);

    std::string ret = "";
    std::cout << "Enter user Pin: ";
    std::getline(std::cin, ret);

    SetConsoleMode(h_stdin, mode | ENABLE_ECHO_INPUT);
    std::cout << std::endl;
    return ret;
}

HRESULT login(CK_SESSION_HANDLE session_handle = g_session) {
    auto pin = get_password();
    auto result = g_func_list->C_Login(session_handle, CKU_USER, (unsigned char*)pin.c_str(), pin.size());

    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to login", result));
    }

    return result;
}

std::vector<uint8_t> generate_random_data(CK_ULONG size) {
    //auto tmp = (CK_BYTE*)malloc(sizeof(CK_BYTE) * size);
    auto ret = std::vector<uint8_t>(size);
    auto result = g_func_list->C_GenerateRandom(g_session, ret.data(), size);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to generate random data", result));
    }

    return ret;
}

std::string generate_random_string(CK_ULONG size) {
    std::string ret = "";
    try {
        auto vec = generate_random_data(size);
        for (int i = 0; i < size; i++) {
            ret += vec[i] % 93 + 33;
        }
    }
    catch (std::exception) {
        throw;
    }

    return ret;
}

std::vector<uint8_t> key_data_to_vector(const char* ptr, ULONG field_size) {
    auto ret = std::vector<uint8_t>(field_size);
    for (auto i = 0; i < field_size; i++) {
        ret[i] = ptr[i];
    }
    //std::reverse(ret.begin(), ret.end());

    return ret;
}

std::unique_ptr<rsa_key> generate_rsa_key() {
    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;

    auto status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_RSA_ALGORITHM, nullptr, 0);
    if (status < 0) {
        throw std::runtime_error("failed to open algorithm provider (code: " + std::to_string(status) + ")");
    }

    status = BCryptGenerateKeyPair(alg_handle, &key_handle, 2048, 0);
    if (status < 0) {
        throw std::runtime_error("failed to generate key pair (code: " + std::to_string(status) + ")");
    }

    status = BCryptFinalizeKeyPair(key_handle, 0);
    if (status < 0) {
        throw std::runtime_error("failed to finalize key pair (code: " + std::to_string(status) + ")");
    }

    ULONG key_data_size = 0;
    status = BCryptExportKey(key_handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, nullptr, 0, &key_data_size, 0);
    if (status < 0) {
        throw std::runtime_error("failed to get generated key size (code: " + std::to_string(status) + ")");
    }

    auto blob = (BCRYPT_RSAKEY_BLOB*)malloc(key_data_size);
    if (blob == nullptr) {
        throw std::runtime_error("failed to allocate memory for rsa key buffer");
    }

    status = BCryptExportKey(key_handle, nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, (PUCHAR)blob, key_data_size, &key_data_size, 0);
    if (status < 0) {
        free(blob);
        throw std::runtime_error("failed to export key pair (code: " + std::to_string(status) + ")");
    }

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

    free(blob);

    status = BCryptDestroyKey(key_handle);
    if (status < 0) {
        throw std::runtime_error("failed to destroy key pair (code: " + std::to_string(status) + ")");
    }

    status = BCryptCloseAlgorithmProvider(alg_handle, 0);
    if (status < 0) {
        throw std::runtime_error("failed to close algorithm provider (code: " + std::to_string(status) + ")");
    }

    return std::move(ret);
}

HRESULT add_rsa_keypair(CK_OBJECT_HANDLE* pubkey_handle, CK_OBJECT_HANDLE* privkey_handle, CK_SESSION_HANDLE session_handle = g_session) {
    std::cout << "generate RSA key: ";
    auto key = generate_rsa_key();
    std::cout << "success" << std::endl;

    CK_UTF8CHAR pubkey_label[] = "test rsa publickey object";
    CK_KEY_TYPE key_type = CKK_RSA;

    CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;

    CK_ATTRIBUTE pubkey_template[] = {
        {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
        {CKA_TOKEN, &bbool_true, sizeof(bbool_true)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ENCRYPT, &bbool_true, sizeof(bbool_true)},
        {CKA_LABEL, pubkey_label, sizeof(pubkey_label) - 1},
        {CKA_MODULUS, key->modulus.data(), key->modulus.size()},
        {CKA_PUBLIC_EXPONENT, key->public_exponent.data(), key->public_exponent.size()},
        {CKA_ID, object_id, sizeof(object_id)}
    };

    auto result = g_func_list->C_CreateObject(session_handle, pubkey_template, sizeof(pubkey_template) / sizeof(pubkey_template[0]), pubkey_handle);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to create public key object", result));
    }

    CK_UTF8CHAR privkey_label[] = "test rsa privatekey object";
    CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;

    CK_ATTRIBUTE privkey_template[] = {
        {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
        {CKA_TOKEN, &bbool_true, sizeof(bbool_true)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_DECRYPT, &bbool_true, sizeof(bbool_true)},
        {CKA_SENSITIVE, &bbool_true, sizeof(bbool_true)},
        {CKA_LABEL, privkey_label, sizeof(privkey_label) - 1},
        {CKA_MODULUS, key->modulus.data(), key->modulus.size()},
        {CKA_PUBLIC_EXPONENT, key->public_exponent.data(), key->public_exponent.size()},
        {CKA_PRIVATE_EXPONENT, key->private_exponent.data(), key->private_exponent.size()},
        {CKA_PRIME_1, key->prime1.data(), key->prime1.size()},
        {CKA_PRIME_2, key->prime2.data(), key->prime2.size()},
        {CKA_EXPONENT_1, key->exponent1.data(), key->exponent1.size()},
        {CKA_EXPONENT_2, key->exponent2.data(), key->exponent2.size()},
        {CKA_COEFFICIENT, key->coefficient.data(), key->coefficient.size()},
        {CKA_ID, object_id, sizeof(object_id)}
    };

    result = g_func_list->C_CreateObject(session_handle, privkey_template, sizeof(privkey_template) / sizeof(privkey_template[0]), privkey_handle);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to create private key object", result));
    }

    return result;
}

std::unique_ptr<aes_cipher_struct> encrypt(CK_MECHANISM* mechanism, CK_OBJECT_HANDLE* publickey, std::vector<uint8_t> message, CK_SESSION_HANDLE session_handle = g_session) {
    auto aes_key = generate_random_data(AES_KEY_LEN);

    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    DWORD data = 0, key_object_size = 0, iv_block_size = 0, key_blob_size = 0, cipher_data_size = 0;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT auth_tag_length{};
    auto aes_cipher = std::make_unique<struct aes_cipher_struct>();

    std::cout << "encrypt random string with AES: ";

    auto status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) {
        throw std::runtime_error("failed to open algorithm provider (code: " + std::to_string(status) + ")");
    }

    status = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) {
        throw std::runtime_error("failed to get set chaining mode (code: " + std::to_string(status) + ")");
    }

    status = BCryptGetProperty(alg_handle, BCRYPT_AUTH_TAG_LENGTH, (PBYTE)&auth_tag_length, sizeof(auth_tag_length), &data, 0);
    if (status < 0) {
        throw std::runtime_error("failed to get auth tag size (code: " + std::to_string(status) + ")");
    }

    status = BCryptGetProperty(alg_handle, BCRYPT_BLOCK_LENGTH, (PBYTE)&iv_block_size, sizeof(DWORD), &data, 0);
    if (status < 0) {
        throw std::runtime_error("failed to get iv block size (code: " + std::to_string(status) + ")");
    }

    status = BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, aes_key.data(), aes_key.size(), 0);
    if (status < 0) {
        throw std::runtime_error("failed to generate symmetric key (code: " + std::to_string(status) + ")");
    }

    auto aes_nonce = generate_random_data(AES_NONCE_LEN);

    auto iv_buffer = std::vector<uint8_t>(iv_block_size);
    auto aes_iv = generate_random_data(iv_block_size);
    std::copy(aes_iv.begin(), aes_iv.end(), iv_buffer.begin());

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    auto auth_tag = std::vector<uint8_t>(auth_tag_length.dwMinLength);
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = aes_nonce.data();
    auth_info.cbNonce = aes_nonce.size();
    auth_info.pbTag = auth_tag.data();
    auth_info.cbTag = auth_tag.size();

    status = BCryptEncrypt(key_handle, message.data(), message.size(), &auth_info, iv_buffer.data(), iv_buffer.size(), nullptr, 0, &cipher_data_size, 0);
    if (status < 0) {
        throw std::runtime_error("failed to get cipher size (code: " + std::to_string(status) + ")");
    }

    std::copy(aes_iv.begin(), aes_iv.end(), iv_buffer.begin());

    auto cipher_data = std::vector<uint8_t>(cipher_data_size);
    status = BCryptEncrypt(key_handle, message.data(), message.size(), &auth_info, iv_buffer.data(), iv_buffer.size(), cipher_data.data(), cipher_data_size, &data, 0);
    if (status < 0) {
        throw std::runtime_error("failed to encrypt data by aes (code: " + std::to_string(status) + ")");
    }

    status = BCryptDestroyKey(key_handle);
    if (status < 0) {
        throw std::runtime_error("failed to destroy aes key (code: " + std::to_string(status) + ")");
    }

    status = BCryptCloseAlgorithmProvider(alg_handle, 0);
    if (status < 0) {
        throw std::runtime_error("failed to close algorithm provider (code: " + std::to_string(status) + ")");
    }

    //aes_key.insert(aes_key.end(), aes_iv.begin(), aes_iv.end());

    std::cout << "success" << std::endl;
    std::cout << "encrypt AES key with RSA: ";

    auto result = g_func_list->C_EncryptInit(g_session, mechanism, *publickey);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to initialize encrypt operation", result));
    }

    CK_ULONG encrypted_data_len = 0;
    result = g_func_list->C_Encrypt(g_session, aes_key.data(), aes_key.size(), nullptr, &encrypted_data_len);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to get size of encrypted data", result));
    }

    auto encrypted_aes_key = std::vector<uint8_t>(encrypted_data_len);
    result = g_func_list->C_Encrypt(g_session, aes_key.data(), aes_key.size(), encrypted_aes_key.data(), &encrypted_data_len);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to encrypt data", result));
    }

    aes_cipher->cipher_data = cipher_data;
    aes_cipher->encrypted_aes_key = encrypted_aes_key;
    aes_cipher->iv = aes_iv;
    aes_cipher->tag = std::vector<uint8_t>(auth_info.cbTag);
    memcpy(aes_cipher->tag.data(), auth_info.pbTag, auth_info.cbTag);
    aes_cipher->nonce = aes_nonce;

    //cipher_data.reserve(cipher_data.size() + encrypted_data_len);
    //cipher_data.insert(cipher_data.end(), encrypted_aes_key.begin(), encrypted_aes_key.end());

    std::cout << "success" << std::endl;

    return std::move(aes_cipher);
}

std::vector<uint8_t> decrypt(CK_MECHANISM* mechanism, CK_OBJECT_HANDLE* privatekey, std::unique_ptr<aes_cipher_struct> encrypted, CK_SESSION_HANDLE session_handle = g_session) {
    /*std::cout << "encrypted random string: ";
    print_hex_vector(encrypted);

    std::cout << "encrypted AES key and IV: ";
    print_hex_vector(encrypted_aes_key_and_iv);*/

    std::cout << "decrypt AES key with RSA: ";

    auto result = g_func_list->C_DecryptInit(g_session, mechanism, *privatekey);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to initialize decrypt operetion", result));
    }

    CK_ULONG decrypted_data_len = 0;
    result = g_func_list->C_Decrypt(g_session, encrypted->encrypted_aes_key.data(), encrypted->encrypted_aes_key.size(), nullptr, &decrypted_data_len);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to get size of decrypted data", result));
    }

    auto decrypted_aes_key = std::vector<uint8_t>(decrypted_data_len);

    result = g_func_list->C_Decrypt(g_session, encrypted->encrypted_aes_key.data(), encrypted->encrypted_aes_key.size(),
        decrypted_aes_key.data(), &decrypted_data_len);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to decrypt AES key", result));
    }

    /*std::cout << "decrypted AES key: ";
    print_hex_vector(aes_key);

    std::cout << "decrypted AES IV: ";
    print_hex_vector(aes_iv);*/

    //decrypted_aes_key_and_iv.clear();

    std::cout << "success" << std::endl;

    std::cout << "decrypt random string with AES: ";

    BCRYPT_ALG_HANDLE alg_handle = nullptr;
    BCRYPT_KEY_HANDLE key_handle = nullptr;
    DWORD data = 0, key_object_size = 0;

    auto status = BCryptOpenAlgorithmProvider(&alg_handle, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (status < 0) {
        throw std::runtime_error("failed to open algorithm provider (code: " + std::to_string(status) + ")");
    }

    status = BCryptSetProperty(alg_handle, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) {
        throw std::runtime_error("failed to get set chaining mode (code: " + std::to_string(status) + ")");
    }

    status = BCryptGenerateSymmetricKey(alg_handle, &key_handle, nullptr, 0, decrypted_aes_key.data(), decrypted_aes_key.size(), 0);
    if (status < 0) {
        throw std::runtime_error("failed to generate symmetric key (code: " + std::to_string(status) + ")");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info{};
    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = encrypted->nonce.data();
    auth_info.cbNonce = encrypted->nonce.size();
    auth_info.pbTag = encrypted->tag.data();
    auth_info.cbTag = encrypted->tag.size();

    auto iv_buffer = std::vector<uint8_t>(encrypted->iv.size());
    std::copy(encrypted->iv.begin(), encrypted->iv.end(), iv_buffer.begin());

    status = BCryptDecrypt(key_handle, encrypted->cipher_data.data(), encrypted->cipher_data.size(), &auth_info, iv_buffer.data(), iv_buffer.size(),
        nullptr, 0, &decrypted_data_len, 0);
    if (status < 0) {
        throw std::runtime_error("failed to get decrypted data size (code: " + std::to_string(status) + ")");
    }

    std::copy(encrypted->iv.begin(), encrypted->iv.end(), iv_buffer.begin());

    auto ret = std::vector<uint8_t>(decrypted_data_len);
    status = BCryptDecrypt(key_handle, encrypted->cipher_data.data(), encrypted->cipher_data.size(), &auth_info, iv_buffer.data(), iv_buffer.size(),
        ret.data(), ret.size(), &decrypted_data_len, 0);
    if (status < 0) {
        throw std::runtime_error("failed to decrypt data (code: " + std::to_string(status) + ")");
    }

    status = BCryptDestroyKey(key_handle);
    if (status < 0) {
        throw std::runtime_error("failed to destroy aes key (code: " + std::to_string(status) + ")");
    }

    status = BCryptCloseAlgorithmProvider(alg_handle, 0);
    if (status < 0) {
        throw std::runtime_error("failed to close algorithm provider (code: " + std::to_string(status) + ")");
    }

    std::cout << "success" << std::endl;

    return ret;
}

HRESULT close_session(CK_SESSION_HANDLE session_handle = g_session) {
    auto result = g_func_list->C_CloseSession(g_session);
    if (result != CKR_OK) {
        throw std::runtime_error(error_message("failed to close session", result));
    }
    return result;
}

int main(int argc, char** argv)
{
    HMODULE pkcs11_module = nullptr;
    std::string random_str = "";
    int ret = EXIT_FAILURE;

    auto module_loaded = false;
    auto token_initialized = false;
    auto session_created = false;

    try {
        pkcs11_module = load_module();
        module_loaded = true;

        g_func_list = get_func_list(pkcs11_module);

        initialize();
        token_initialized = true;

        auto slot_id_list = get_slot_id_list();

        open_session(slot_id_list[0]);
        session_created = true;

        random_str = generate_random_string(RANDOM_STRING_LEN);
        std::cout << "generated string: " << random_str << std::endl;

        login();

        CK_OBJECT_HANDLE pubkey_handle, privkey_handle;
        CK_MECHANISM mechanism = { CKM_RSA_PKCS, nullptr, 0 };

        add_rsa_keypair(&pubkey_handle, &privkey_handle);
        // find_rsa_keypair(&pubkey_handle, &privkey_handle);

        auto vectorized_random_str = std::vector<uint8_t>(random_str.begin(), random_str.end());
        auto encrypted_data = encrypt(&mechanism, &pubkey_handle, vectorized_random_str);

        auto decrypted_data = decrypt(&mechanism, &privkey_handle, std::move(encrypted_data));
        auto decrypted_str = std::string(decrypted_data.begin(), decrypted_data.end());
        std::cout << "decrypted string: " << decrypted_str << std::endl;

        if (!strcmp(random_str.c_str(), decrypted_str.c_str())) {
            std::cout << "encryption and decryption succeeded" << std::endl;
        }
        else {
            std::cout << "encryption and decryption failed" << std::endl;
        }

        ret = EXIT_SUCCESS;
    }
    catch (std::exception e) {
        std::cerr << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }

    if (session_created) {
        close_session();
    }
    if (token_initialized) {
        g_func_list->C_Finalize(nullptr);
    }
    if (module_loaded) {
        if (!FreeLibrary(pkcs11_module)) {
            std::cerr << "failed to unload module" << std::endl;
        }
    }

    return ret;
}
