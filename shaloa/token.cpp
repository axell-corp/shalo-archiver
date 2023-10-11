#include "pch.h"
#include "windows-crypt.h"
#include "exceptions.h"
#include "token.h"
#include <boost/scope_exit.hpp>

Token::Token(HMODULE module_handle) : _module(module_handle)
{
    try {
        load_func_list("C_GetFunctionList");
        initialize_token();
        get_slot_id_list_from_token();
    }
    catch (std::exception e) {
        if (_is_token_initialized) {
            finalize_token();
        }
        throw;
    }
}

Token::~Token()
{
    if (_is_session_opened) {
        close_session();
    }
    if (_is_token_initialized) {
        finalize_token();
    }
}

void Token::open_session(int slot_id_num)
{
    std::string error_str = "セッションの確立に失敗しました";

    if (slot_id_num >= _slot_id_list.size()) {
        throw TokenException("スロット ID の値が大きすぎます", error_str);
    }

    CK_ULONG slot_id = _slot_id_list[slot_id_num];
    CK_TOKEN_INFO token_info{};
    auto result = _func_list->C_GetTokenInfo(slot_id, &token_info);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    if (!(token_info.flags & CKF_USER_PIN_INITIALIZED)) {
        throw TokenException("User PIN がまだ設定されていません", error_str);
    }

    result = _func_list->C_OpenSession(slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &_session);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    _is_session_opened = true;
}

std::vector<CK_SLOT_ID> Token::get_slot_id_list() const
{
    return _slot_id_list;
}

void Token::login(std::string pin) const
{
    std::string error_str = "ログインに失敗しました";

    auto result = _func_list->C_Login(_session, CKU_USER, (unsigned char*)pin.c_str(), pin.size());
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }
}

std::vector<uint8_t> Token::generate_random_data(CK_ULONG size) const
{
    std::string error_str = "乱数の生成に失敗しました";

    if (!_is_session_opened) {
        throw TokenException("セッションがまだ確立されていません", error_str);
    }
    auto ret = std::vector<uint8_t>(size);
    auto result = _func_list->C_GenerateRandom(_session, ret.data(), size);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    return ret;
}

std::unique_ptr<token_encrypted> Token::encrypt(const std::vector<uint8_t>& raw_vec, int pubkey_id)
{
    std::string error_str = "トークンによる暗号化に失敗しました";

    CK_OBJECT_HANDLE pubkey_handle = 0;
    try {
        pubkey_handle = find_object_by_key_id(pubkey_id, CKO_PUBLIC_KEY);
    }
    catch (...) {
        throw;
    }

    auto result = _func_list->C_EncryptInit(_session, const_cast<CK_MECHANISM_PTR>(&_mechanism), pubkey_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    CK_ULONG encrypted_data_len = 0;
    result = _func_list->C_Encrypt(_session, const_cast<CK_BYTE_PTR>(raw_vec.data()), raw_vec.size(), nullptr, &encrypted_data_len);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    auto ret = std::make_unique<token_encrypted>();
    ret->encrypted_data.resize(encrypted_data_len);

    result = _func_list->C_Encrypt(_session, const_cast<CK_BYTE_PTR>(raw_vec.data()), raw_vec.size(), ret->encrypted_data.data(), &encrypted_data_len);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    try {
        ret->pubkey_modulus_hash = get_modulus_hash_by_key_handle(pubkey_handle);
    }
    catch (...) {
        throw;
    }

    return ret;
}

std::vector<uint8_t> Token::decrypt(const std::vector<uint8_t>& encrypted_vec, const std::vector<uint8_t>& privkey_modulus_hash)
{
    std::string error_str = "トークンによる復号に失敗しました";

    CK_OBJECT_HANDLE privkey_handle = 0;
    try {
        privkey_handle = find_rsa_key_by_modulus_hash(privkey_modulus_hash, CKO_PRIVATE_KEY);
    }
    catch (...) {
        throw;
    }

    auto result = _func_list->C_DecryptInit(_session, const_cast<CK_MECHANISM_PTR>(&_mechanism), privkey_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    CK_ULONG decrypted_data_len = 0;
    result = _func_list->C_Decrypt(_session, const_cast<CK_BYTE_PTR>(encrypted_vec.data()), encrypted_vec.size(), nullptr, &decrypted_data_len);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    std::vector<uint8_t> ret(decrypted_data_len);
    result = _func_list->C_Decrypt(_session, const_cast<CK_BYTE_PTR>(encrypted_vec.data()), encrypted_vec.size(), ret.data(), &decrypted_data_len);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    return ret;
}

void Token::add_rsa_keypair(const std::shared_ptr<rsa_key> key, int slot_id, const char* subject, std::optional<CK_DATE> end_date) {
    std::string error_str = "RSA 鍵の追加に失敗しました";

    CK_UTF8CHAR* key_label = (CK_UTF8CHAR*)subject;
    size_t key_label_size = strlen(subject);
    CK_KEY_TYPE key_type = CKK_RSA;
    CK_BBOOL bbool_true = CK_TRUE;
    CK_OBJECT_CLASS pubkey_class = CKO_PUBLIC_KEY;

    CK_OBJECT_HANDLE pubkey_handle;
    CK_OBJECT_HANDLE privkey_handle;

    CK_BYTE object_id[11];
    memcpy(object_id, _default_rsa_key_id, 11);

    if (2 <= slot_id && slot_id <= 4) {
        object_id[10] = slot_id + '0';
    }
    else if (slot_id != 1) {
        throw OtherException(SHALOA_RESULT_ERROR_INVALID_ARGUMENT, "スロット ID は 1~4 である必要があります");
    }

    std::vector<CK_ATTRIBUTE> pubkey_template({
        {CKA_CLASS, &pubkey_class, sizeof(pubkey_class)},
        {CKA_TOKEN, &bbool_true, sizeof(bbool_true)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_ENCRYPT, &bbool_true, sizeof(bbool_true)},
        {CKA_LABEL, key_label, (CK_ULONG)key_label_size},
        {CKA_MODULUS, key->modulus.data(), (CK_ULONG)key->modulus.size()},
        {CKA_PUBLIC_EXPONENT, key->public_exponent.data(), (CK_ULONG)key->public_exponent.size()},
        {CKA_ID, object_id, sizeof(object_id)},
    });

    if (end_date) {
        pubkey_template.push_back({ CKA_END_DATE, &end_date.value(), sizeof(end_date.value())});
    }

    auto result = _func_list->C_CreateObject(_session, pubkey_template.data(), pubkey_template.size(), &pubkey_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    CK_OBJECT_CLASS privkey_class = CKO_PRIVATE_KEY;

    std::vector<CK_ATTRIBUTE> privkey_template = {
        {CKA_CLASS, &privkey_class, sizeof(privkey_class)},
        {CKA_TOKEN, &bbool_true, sizeof(bbool_true)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_DECRYPT, &bbool_true, sizeof(bbool_true)},
        {CKA_SENSITIVE, &bbool_true, sizeof(bbool_true)},
        {CKA_LABEL, key_label, (CK_ULONG)key_label_size},
        {CKA_MODULUS, key->modulus.data(), (CK_ULONG)key->modulus.size()},
        {CKA_PUBLIC_EXPONENT, key->public_exponent.data(), (CK_ULONG)key->public_exponent.size()},
        {CKA_PRIVATE_EXPONENT, key->private_exponent.data(), (CK_ULONG)key->private_exponent.size()},
        {CKA_PRIME_1, key->prime1.data(), (CK_ULONG)key->prime1.size()},
        {CKA_PRIME_2, key->prime2.data(), (CK_ULONG)key->prime2.size()},
        {CKA_EXPONENT_1, key->exponent1.data(), (CK_ULONG)key->exponent1.size()},
        {CKA_EXPONENT_2, key->exponent2.data(), (CK_ULONG)key->exponent2.size()},
        {CKA_COEFFICIENT, key->coefficient.data(), (CK_ULONG)key->coefficient.size()},
        {CKA_ID, object_id, sizeof(object_id)}
    };

    if (end_date) {
        privkey_template.push_back({ CKA_END_DATE, &end_date.value(), sizeof(end_date.value()) });
    }

    result = _func_list->C_CreateObject(_session, privkey_template.data(), privkey_template.size(), &privkey_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }
}

void Token::add_certificate(const std::vector<uint8_t>& cert_value, int slot_id, const char* subject) {
    std::string error_str = "証明書の追加に失敗しました";

    CK_OBJECT_CLASS cert_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert_type = CKC_X_509;
    CK_BBOOL bbool_true = CK_TRUE;
    CK_UTF8CHAR* cert_label = (CK_UTF8CHAR*)subject;
    size_t cert_label_size = strlen(subject);

    CK_BYTE object_id[11];
    memcpy(object_id, _default_rsa_key_id, 11);

    if (2 <= slot_id && slot_id <= 4) {
        object_id[10] = slot_id + '0';
    }
    else if (slot_id != 1) {
        throw OtherException(SHALOA_RESULT_ERROR_INVALID_ARGUMENT, "スロット ID は 1~4 の範囲である必要があります");
    }

    CK_OBJECT_HANDLE cert_handle;
    
    std::vector<CK_ATTRIBUTE> cert_template = {
        {CKA_CLASS, &cert_class, sizeof(cert_class)},
        {CKA_CERTIFICATE_TYPE, &cert_type, sizeof(cert_type)},
        {CKA_TOKEN, &bbool_true, sizeof(bbool_true)},
        {CKA_LABEL, cert_label, (CK_ULONG)cert_label_size},
        {CKA_VALUE, const_cast<uint8_t *>(cert_value.data()), (CK_ULONG)cert_value.size()},
        {CKA_ID, object_id, sizeof(object_id)},
    };

    auto result = _func_list->C_CreateObject(_session, cert_template.data(), cert_template.size(), &cert_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }
}

void Token::delete_rsa_keypair_and_certificate(int slot_id)
{
    std::string error_str = "RSA 鍵の削除に失敗しました";

    auto pubkey_handle = find_object_by_key_id(slot_id, CKO_PUBLIC_KEY);
    auto result = _func_list->C_DestroyObject(_session, pubkey_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    auto privkey_handle = find_object_by_key_id(slot_id, CKO_PRIVATE_KEY);
    result = _func_list->C_DestroyObject(_session, privkey_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    auto cert_handle = find_object_by_key_id(slot_id, CKO_CERTIFICATE);
    result = _func_list->C_DestroyObject(_session, cert_handle);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }
}

std::vector<uint8_t> Token::export_certificate(int slot_id)
{
    std::string error_str = "証明書のエクスポートに失敗しました。";
    
    auto cert_handle = find_object_by_key_id(slot_id, CKO_CERTIFICATE);

    CK_ATTRIBUTE search_template[] = {
    {CKA_VALUE, nullptr, 0}
    };

    auto result = _func_list->C_GetAttributeValue(_session, cert_handle, search_template, 1);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    std::vector<uint8_t> ret(search_template[0].ulValueLen);
    search_template[0].pValue = ret.data();

    result = _func_list->C_GetAttributeValue(_session, cert_handle, search_template, 1);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }
    
    return ret;
}

void Token::load_func_list(std::string func_name)
{
    std::string error_str = "関数の読み込みに失敗しました";

    auto func = (CK_C_GetFunctionList)GetProcAddress(_module, func_name.c_str());

    if (func == nullptr) {
        throw OsException(SHALOA_RESULT_ERROR_READ_FUNCTION_LIST, error_str);
    }

    CK_FUNCTION_LIST* list = nullptr;

    auto result = func(&list);
    
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    _func_list = list;
}

void Token::initialize_token()
{
    auto result = _func_list->C_Initialize(nullptr);
    if (result != CKR_OK) {
        throw TokenException(result, "トークンの初期化に失敗しました");
    }
}

void Token::get_slot_id_list_from_token() {
    std::string error_str = "トークンからのスロット ID 情報の読み込みに失敗しました";

    CK_ULONG slot_count = 0;
    auto result = _func_list->C_GetSlotList(CK_TRUE, nullptr, &slot_count);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    _slot_id_list.resize(slot_count);

    result = _func_list->C_GetSlotList(CK_TRUE, _slot_id_list.data(), &slot_count);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);

    }
}

std::vector<uint8_t> Token::get_modulus_hash_by_key_handle(CK_OBJECT_HANDLE key_handle)
{
    std::string error_str = "modulus hash の取得に失敗しました";

    CK_ATTRIBUTE search_template[] = {
    {CKA_MODULUS, nullptr, 0}
    };

    auto result = _func_list->C_GetAttributeValue(_session, key_handle, search_template, 1);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    std::vector<uint8_t> modulus(search_template[0].ulValueLen);
    search_template[0].pValue = modulus.data();

    result = _func_list->C_GetAttributeValue(_session, key_handle, search_template, 1);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    auto ret = cng_sha256(modulus);

    return ret;
}

CK_OBJECT_HANDLE Token::find_object_by_key_id(int key_id, CK_OBJECT_CLASS object_class)
{
    std::string error_str = "オブジェクトの検索に失敗しました";
    if (0 >= key_id || key_id >= 5) {
        throw OtherException(SHALOA_RESULT_ERROR_INVALID_ARGUMENT, "鍵 ID が不正です");
    }

    _default_rsa_key_id[10] = key_id + '0';
    //CK_OBJECT_CLASS object_class = CKO_PUBLIC_KEY;

    CK_ATTRIBUTE attribute[] = {
        {CKA_ID, _default_rsa_key_id, sizeof(_default_rsa_key_id)},
        {CKA_CLASS, &object_class, sizeof(object_class)}
    };

    auto result = _func_list->C_FindObjectsInit(_session, attribute, 2);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    BOOST_SCOPE_EXIT_ALL(this) {
        this->_func_list->C_FindObjectsFinal(this->_session);
    };

    CK_OBJECT_HANDLE ret = CK_INVALID_HANDLE;
    CK_ULONG object_count = 0;

    result = _func_list->C_FindObjects(_session, &ret, 1, &object_count);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    if (object_count == 0) {
        throw OtherException(SHALOA_RESULT_ERROR_KEY_NOT_FOUND, "指定の ID を持つオブジェクトが見つかりません");
    }

    return ret;
}

CK_OBJECT_HANDLE Token::find_rsa_key_by_modulus_hash(const std::vector<uint8_t>& modulus_hash, CK_OBJECT_CLASS object_class)
{
    std::string error_str = "RSA 鍵の検索に失敗しました";

    CK_ATTRIBUTE attribute[] = {
        {CKA_CLASS, &object_class, sizeof(object_class)}
    };

    auto result = _func_list->C_FindObjectsInit(_session, attribute, 1);
    CK_OBJECT_HANDLE ret = CK_INVALID_HANDLE;
    CK_ULONG object_count = 0;

    BOOST_SCOPE_EXIT_ALL(this) {
        this->_func_list->C_FindObjectsFinal(this->_session);
    };

    for (;;) {
        result = _func_list->C_FindObjects(_session, &ret, 1, &object_count);
        if (result != CKR_OK) {
            throw TokenException(result, error_str);
        }
        else if (object_count == 0) {
            throw OtherException(SHALOA_RESULT_ERROR_KEY_NOT_FOUND, "暗号化されたファイルに対応する RSA 鍵が見つかりません");
        }

        std::vector<uint8_t> searched_modulus_hash(modulus_hash.size());
        try {
           searched_modulus_hash = get_modulus_hash_by_key_handle(ret);
        }
        catch (...) {
            throw;
        }

        if (searched_modulus_hash == modulus_hash) {
            return ret;
        }
    }
}

int Token::find_key_id_from_modulus_hash(const std::vector<uint8_t> &modulus_hash) {
    std::string error_str = "鍵 ID の検索に失敗しました";

    CK_OBJECT_CLASS object_class = CKO_PUBLIC_KEY;
    CK_OBJECT_HANDLE key_handle = CK_INVALID_HANDLE;

    try {
        key_handle = find_rsa_key_by_modulus_hash(modulus_hash, object_class);
    } catch (...) {
        throw;
    }

    CK_ATTRIBUTE subject_search_attribute[] = {
        {CKA_ID, nullptr, 0}
    };

    auto result = _func_list->C_GetAttributeValue(_session, key_handle, subject_search_attribute, 1);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }

    std::vector<uint8_t> subject(subject_search_attribute[0].ulValueLen);
    subject_search_attribute[0].pValue = subject.data();

    result = _func_list->C_GetAttributeValue(_session, key_handle, subject_search_attribute, 1);
    if (result != CKR_OK) {
        throw TokenException(result, error_str);
    }
    
    char id = subject[subject.size() - 1] - '0';

    return id;
}

inline void Token::close_session()
{
    auto result = _func_list->C_CloseSession(_session);
}

inline void Token::finalize_token()
{
    auto result = _func_list->C_Finalize(nullptr);
}
