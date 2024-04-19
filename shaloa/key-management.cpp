#include "pch.h"
#include "key-management.h"
#include "windows-crypt.h"
#include "exceptions.h"
#include "module.h"
#include "token.h"
#include "pem.h"
#include <fstream>
#include <wincrypt.h>
#include <regex>
#include <chrono>
#include <boost/scope_exit.hpp>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "cryptlib.lib")
#pragma comment(lib, "Ncrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern std::string last_error_message;

constexpr int RSA_KEY_SIZE = 0x1000;

class PemKey {
public:
    PemKey() {
        BCRYPT_RSAKEY_BLOB* generated_key;
        try {
            generated_key = cng_generate_rsa_key_blob();
            this->key_blob = generated_key;
        }
        catch (std::exception& e) {
            throw;
        }
    }

    PemKey(std::vector<CHAR>& key_string) {
        std::string error_message = "鍵情報のデコードに失敗しました";

        /*DWORD binary_key_size = 0;
        auto result = CryptStringToBinaryA(key_string.data(), 0, CRYPT_STRING_BASE64HEADER, nullptr, &binary_key_size, nullptr, nullptr);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        auto binary_key = std::vector<BYTE>(binary_key_size);
        result = CryptStringToBinaryA(key_string.data(), 0, CRYPT_STRING_BASE64HEADER, binary_key.data(), &binary_key_size, nullptr, nullptr);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        DWORD decoded_size = 0;
        BCRYPT_RSAKEY_BLOB* decoded_key = nullptr;
        result = CryptDecodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, binary_key.data(), binary_key.size(), CRYPT_DECODE_ALLOC_FLAG, nullptr,
            &decoded_key, &decoded_size);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }*/
        CryptoPP::RSA::PrivateKey private_key;
        auto s = std::string(key_string.begin(), key_string.end());
        auto key_string_source = CryptoPP::StringSource(s, true);

        try {
            CryptoPP::PEM_Load(key_string_source, private_key);
        }
        catch (...) {
            throw;
        }

        auto decoded_key = std::make_shared<rsa_key>();

        // メモリ割り当て
        decoded_key->public_exponent.resize(private_key.GetPublicExponent().MinEncodedSize());
        decoded_key->private_exponent.resize(private_key.GetPrivateExponent().MinEncodedSize());
        decoded_key->modulus.resize(private_key.GetModulus().MinEncodedSize());
        decoded_key->prime1.resize(private_key.GetPrime1().MinEncodedSize());
        decoded_key->prime2.resize(private_key.GetPrime2().MinEncodedSize());
        decoded_key->exponent1.resize(private_key.GetModPrime1PrivateExponent().MinEncodedSize());
        decoded_key->exponent2.resize(private_key.GetModPrime2PrivateExponent().MinEncodedSize());
        decoded_key->coefficient.resize(private_key.GetMultiplicativeInverseOfPrime2ModPrime1().MinEncodedSize());

        // vector に変換
        private_key.GetPublicExponent().Encode(decoded_key->public_exponent.data(), decoded_key->public_exponent.capacity());
        private_key.GetPrivateExponent().Encode(decoded_key->private_exponent.data(), decoded_key->private_exponent.capacity());
        private_key.GetModulus().Encode(decoded_key->modulus.data(), decoded_key->modulus.capacity());
        private_key.GetPrime1().Encode(decoded_key->prime1.data(), decoded_key->prime1.capacity());
        private_key.GetPrime2().Encode(decoded_key->prime2.data(), decoded_key->prime2.capacity());
        private_key.GetModPrime1PrivateExponent().Encode(decoded_key->exponent1.data(), decoded_key->exponent1.capacity());
        private_key.GetModPrime2PrivateExponent().Encode(decoded_key->exponent2.data(), decoded_key->exponent2.capacity());
        private_key.GetMultiplicativeInverseOfPrime2ModPrime1().Encode(decoded_key->coefficient.data(), decoded_key->coefficient.capacity());

        this->key_struct = decoded_key;

        // BCRYPT_RSAKEY_BLOB を構築
        auto entire_key_size = RSA_KEY_SIZE;
        auto blob = (BCRYPT_RSAKEY_BLOB*)LocalAlloc(LPTR, sizeof(BCRYPT_RSAKEY_BLOB) + entire_key_size);
        // todo: null check

        blob->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
        blob->BitLength = entire_key_size;
        blob->cbModulus = key_struct->modulus.size();
        blob->cbPublicExp = key_struct->public_exponent.size();
        blob->cbPrime1 = key_struct->prime1.size();
        blob->cbPrime2 = key_struct->prime2.size();

        char* ptr = (char*)blob + sizeof(BCRYPT_RSAKEY_BLOB);
        copy_vec_to_ptr(ptr, key_struct->public_exponent);
        ptr += blob->cbPublicExp;
        copy_vec_to_ptr(ptr, key_struct->modulus);
        ptr += blob->cbModulus;
        copy_vec_to_ptr(ptr, key_struct->prime1);
        ptr += blob->cbPrime1;
        copy_vec_to_ptr(ptr, key_struct->prime2);
        ptr += blob->cbPrime2;

        copy_vec_to_ptr(ptr, key_struct->exponent1);
        ptr += blob->cbPrime1;
        copy_vec_to_ptr(ptr, key_struct->exponent2);
        ptr += blob->cbPrime2;
        copy_vec_to_ptr(ptr, key_struct->coefficient);
        ptr += blob->cbPrime1;
        copy_vec_to_ptr(ptr, key_struct->private_exponent);

        this->key_blob = blob;
    }

    ~PemKey() {
        if (key_blob != nullptr)
        {
            LocalFree(key_blob);
        }
    }

    std::vector<CHAR> get_string() {
        // 以前に変換したことがあればそれを返す
        if (key_string.size() > 0) {
            return key_string;
        }

        std::string error_message = "鍵の情報を ASN.1 フォーマットにエンコードできませんでした";

        DWORD encoded_size = 0;
        PUCHAR encoded = nullptr;
        auto result = CryptEncodeObjectEx(X509_ASN_ENCODING, CNG_RSA_PRIVATE_KEY_BLOB, key_blob, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &encoded, &encoded_size);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        DWORD stringified_size = 0;
        result = CryptBinaryToStringA(encoded, encoded_size, CRYPT_STRING_BASE64, nullptr, &stringified_size);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        auto key_string = std::vector<CHAR>(stringified_size);
        result = CryptBinaryToStringA(encoded, encoded_size, CRYPT_STRING_BASE64, key_string.data(), &stringified_size);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        std::string header = "-----BEGIN RSA PRIVATE KEY-----\n";
        std::string footer = "-----END RSA PRIVATE KEY-----\n";

        key_string.insert(key_string.begin(), header.begin(), header.end());

        // 変換された文字列の最後に空白が1個できるのでその分マイナス
        key_string.insert(key_string.end() - 1, footer.begin(), footer.end());
        key_string.pop_back();

        this->key_string = key_string;
        return key_string;
    }

    std::vector<uint8_t> get_certificate(std::string &subject, std::optional<std::chrono::year_month_day> end_date) const {
        //todo
        std::string error_msg = "自己署名証明書の作成に失敗しました";

        // 鍵情報用意
        NCRYPT_PROV_HANDLE provHandle;
        NCRYPT_KEY_HANDLE nkey = 0;
        auto result = NCryptOpenStorageProvider(&provHandle, MS_KEY_STORAGE_PROVIDER, 0);
        if (!NT_SUCCESS(result)) {
            throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, "NCryptOpenStorageProvider()");
        }
        BOOST_SCOPE_EXIT_ALL(&provHandle) {
            NCryptFreeObject(provHandle);
        };

        result = NCryptImportKey(provHandle, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, NULL, &nkey, (PUCHAR)key_blob, key_blob->BitLength, 0);
        if (!NT_SUCCESS(result)) {
            throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, result, "NcryptInportKey()");
        }
        BOOST_SCOPE_EXIT_ALL(&nkey) {
            NCryptDeleteKey(nkey, NCRYPT_SILENT_FLAG);
        };

        // アルゴリズム情報（1,2,840,113549,1,1,11）用意
        auto sign_algo = std::make_unique<CRYPT_ALGORITHM_IDENTIFIER>();
        sign_algo->pszObjId = const_cast<char*>(szOID_RSA_SHA256RSA);
        sign_algo->Parameters.cbData = 0;
        sign_algo->Parameters.pbData = nullptr;

        // 有効期限用意
        SYSTEMTIME system_time = {0};
        if (end_date) {
            system_time = {
                .wYear = (unsigned short)(int)(end_date->year()),
                .wMonth = (unsigned short)((unsigned int)(end_date->month())),
                .wDayOfWeek = (unsigned short)end_date->_Calculate_weekday(),
                .wDay = (unsigned short)(unsigned int)(end_date->day()),
            };
        }
        else {
            GetSystemTime(&system_time);
            system_time.wYear += 1;
        }

        // その他情報用意
        DWORD encoded_size = 0;
        auto sz_str = std::format("CN={}", subject);
        const char* sz_x500 = sz_str.c_str();
        CertStrToNameA(X509_ASN_ENCODING, sz_x500, CERT_X500_NAME_STR, nullptr, nullptr, &encoded_size, nullptr);
        auto encoded = std::vector<BYTE>(encoded_size);
        CertStrToNameA(X509_ASN_ENCODING, sz_x500, CERT_X500_NAME_STR, nullptr, encoded.data(), &encoded_size, nullptr);

        auto subject_issuer_blob = std::make_unique<CERT_NAME_BLOB>();
        subject_issuer_blob->pbData = encoded.data();
        subject_issuer_blob->cbData = encoded_size;

        auto key_prov_info = std::make_unique<CRYPT_KEY_PROV_INFO>();
        key_prov_info->pwszContainerName = const_cast<wchar_t*>(L"shaloa");
        key_prov_info->pwszProvName = nullptr;
        key_prov_info->dwProvType = PROV_RSA_FULL;
        key_prov_info->dwFlags = CRYPT_MACHINE_KEYSET;
        key_prov_info->cProvParam = 0;
        key_prov_info->rgProvParam = nullptr;
        key_prov_info->dwKeySpec = AT_SIGNATURE;

        // private key で署名
        auto cert_context = CertCreateSelfSignCertificate(nkey, subject_issuer_blob.get(), 0, key_prov_info.get(), sign_algo.get(), 0, &system_time, 0);
        if (cert_context == nullptr) {
            throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_CNG_OPERATION, "CertCreateSelfSignCertificate() の処理に失敗しました");
        }
        BOOST_SCOPE_EXIT_ALL(&cert_context) {
            CertFreeCertificateContext(cert_context);
        };

        // certificate 出力
        auto encoded_cert = std::vector<uint8_t>(cert_context->pbCertEncoded, cert_context->pbCertEncoded + cert_context->cbCertEncoded / sizeof(BYTE));

        return encoded_cert;
    }

    BCRYPT_RSAKEY_BLOB* get_key_blob_ptr() const {
        return key_blob;
    }

    std::shared_ptr<rsa_key> get_key_struct() const {
        return key_struct;
    }

private:
    BCRYPT_RSAKEY_BLOB* key_blob;
    std::shared_ptr<rsa_key> key_struct;
    std::vector<CHAR> key_string;

    void copy_vec_to_ptr(const char* ptr, std::vector<uint8_t>& vec) {
        std::copy(vec.begin(), vec.end(), const_cast<char *>(ptr));
    }
};

void save_file(const std::vector<CHAR>& file, std::filesystem::path file_path) {
    auto ofs = std::ofstream(file_path, std::ios::out | std::ios::binary);
    if (!ofs) {
        throw OtherException(SHALOA_RESULT_ERROR_FILE_IO, "指定された場所に書き込めません");
    }
    ofs.write(file.data(), file.size());
    ofs << std::flush;
}

std::vector<CHAR> load_file(const std::filesystem::path fn) {
    auto ifs = std::ifstream(fn, std::ios::in | std::ios::binary);
    if (!ifs) {
        throw OtherException(SHALOA_RESULT_ERROR_FILE_IO, "指定されたファイルが開けません");
    }

    ifs.seekg(0, std::ios::end);
    size_t size = ifs.tellg();
    ifs.seekg(0);

    auto ret = std::vector<CHAR>(size);
    ifs.read(ret.data(), size);

    return ret;
}

std::chrono::year_month_day parse_date(std::string date_str) {
    std::chrono::year_month_day ymd;
    std::stringstream ss;
    ss << date_str;
    ss >> std::chrono::parse("%Y%m%d", ymd);

    if (!ss) {
        throw OtherException(SHALOA_RESULT_ERROR_INVALID_ARGUMENT, "日付の記法が間違っています");
    }

    return ymd;
}

CK_DATE ymd_to_ck_date(std::chrono::year_month_day &ymd) {
    CK_DATE ret{0};

    std::to_chars((char*)ret.year, (char*)ret.year + 4, (int)ymd.year());
    std::to_chars((char*)ret.month, (char*)ret.month + 2, (unsigned int)ymd.month());
    std::to_chars((char*)ret.day, (char*)ret.day + 2, (unsigned int)ymd.day());

    return ret;
}

int _shaloa_create_key(const std::filesystem::path fn)
{
    int ret = SHALOA_RESULT_ERROR_INTERNAL;

    try {
        auto pem_key = std::make_unique<PemKey>();
        auto key_string = pem_key->get_string();
        save_file(key_string, fn);
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

int _shaloa_import_key(const std::filesystem::path fn, int slot_id, std::string subject, std::string end_date, const char* pin)
{
    int ret = SHALOA_RESULT_ERROR_INTERNAL;

    try {
        auto key_string = load_file(fn);
        auto pem_key = std::make_unique<PemKey>(key_string);

        auto shalo_module = std::make_unique<Module>();
        auto token = std::make_unique<Token>(shalo_module->get_module_pointer());

        token->open_session(0);

        auto key = pem_key->get_key_struct();



        std::optional<CK_DATE> ck_date = std::nullopt;

        std::optional<std::chrono::year_month_day> ymd = std::nullopt;

        if (!end_date.empty()) {
            ymd = parse_date(end_date);
            ck_date = ymd_to_ck_date(ymd.value());
        }

        auto cert = pem_key->get_certificate(subject, ymd);

        token->login(pin);

        token->add_rsa_keypair(key, slot_id, subject.c_str(), ck_date);
        token->add_certificate(cert, slot_id, subject.c_str());

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

int _shaloa_export_key(const std::filesystem::path fn, int slot_id, const char* pin)
{
    int ret = SHALOA_RESULT_ERROR_INTERNAL;

    try {
        auto shalo_module = std::make_unique<Module>();
        auto token = std::make_unique<Token>(shalo_module->get_module_pointer());

        token->open_session(0);

        token->login(pin);

        auto der_cert = token->export_certificate(slot_id);

        std::string error_message = "証明書を PEM フォーマットにエンコードできませんでした";

        DWORD stringified_size = 0;
        auto result = CryptBinaryToStringA(der_cert.data(), der_cert.size(), CRYPT_STRING_BASE64HEADER, nullptr, &stringified_size);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        auto pem_cert = std::vector<CHAR>(stringified_size);
        result = CryptBinaryToStringA(der_cert.data(), der_cert.size(), CRYPT_STRING_BASE64HEADER, pem_cert.data(), &stringified_size);
        if (!result) {
            throw OsException(SHALOA_RESULT_ERROR_CNG_OPERATION, error_message);
        }

        save_file(pem_cert, fn);

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

int _shaloa_delete_key(int key_id, const char* pin)
{
    int ret = SHALOA_RESULT_ERROR_INTERNAL;

    try {
        auto shalo_module = std::make_unique<Module>();
        auto token = std::make_unique<Token>(shalo_module->get_module_pointer());

        token->open_session(0);

        token->login(pin);

        token->delete_rsa_keypair_and_certificate(key_id);

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
