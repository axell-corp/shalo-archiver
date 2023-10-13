#include "pch.h"
#include "shaloa.h"
#include "file-crypt.h"
#include "key-management.h"

std::string last_error_message = "";

template <typename T>
concept Char_or_wchar = std::same_as<T, const char*> || std::same_as<T, const wchar_t*>;

template <Char_or_wchar T>
std::optional<std::filesystem::path> make_path(T fp) {
    try {
        return std::filesystem::path(fp);
    }
    catch (std::exception& e) {
        last_error_message = e.what();
        return std::nullopt;
    }
}

int shaloaEncodeW(const wchar_t* fnInp, const wchar_t* fnOutp, int key_id) {
    auto _fnInp = make_path(fnInp);
    auto _fnOutp = make_path(fnOutp);
    if (!_fnInp || !_fnOutp) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_encode(_fnInp.value(), _fnOutp.value(), key_id);
}

int shaloaEncodeA(const char* fnInp, const char* fnOutp, int key_id) {
    auto _fnInp = make_path(fnInp);
    auto _fnOutp = make_path(fnOutp);
    if (!_fnInp || !_fnOutp) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_encode(_fnInp.value(), _fnOutp.value(), key_id);
}

int shaloaDecodeW(const wchar_t* fnInp, const wchar_t* fnOutp, const char *pin, int *key_id) {
    auto _fnInp = make_path(fnInp);
    auto _fnOutp = make_path(fnOutp);
    if (!_fnInp || !_fnOutp) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_decode(_fnInp.value(), _fnOutp.value(), pin, key_id);
}

int shaloaDecodeA(const char* fnInp, const char* fnOutp, const char* pin, int *key_id) {
    auto _fnInp = make_path(fnInp);
    auto _fnOutp = make_path(fnOutp);
    if (!_fnInp || !_fnOutp) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_decode(_fnInp.value(), _fnOutp.value(), pin, key_id);
}

int shaloaCreateKeyW(const wchar_t* fn)
{
    auto _fn = make_path(fn);
    if (!_fn) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_create_key(_fn.value());
}

int shaloaCreateKeyA(const char* fn)
{
    auto _fn = make_path(fn);
    if (!_fn) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_create_key(_fn.value());
}

int shaloaImportKeyW(const wchar_t* fn, int slot_id, const wchar_t* subject, const wchar_t* end_date, const char* pin)
{
    auto _fn = make_path(fn);
    if (!_fn) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }

    size_t i;
    auto subject_len = lstrlenW(subject);
    auto subject_converted = std::vector<char>(subject_len + 1);
    wcstombs_s(&i, subject_converted.data(), subject_converted.capacity(), subject, subject_len);

    auto end_date_len = lstrlenW(end_date);
    auto end_date_converted = std::vector<char>(end_date_len + 1);
    wcstombs_s(&i, end_date_converted.data(), end_date_converted.capacity(), end_date, end_date_len);
    
    return _shaloa_import_key(_fn.value(), slot_id, subject_converted.data(), end_date_converted.data(), pin);
}

int shaloaImportKeyA(const char* fn, int slot_id, const char* subject, const char* end_date, const char* pin)
{
    auto _fn = make_path(fn);
    if (!_fn) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_import_key(_fn.value(), slot_id, subject, end_date, pin);
}

int shaloaExportKeyW(const wchar_t* fn, int slot_id, const char* pin) {
    auto _fn = make_path(fn);
    if (!_fn) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_export_key(_fn.value(), slot_id, pin);
}

int shaloaExportKeyA(const char* fn, int slot_id, const char* pin) {
    auto _fn = make_path(fn);
    if (!_fn) {
        return SHALOA_RESULT_ERROR_INTERNAL;
    }
    return _shaloa_export_key(_fn.value(), slot_id, pin);
}

int shaloaDeleteKey(int key_id, const char *pin)
{
    return _shaloa_delete_key(key_id, pin);
}

std::wstring convert_multibyte_to_wide(std::string &multibyte_string, unsigned int codepage_from) {
    auto wchar_len = MultiByteToWideChar(codepage_from, 0, multibyte_string.data(), -1, nullptr, 0);
    auto ret = std::wstring(wchar_len, L'\0');
    if (MultiByteToWideChar(codepage_from, 0, multibyte_string.data(), -1, ret.data(), ret.capacity()) < 0) {
        auto os_error_code = GetLastError();
        return std::format(L"エラーメッセージの文字コード変換に失敗しました (Code: {:x})", os_error_code);
    }

    ret.resize(std::char_traits<wchar_t>::length(ret.data()));
    ret.shrink_to_fit();

    return ret;
}

template <typename T>
requires std::same_as<T, char> || std::same_as<T, wchar_t>
int _shaloa_get_last_error_detail(T *buf, size_t buflen, std::basic_string<T> &message) {
    auto error_message_size = message.size() + 1;

    if (buf == nullptr) {
        return error_message_size;
    }

    auto write_len = std::min<size_t>(error_message_size, buflen);

    message.copy(buf, write_len - 1);
    buf[write_len - 1] = '\0';

    return write_len;
}

int shaloaGetLastErrorDetailW(wchar_t *buf, size_t buflen) {
    auto message = convert_multibyte_to_wide(last_error_message, CP_ACP);
    return _shaloa_get_last_error_detail(buf, buflen, message);
}

int shaloaGetLastErrorDetailA(char *buf, size_t buflen) {
    return _shaloa_get_last_error_detail(buf, buflen, last_error_message);
}
