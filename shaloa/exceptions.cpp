#include "pch.h"
#include "exceptions.h"
#include <sstream>
#include <unordered_map>
#include <system_error>

OsException::OsException(ShaloaResult shaloa_result, std::string message) : OsException(shaloa_result, HRESULT_FROM_WIN32(GetLastError()), message)
{
    // Win32 エラーの場合は GetLastError() でコードを取って HRESULT に変換する
}

OsException::OsException(ShaloaResult shaloa_result, long result, std::string message) : std::exception(message.c_str()), shaloa_result(shaloa_result), os_error_code(result)
{
    // もし NTSTATUS なら HRESULT に変換する
    HRESULT hresult_error_code;
    if ((result & 0xC0000000) == 0xC0000000) {
        hresult_error_code = HRESULT_FROM_NT(result);
        // hresult_error_code = result;
    }
    else {
        hresult_error_code = result;
    }

    // HRESULT からエラーを表す文字列を取得
    //auto error_message = std::system_category().message(hresult_error_code);
    //os_error_message = error_message.size() ? error_message : "The error code did not exist in the system errors.";
    os_error_message = std::system_category().message(hresult_error_code);

    std::stringstream str;
    str << "Error: " << this->what() << ": " << os_error_message << "(Code: " << std::showbase << std::hex << os_error_code << ")";
    readable_error_message = str.str();
}

std::string&& OsException::get_error_message()
{
    return std::move(readable_error_message);
}

ShaloaResult OsException::get_shaloa_result() const
{
    return shaloa_result;
}

const std::unordered_map<CK_RV, std::string> token_error_string_map {
    {CKR_OK,                      "成功"},
    {CKR_ATTRIBUTE_SENSITIVE,     "機密なアトリビュートはエクスポートできません"},
    {CKR_ACTION_PROHIBITED,       "cryptoki によって禁止されています"},
    {CKR_DATA_LEN_RANGE,          "入力されたデータが長すぎます"},
    {CKR_DATA_INVALID,            "入力されたデータが不正です"},
    {CKR_ENCRYPTED_DATA_LEN_RANGE,"暗号化されたデータが長すぎます"},
    {CKR_ENCRYPTED_DATA_INVALID,  "暗号化されたデータが不正です"},
    {CKR_SIGNATURE_LEN_RANGE,     "署名が長すぎます"},
    {CKR_SIGNATURE_INVALID,       "署名が不正です"},
    {CKR_FUNCTION_NOT_SUPPORTED,  "この機能はサポートされていません"},
    {CKR_MECHANISM_INVALID,       "メカニズムが不正です"},
    {CKR_MECHANISM_PARAM_INVALID, "メカニズムのパラメータが不正です"},
    {CKR_PIN_INCORRECT,           "PIN が間違っています"},
    {CKR_PIN_INVALID,             "PIN が不正です"},
    {CKR_PIN_LEN_RANGE,           "PIN が長すぎます"},
    {CKR_PIN_LOCKED,              "PIN がロックされています"},
    {CKR_FUNCTION_FAILED,         "関数の実行に失敗しました"},
    {CKR_USER_PIN_NOT_INITIALIZED,"User PIN が初期化されていません"},
    {CKR_DEVICE_ERROR,            "デバイスとの通信に失敗しました"},
    {CKR_TOKEN_WRITE_PROTECTED,   "デバイスへの書き込みが制限されています"},
    {CKR_TOKEN_NOT_RECOGNIZED,    "トークンが認識されていません"},
    {CKR_TOKEN_NOT_PRESENT,       "トークンが存在しません"},
    {CKR_SESSION_READ_ONLY,       "セッションは読み取り専用です"},
    {CKR_USER_NOT_LOGGED_IN,      "ログインされていません"},
};

TokenException::TokenException(std::string errorstr, std::string message) : std::exception(message.c_str()), token_error_code(std::nullopt)
{
    token_error_message = errorstr;
    std::stringstream str;
    str << "Error: " << this->what() << ": " << token_error_message;
    readable_error_message = str.str();
}

TokenException::TokenException(CK_RV result, std::string message) : std::exception(message.c_str()), token_error_code(result)
{
    if (token_error_string_map.contains(result)) {
        token_error_message = token_error_string_map.at(result);
    }
    else {
        token_error_message = "Undocumented error";
    }

    std::stringstream str;
    str << "Error: " << this->what() << ": " << token_error_message;
    if (token_error_code) {
        str << "(Code: " << std::showbase << std::hex << token_error_code.value() << ")";
    }

    readable_error_message = str.str();
}

std::string &&TokenException::get_error_message()
{
    return std::move(readable_error_message);
}

OtherException::OtherException(ShaloaResult shaloa_result, std::string message) : std::exception(message.c_str()), shaloa_result(shaloa_result)
{
}

ShaloaResult OtherException::get_shaloa_result() const
{
    return shaloa_result;
}
