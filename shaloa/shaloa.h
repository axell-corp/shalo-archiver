#pragma once

#if defined(_WIN64) || defined(_M_X64) || defined(__amd64__) || defined(__x86_64__) || defined(__arm64__)
#define SHALOA_API
#else
#define SHALOA_API  __stdcall
#endif

extern "C" {
    typedef enum ShaloaResult {
        SHALOA_RESULT_SUCCESS                   = 0,    // 成功
        SHALOA_RESULT_ERROR_INVALID_ARGUMENT    = -1,   // 引数が不正
        SHALOA_RESULT_ERROR_FILE_IO             = -2,   // ファイル入出力エラー
        SHALOA_RESULT_ERROR_PKCS_TOKEN          = -3,   // トークン絡みのエラー
        SHALOA_RESULT_ERROR_READ_MODULE         = -4,   // モジュール読み込みに失敗
        SHALOA_RESULT_ERROR_READ_FUNCTION_LIST  = -5,   // モジュールからの関数リストの読み込みに失敗
        SHALOA_RESULT_ERROR_INVALID_FILE        = -6,   // 不正なファイルを読み込ませようとした
        SHALOA_RESULT_ERROR_CNG_OPERATION       = -7,   // CNG による処理に失敗
        SHALOA_RESULT_ERROR_KEY_NOT_FOUND       = -8,   // 鍵が見つからない
        SHALOA_RESULT_ERROR_INTERNAL            = -256, // その他の内部エラー
    } ShaloaResult;

    int SHALOA_API shaloaEncodeW(const wchar_t* fnInp, const wchar_t* fnOutp, int key_id);
    int SHALOA_API shaloaEncodeA(const char* fnInp, const char* fnOutp, int key_id);

    int SHALOA_API shaloaDecodeW(const wchar_t* fnInp, const wchar_t* fnOutp, const char *pin, int *key_id);
    int SHALOA_API shaloaDecodeA(const char* fnInp, const char* fnOutp, const char* pin, int *key_id);

    int SHALOA_API shaloaCreateKeyW(const wchar_t* fn);
    int SHALOA_API shaloaCreateKeyA(const char* fn);

    int SHALOA_API shaloaImportKeyW(const wchar_t* fn, int slot_id, const wchar_t *subject, const wchar_t *end_date, const char* pin);
    int SHALOA_API shaloaImportKeyA(const char* fn, int slot_id, const char* subject, const char* end_date, const char *pin);

    int SHALOA_API shaloaExportKeyW(const wchar_t* fn, int slot_id, const char* pin);
    int SHALOA_API shaloaExportKeyA(const char* fn, int slot_id, const char* pin);

    int SHALOA_API shaloaDeleteKey(int key_id, const char *pin);

    int SHALOA_API shaloaGetLastErrorDetailW(wchar_t *buf, size_t buflen);
    int SHALOA_API shaloaGetLastErrorDetailA(char *buf, size_t buflen);

#ifdef UNICODE
#define shaloaEncode shaloaEncodeW
#define shaloaDecode shaloaDecodeW
#define shaloaCreateKey shaloaCreateKeyW
#define shaloaImportKey shaloaImportKeyW
#define shaloaExportKey shaloaExportKeyW
#define shaloaGetLastErrorDetail shaloaGetLastErrorDetailW
#else
#define shaloaEncode shaloeEncodeA
#define shaloaDecode shaloaDecodeA
#define shaloaCreateKey shaloaCreateKeyA
#define shaloaImportKey shaloaImportKeyA
#define shaloaExportKey shaloaExportKeyA
#define shaloaGetLastErrorDetail shaloaGetLastErrorDetailA
#endif // UNICODE

}
