#include "json-mode.h"
#include "../json/single_include/nlohmann/json.hpp"
#include "../shaloa/shaloa.h"
#include <iostream>
#include <unordered_map>
#include <format>

const std::unordered_map<int, std::string> message_map{
    {SHALOA_RESULT_SUCCESS, "SHALOA_RESULT_SUCCESS"},
    {SHALOA_RESULT_ERROR_INVALID_ARGUMENT, "SHALOA_RESULT_ERROR_INVALID_ARGUMENT"},
    {SHALOA_RESULT_ERROR_FILE_IO, "SHALOA_RESULT_ERROR_FILE_IO"},
    {SHALOA_RESULT_ERROR_PKCS_TOKEN, "SHALOA_RESULT_ERROR_PKCS_TOKEN"},
    {SHALOA_RESULT_ERROR_READ_MODULE, "SHALOA_RESULT_ERROR_READ_MODULE"},
    {SHALOA_RESULT_ERROR_READ_FUNCTION_LIST, "SHALOA_RESULT_ERROR_READ_FUNCTION_LIST"},
    {SHALOA_RESULT_ERROR_INVALID_FILE, "SHALOA_RESULT_ERROR_INVALID_FILE"},
    {SHALOA_RESULT_ERROR_CNG_OPERATION, "SHALOA_RESULT_ERROR_CNG_OPERATION"},
    {SHALOA_RESULT_ERROR_KEY_NOT_FOUND, "SHALOA_RESULT_ERROR_KEY_NOT_FOUND"},
    {SHALOA_RESULT_ERROR_INTERNAL, "SHALOA_RESULT_ERROR_INTERNAL"}};

constexpr const char *json_mode_error_msg = "SHALOA_RESULT_ERROR_JSON_MODE";

enum class Operation {
    Encode,
    Decode,
    CreateKey,
    ImportKey,
    Invalid = -1
};

// 不正な operation が与えられると Invalid にフォールバック
NLOHMANN_JSON_SERIALIZE_ENUM(Operation, {
    {Operation::Invalid, nullptr},
    {Operation::Encode, "Encode"},
    {Operation::Decode, "Decode"},
    {Operation::CreateKey, "CreateKey"},
    {Operation::ImportKey, "ImportKey"},
})

// 循環参照があるのであらかじめ定義しておく
std::string convert_codepage(unsigned int from, unsigned int to, const char *str);

// json-mode.cpp 内で起きたエラーは SHALOA_RESULT_ERROR_JSON_MODE になる
void print_error_json(unsigned int message_codepage, const char *result_str, const char *error_detail)
{
    auto j = std::format("{{ \"result\": \"{}\", \"detail\": \"{}\" }}", result_str, error_detail);
    if (message_codepage != CP_UTF8)
    {
        auto utf8_j = convert_codepage(message_codepage, CP_UTF8, j.data());
        std::cout << utf8_j << std::endl;
    }
    else
    {
        std::cout << j << std::endl;
    }
}

std::wstring convert_char_to_wchar(unsigned int codepage_from, const char *multibyte_str)
{
    // マルチバイト文字列を UTF-16 に変換
    auto wchar_len = MultiByteToWideChar(codepage_from, 0, multibyte_str, -1, nullptr, 0);
    auto wchar_converted = std::wstring(wchar_len, L'\0');
    auto result = MultiByteToWideChar(codepage_from, 0, multibyte_str, -1, wchar_converted.data(), wchar_converted.capacity());
    if (result == 0)
    {
        auto os_error_code = GetLastError();
        print_error_json(CP_UTF8, json_mode_error_msg, std::format("Code: {}", os_error_code).data());
        std::exit(EXIT_FAILURE);
    }
    wchar_converted.resize(std::char_traits<wchar_t>::length(wchar_converted.data()));
    wchar_converted.shrink_to_fit();

    return wchar_converted;
}

std::string convert_wchar_to_char(unsigned int codepage_to, const wchar_t *wstr) {
    auto len = WideCharToMultiByte(codepage_to, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    auto converted = std::string(len, 0);
    auto result = WideCharToMultiByte(codepage_to, 0, wstr, -1, converted.data(), converted.capacity(), nullptr, nullptr);
    if (result == 0)
    {
        auto os_error_code = GetLastError();

        // ここの print_error_json 自体は convert_codepage を利用しないので、呼び出しは循環しない
        print_error_json(CP_UTF8, json_mode_error_msg, std::format("Code: {}", os_error_code).data());
        std::exit(EXIT_FAILURE);
    }
    converted.resize(std::char_traits<char>::length(converted.data()));
    converted.shrink_to_fit();

    return converted;
}

std::string convert_codepage(unsigned int from, unsigned int to, const char *str)
{
    // マルチバイト文字列のコードポイントを変換
    // 一旦ワイド文字列を経由する
    auto wide_string = convert_char_to_wchar(from, str);
    auto converted = convert_wchar_to_char(to, wide_string.data());

    return converted;
}

int check_exec_result(int result)
{
    if (result < 0)
    {
        // エラー発生
        int buflen = shaloaGetLastErrorDetail(nullptr, 0);
        std::wstring buf(buflen - 1, '\0');

        // buf の中身は Shift-JIS
        shaloaGetLastErrorDetail(const_cast<wchar_t *>(buf.data()), buflen);

        auto error_msg = message_map.at((ShaloaResult)result);

        auto converted = convert_wchar_to_char(CP_UTF8, buf.data());

        // UTF-8 として出力される
        print_error_json(CP_UTF8, error_msg.data(), converted.data());

        return EXIT_FAILURE;
    }
    else
    {
        return EXIT_SUCCESS;
    }
}

int exec_encode(nlohmann::json properties)
{
    /*
    {
        operation: "Encode",
        properties: {
            inPath: string,
            outPath: string,
            keyId: [1-4]
        }
    }
    */
    if (!properties.contains("inPath") || !properties.contains("outPath") || !properties.contains("keyId"))
    {
        // inPath と outPath と keyId は必須
        print_error_json(CP_UTF8, json_mode_error_msg, "必須のフィールドが存在しません");
        return EXIT_FAILURE;
    }

    // パスは UTF-8 で表現されている
    auto inpath = properties["inPath"].get<std::string>();
    auto outpath = properties["outPath"].get<std::string>();

    // wchar_t（UTF-16）に変換
    auto inpath_w = convert_char_to_wchar(CP_UTF8, inpath.data());
    auto outpath_w = convert_char_to_wchar(CP_UTF8, outpath.data());

    auto key_id = properties["keyId"].get<int>();

    auto result = shaloaEncodeW(inpath_w.c_str(), outpath_w.c_str(), key_id);

    return check_exec_result(result);
}

int exec_decode(nlohmann::json properties, int *id)
{
    /*
    {
        operation: "Decode",
        properties: {
            inPath: string,
            outPath: string,
            pin: string
        }
    }
    */
    if (!properties.contains("inPath") || !properties.contains("outPath") || !properties.contains("pin"))
    {
        // inPath と outPath と pin は必須
        print_error_json(CP_UTF8, json_mode_error_msg, "必須のフィールドが存在しません");
        return EXIT_FAILURE;
    }

    // パスは UTF-8 で表現されている
    auto inpath = properties["inPath"].get<std::string>();
    auto outpath = properties["outPath"].get<std::string>();

    // wchar_t（UTF-16）に変換
    auto inpath_w = convert_char_to_wchar(CP_UTF8, inpath.data());
    auto outpath_w = convert_char_to_wchar(CP_UTF8, outpath.data());

    auto pin = properties["pin"].get<std::string>();

    auto result = shaloaDecodeW(inpath_w.c_str(), outpath_w.c_str(), pin.c_str(), id);

    return check_exec_result(result);
}

int exec_create_key(nlohmann::json properties)
{
    /*
    {
        operation: "CreateKey",
        properties: {
            outPath: string
        }
    }
    */

    if (!properties.contains("outPath"))
    {
        // outPath は必須
        print_error_json(CP_UTF8, json_mode_error_msg, "必須のフィールドが存在しません");
        return EXIT_FAILURE;
    }

    // パスは UTF-8 で表現されている
    auto outpath = properties["outPath"].get<std::string>();

    // wchar_t（UTF-16）に変換
    auto outpath_w = convert_char_to_wchar(CP_UTF8, outpath.data());

    auto result = shaloaCreateKeyW(outpath_w.c_str());

    return check_exec_result(result);
}

int exec_import_key(nlohmann::json properties)
{
    /*
    {
        operation: "ImportKey",
        properties: {
            inPath: string,
            slotId: [1-4],
            subject: string,
            endDate: string (yyyymmdd),
            pin: string
        }
    }
    */

    if (!properties.contains("inPath") 
        || !properties.contains("slotId") 
        || !properties.contains("subject")
        || !properties.contains("endDate")
        || !properties.contains("pin")
    ) {
        // 必須フィールドのチェック
        print_error_json(CP_UTF8, json_mode_error_msg, "必須のフィールドが存在しません");
        return EXIT_FAILURE;
    }

    // パスは UTF-8 で表現されている
    auto inpath = properties["inPath"].get<std::string>();

    // wchar_t（UTF-16）に変換
    auto inpath_w = convert_char_to_wchar(CP_UTF8, inpath.data());

    auto slot_id = properties["slotId"].get<int>();
    auto pin = properties["pin"].get<std::string>();
    auto end_date = properties["endDate"].get<std::string>();
    auto subject = properties["subject"].get<std::string>();

    auto subject_w = convert_char_to_wchar(CP_UTF8, subject.data());
    auto end_date_w = convert_char_to_wchar(CP_UTF8, end_date.data());

    auto result = shaloaImportKeyW(inpath_w.c_str(), slot_id, subject_w.c_str(), 
        end_date_w.c_str(), pin.c_str());
    
    return check_exec_result(result);
}

int exec_json_mode(const char *json_str)
{
    /*
    {
        operation: "Encode" | "Decode" | "CreateKey" | "ImportKey",
        properties: { ... }
    }
    */

    auto parsed = nlohmann::json::parse(json_str);

    if (!parsed.contains("operation") || !parsed.contains("properties"))
    {
        // operation と properties のフィールドがあることを確認
        print_error_json(CP_UTF8, json_mode_error_msg, "'operation' と 'properties' は必須です");
        return EXIT_FAILURE;
    }

    auto operation = parsed["operation"].get<Operation>();
    if (operation == Operation::Invalid)
    {
        // operation が不正
        print_error_json(CP_UTF8, json_mode_error_msg, "'operation' の値が不正です");
        return EXIT_FAILURE;
    }

    auto properties = parsed["properties"];

    int result = 0;
    int id = 0;

    switch (operation) {
    case Operation::Encode:
        result = exec_encode(properties);
        break;
    
    case Operation::Decode:
        result = exec_decode(properties, &id);
        break;
    
    case Operation::CreateKey:
        result = exec_create_key(properties);
        break;
    
    case Operation::ImportKey:
        result = exec_import_key(properties);
        break;
    
    default:
        // ここには来ない
        return EXIT_FAILURE;
    }

    if (result == EXIT_SUCCESS) {
        // 正常終了
        auto j = nlohmann::json({{"result", message_map.at(result)},
                                {"detail", std::to_string(id)}});

        std::cout << j << std::endl;
    }

    return EXIT_SUCCESS;
}
