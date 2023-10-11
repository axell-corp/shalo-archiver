// shaloa-cui-frontend.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <iostream>
#include "../shaloa/shaloa.h"
#include "json-mode.h"
#include <tchar.h>
#include <vector>
#include <Windows.h>
#include <string>
#include <boost/program_options.hpp>

namespace po = boost::program_options;

typedef std::basic_string<TCHAR> tstring;

void print_usage() {
    std::vector<std::string> usage = {
        "Usage:",
        "    shaloa.exe -e -i <input> -o <output> -k <key ID>",
        "    shaloa.exe -d -i <input> -o <output>",
        "    shaloa.exe -c -o <output>",
        "    shaloa.exe -x -o <output> -k <key ID>",
        "    shaloa.exe -r -k <key ID>",
        "    shaloa.exe -m -i <input> -k <key ID> -s <suject> -a <date>",
        "    shaloa.exe --json",
    };

    std::copy(usage.begin(), usage.end(), std::ostream_iterator<std::string>(std::cout, "\n"));
}

void print_argument_error(po::options_description &opt) {
    std::cerr << "Required option(s) was not given" << std::endl;
    print_usage();
    std::cout << opt << std::endl;
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

int _tmain(int argc, TCHAR* argv[])
{
    tstring input, output, subject, date;

    int keyid;
    
    auto generic_options = po::options_description("Generic options");
    generic_options.add_options()
        ("help,h", "Print usage and exit")
        ("version,v", "Print version of this program and exit")
        ("json,j", "Json mode")
    ;

    auto functional_options = po::options_description("Functional options");
    functional_options.add_options()
        ("encrypt,e", "Encrypt <input> file and output encrypted file to <output>")
        ("decrypt,d", "Decrypt <input> file and output decrypted file to <output>")
        ("create,c", "Create an RSA key pair and export it to <output>")
        ("import,m", "Import an RSA key pair from the file on <input> to <key ID> of the token")
        ("remove,r", "Remove an RSA key pair of <key ID>")
        ("export,x", "Export an RSA key pair to <output>")
    ;

    auto param_options = po::options_description("Parameters");
    param_options.add_options()
        ("input,i", new po::typed_value<tstring, TCHAR>(&input) ,"Path to a file to input")
        ("output,o", new po::typed_value<tstring, TCHAR>(&output), "Path to a file to output")
        ("subject,s", new po::typed_value<tstring, TCHAR>(&subject), "Subject of the key")
        ("date,a", new po::typed_value<tstring, TCHAR>(&date), "Expiration date for the key, ex. 20230831")
        ("key-id,k", po::value(&keyid)->default_value(1), "Key ID, range 1-4")
    ;

    auto opt = po::options_description();
    opt.add(generic_options).add(functional_options).add(param_options);

    po::variables_map values;

    try {
        po::store(po::parse_command_line(argc, argv, opt), values);
        po::notify(values);

        int result = SHALOA_RESULT_SUCCESS;

        if (values.count("help")) {
            print_usage();
            std::cout << opt << std::endl;
            return EXIT_SUCCESS;

        } else if (values.count("version")) {
            std::cout << "This function has not been implemented yet" << std::endl;
            return EXIT_SUCCESS;
        } else if (values.count("json")) {
            // stdin から読む
            std::string buf, json;
            while (std::cin >> buf) {
                buf += ' ';
                json += buf;
            }
            return exec_json_mode(json.data());

        } else if (values.count("encrypt")) {
            if (!values.count("input") || !values.count("output") || !values.count("key-id")) {
                print_argument_error(opt);
                return EXIT_FAILURE;
            }

            result = shaloaEncode(input.c_str(), output.c_str(), keyid);

        } else if (values.count("decrypt")) {
            if (!values.count("input") || !values.count("output")) {
                print_argument_error(opt);
                return EXIT_FAILURE;
            }

            auto pin = get_password();
            result = shaloaDecode(input.c_str(), output.c_str(), pin.c_str(), nullptr);

        } else if (values.count("create")) {
            if (!values.count("output")) {
                print_argument_error(opt);
                return EXIT_FAILURE;
            }

            result = shaloaCreateKey(output.c_str());
        
        } else if (values.count("import")) {
            if (!values.count("input") || !values.count("key-id") || !values.count("subject") || !values.count("date")) {
                print_argument_error(opt);
                return EXIT_FAILURE;
            }

            auto pin = get_password();
            result = shaloaImportKey(input.c_str(), keyid, subject.c_str(), date.c_str(), pin.c_str());
        
        } else if (values.count("export")) {
            if (!values.count("output") || !values.count("key-id")) {
                print_argument_error(opt);
                return EXIT_FAILURE;
            }

            auto pin = get_password();
            result = shaloaExportKey(output.c_str(), keyid, pin.c_str());
        
        } else if (values.count("remove")) {
            if (!values.count("key-id")) {
                print_argument_error(opt);
                return EXIT_FAILURE;
            }

            auto pin = get_password();
            result = shaloaDeleteKey(keyid, pin.c_str());

        } else {
            print_usage();
            std::cout << opt << std::endl;
            return EXIT_FAILURE;
            
        }

        if (result != SHALOA_RESULT_SUCCESS) {
            std::cerr << "error(" << result << ")" << std::endl;
            int buflen = shaloaGetLastErrorDetailA(nullptr, 0);
            std::vector<char> buf(buflen);
            shaloaGetLastErrorDetailA(buf.data(), buflen);
            std::cerr << buf.data() << std::endl;

            return EXIT_FAILURE;
        }

    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

// プログラムの実行: Ctrl + F5 または [デバッグ] > [デバッグなしで開始] メニュー
// プログラムのデバッグ: F5 または [デバッグ] > [デバッグの開始] メニュー

// 作業を開始するためのヒント: 
//    1. ソリューション エクスプローラー ウィンドウを使用してファイルを追加/管理します 
//   2. チーム エクスプローラー ウィンドウを使用してソース管理に接続します
//   3. 出力ウィンドウを使用して、ビルド出力とその他のメッセージを表示します
//   4. エラー一覧ウィンドウを使用してエラーを表示します
//   5. [プロジェクト] > [新しい項目の追加] と移動して新しいコード ファイルを作成するか、[プロジェクト] > [既存の項目の追加] と移動して既存のコード ファイルをプロジェクトに追加します
//   6. 後ほどこのプロジェクトを再び開く場合、[ファイル] > [開く] > [プロジェクト] と移動して .sln ファイルを選択します
