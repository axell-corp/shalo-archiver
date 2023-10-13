#include "pch.h"
#include "module.h"
#include "exceptions.h"
#include <ShlObj.h>

Module::Module() {
    std::string error_msg = "モジュールの読み込みに失敗しました";
    TCHAR lib_path[MAX_PATH]{};
    
    auto get_path_result = SHGetFolderPath(nullptr, CSIDL_PROFILE, nullptr, 0, lib_path);
    if (get_path_result != S_OK) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_READ_MODULE, get_path_result, error_msg);
    }

    _tcscat_s(lib_path, _library_directory);

    auto set_result = SetDllDirectory(lib_path);
    if (!set_result) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_READ_MODULE, error_msg);
    }

    auto lib = LoadLibrary(_library_name);
    if (lib == nullptr) {
        throw OsException(ShaloaResult::SHALOA_RESULT_ERROR_READ_MODULE, error_msg);
    }

    _module = lib;
}

Module::~Module()
{
    if (_module) FreeLibrary(_module);
}

HMODULE Module::get_module_pointer() const
{
    return _module;
}
