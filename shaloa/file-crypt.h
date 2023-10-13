#pragma once
#include <filesystem>

int _shaloa_decode(const std::filesystem::path fnInp, const std::filesystem::path fnOutp, const char* pin, int *key_id);
int _shaloa_encode(const std::filesystem::path fnInp, const std::filesystem::path fnOutp, int key_id);
