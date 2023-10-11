#pragma once
#include <filesystem>

int _shaloa_create_key(const std::filesystem::path fn);
int _shaloa_import_key(const std::filesystem::path fn, int slot_id, std::string subject, std::string end_date, const char* pin);
int _shaloa_export_key(const std::filesystem::path fn, int slot_id, const char* pin);
int _shaloa_delete_key(int key_id, const char *pin);
