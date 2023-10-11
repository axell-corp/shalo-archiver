#pragma once
#include <string>
#include <windef.h>
#include <tchar.h>

class Module
{
public:
	Module();
	~Module();
	HMODULE get_module_pointer() const;

private:
	HMODULE _module;
	const TCHAR *_library_name = _T("slpkcs11-vc");
	const TCHAR *_library_directory = _T("\\shalo_pkcs11\\x64");
};
