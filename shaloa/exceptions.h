#pragma once
#include "shaloa.h"
#include "../common/pkcs11common.h"
#include <bcrypt.h>
#include <optional>
#include <string>
#include <Windows.h>

class TokenException : public std::exception
{
public:
	// Error without the code
	TokenException(std::string errorstr, std::string message);

	// Error with the code
	TokenException(CK_RV result, std::string message);

	
	std::string &&get_error_message();

private:
	const std::optional<CK_RV> token_error_code;
	std::string token_error_message;
	std::string readable_error_message;
};

class OsException : public std::exception {
public:
	// Win32 error
	OsException(ShaloaResult shaloa_result, std::string message);

	// HRESULT or NTSTATUS
	OsException(ShaloaResult shaloa_result, long os_error_code, std::string message);

	std::string&& get_error_message();
	ShaloaResult get_shaloa_result() const;

private:
	const ShaloaResult shaloa_result;
	const HRESULT os_error_code;
	std::string os_error_message;
	std::string readable_error_message;
};

class OtherException : public std::exception {
public:
	OtherException(ShaloaResult shaloa_result, std::string message);
	ShaloaResult get_shaloa_result() const;
private:
	const ShaloaResult shaloa_result;
};
