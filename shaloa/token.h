#pragma once
#include "../common/pkcs11common.h"
#include "windows-crypt.h"
#include <vector>
#include <string>
#include <memory>

struct token_encrypted {
	std::vector<uint8_t> encrypted_data;
	std::vector<uint8_t> pubkey_modulus_hash;
};

class Token
{
public:
	Token(HMODULE module_handle);
	~Token();

	void open_session(int slot_id_num);
	std::vector<CK_SLOT_ID> get_slot_id_list() const;
	void login(std::string pin) const;

	std::vector<uint8_t> generate_random_data(CK_ULONG size) const;
	std::unique_ptr<token_encrypted> encrypt(const std::vector<uint8_t>& raw_vec, int pubkey_id);
	std::vector<uint8_t> decrypt(const std::vector<uint8_t>& encrypted_vec, const std::vector<uint8_t>& privkey_modulus_hash);

	void add_rsa_keypair(const std::shared_ptr<rsa_key> key, int slot_id, const char* subject, std::optional<CK_DATE> end_date);
	void delete_rsa_keypair_and_certificate(int slot_id);
	void add_certificate(const std::vector<uint8_t>& cert_value, int slot_id, const char* subject);

	std::vector<uint8_t> export_certificate(int slot_id);
	
	int find_key_id_from_modulus_hash(const std::vector<uint8_t> &modulus_hash);

private:
	void load_func_list(std::string func_name);
	void initialize_token();
	void get_slot_id_list_from_token();
	std::vector<uint8_t> get_modulus_hash_by_key_handle(CK_OBJECT_HANDLE key_handle);
	CK_OBJECT_HANDLE find_object_by_key_id(int key_id, CK_OBJECT_CLASS object_class);
	CK_OBJECT_HANDLE find_rsa_key_by_modulus_hash(const std::vector<uint8_t>& modulus_hash, CK_OBJECT_CLASS object_class);
	void close_session();
	void finalize_token();

	const HMODULE _module;
	CK_FUNCTION_LIST* _func_list;
	std::vector<CK_SLOT_ID> _slot_id_list;
	CK_SESSION_HANDLE _session;

	bool _is_token_initialized = false;
	bool _is_session_opened = false;
	//CK_BYTE _default_rsa_key_id[11] = { 'S','L','A','R','C','V','K','E','Y','#','1' };
	CK_BYTE _default_rsa_key_id[11] = { 'A','X','T','O','O','L','K','E','Y','#','1' };
	const CK_MECHANISM _mechanism = { CKM_RSA_PKCS, nullptr, 0 };
};
