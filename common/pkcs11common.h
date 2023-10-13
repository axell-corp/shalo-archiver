#pragma once

//  pkcs11.h setting

#if defined(_WIN32)

#pragma pack(push, cryptoki, 1)

#define CK_PTR *

#define CK_IMPORT_SPEC __declspec(dllimport)

#define CK_CALL_SPEC __cdecl

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_IMPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "../include/pkcs11/pkcs11.h"

#pragma pack(pop, cryptoki)

#else

#define CK_PTR *

#define CK_IMPORT_SPEC

#define CK_CALL_SPEC

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_IMPORT_SPEC CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType CK_IMPORT_SPEC (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <pkcs11/pkcs11.h>

#endif
