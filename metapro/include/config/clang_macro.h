#pragma once

#include <clang/AST/AST.h>
#include <clang/AST/Stmt.h>

#if defined(CLANG_MAJOR) && (CLANG_MAJOR < 15)
#define CLANG_STRING_KIND_ORDINARY clang::StringLiteral::StringKind::Ascii
#else
#define CLANG_STRING_KIND_ORDINARY clang::StringLiteral::StringKind::Ordinary
#endif

#if defined(CLANG_MAJOR) && (CLANG_MAJOR < 13)
#define CLANG_VALUE_KIND_RVALUE clang::VK_RValue
#else
#define CLANG_VALUE_KIND_RVALUE clang::VK_PRValue
#endif