#include <string>
#include <vector>

#include "clang/AST/ASTContext.h"
#include "clang/AST/AST.h"

std::string replaceString(std::string source,std::string from,std::string to);
std::string escapeForCStringLiteral(const std::string& source);
std::string stmtToString(clang::ASTContext *C, clang::Stmt* S);
std::string translationUnitToString(clang::ASTContext *C, clang::TranslationUnitDecl* decl);
bool endsWith(std::string target, std::string substr);
std::vector<std::string> split(const std::string& str, char delimiter=' ');
std::vector<std::string> splitLines(const std::string& str);