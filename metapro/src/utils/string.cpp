#include "utils/string.h"

#include <string>
#include <iostream>
#include <sstream>
#include "clang/AST/ASTContext.h"
#include "clang/AST/AST.h"

std::string replaceString(std::string source,std::string from,std::string to) {
    std::string result = source;
    size_t start_pos = 0;
    while((start_pos = result.find(from, start_pos)) != std::string::npos) {
        result.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return result;
}

// Prepare C source text for embedding inside a C string literal "...".
// Quotes already escaped in the source (preceded by an odd number of
// backslashes) are left intact; raw quotes are escaped. Newlines become \n.
std::string escapeForCStringLiteral(const std::string& source) {
    std::string out;
    out.reserve(source.size() + 8);
    for (size_t i = 0; i < source.size(); ++i) {
        char c = source[i];
        if (c == '\n') { out += "\\n"; continue; }
        if (c == '"') {
            size_t bs = 0;
            for (size_t j = i; j > 0 && source[j-1] == '\\'; --j) ++bs;
            if ((bs % 2) == 0) out += '\\';
        }
        out += c;
    }
    return out;
}

std::string stmtToString(clang::ASTContext *C, clang::Stmt* S) {
    std::string tmp;
    llvm::raw_string_ostream sout(tmp);
    clang::PrintingPolicy policy = C->getPrintingPolicy();
    policy.IncludeNewlines = false;
    S->printPretty(sout, 0, policy);
    return sout.str();
}

std::string translationUnitToString(clang::ASTContext *C, clang::TranslationUnitDecl* decl) {
    std::string tmp;
    llvm::raw_string_ostream sout(tmp);
    decl->print(sout, C->getPrintingPolicy(),4);
    return sout.str();
}

bool endsWith(std::string target, std::string substr) {
    if (target.length() < substr.length()) return false;
    return target.compare(target.length() - substr.length(), substr.length(), substr) == 0;
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::istringstream iss(str);
    std::string buffer;
 
    std::vector<std::string> result;
 
    while (std::getline(iss, buffer, delimiter)) {
        if (buffer!="")
            result.push_back(buffer);
        else
            result.push_back("");
    }
 
    return result;
}

std::vector<std::string> splitLines(const std::string& str) {
    return split(str, '\n');
}