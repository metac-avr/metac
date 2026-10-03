#include "preprocess/macro_collector.h"

#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Lex/MacroInfo.h"
#include "clang/Lex/PPCallbacks.h"
#include "clang/Lex/Preprocessor.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/ADT/SmallString.h"
#include "spdlog/spdlog.h"

#include <fstream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

// A single spelled replacement token.
struct STok {
    std::string spelling;
    bool isId = false;         // names an identifier (candidate macro/param)
    bool leadingSpace = false; // had whitespace before it in the source
};

struct MacroRecord {
    std::string name;
    bool functionLike = false;
    bool variadic = false;
    bool hasHashOps = false; // body uses `#` or `##`
    std::vector<std::string> params;
    std::vector<STok> body; // replacement tokens
    std::string file;
    unsigned line = 0;
    bool undefined = false;
};

using MacroTable = std::map<std::string, MacroRecord>;

struct EnumRecord {
    std::string name;     // enumerator spelling
    std::string enumName; // enclosing enum tag ("" if anonymous)
    std::string value;    // integer value (base 10)
    bool scoped = false;  // enum class / enum struct
    std::string file;
    unsigned line = 0;
};

// Enum constants are keyed by their name, or "Enum::Name" when scoped.
using EnumTable = std::map<std::string, EnumRecord>;

// ---- Collection --------------------------------------------------------

class MacroCollector : public clang::PPCallbacks {
public:
    MacroCollector(clang::Preprocessor& pp, MacroTable& table)
        : PP(pp), SM(pp.getSourceManager()), table(table) {}

    void MacroDefined(const clang::Token& nameTok,
                      const clang::MacroDirective* MD) override {
        const clang::MacroInfo* mi = MD ? MD->getMacroInfo() : nullptr;
        if (!mi) return;
        clang::SourceLocation loc = mi->getDefinitionLoc();
        // Skip predefined / -D / builtin / system-header macros; keep the codebase's own.
        if (loc.isInvalid() || SM.isWrittenInBuiltinFile(loc) ||
            SM.isWrittenInCommandLineFile(loc) || SM.isWrittenInScratchSpace(loc) ||
            SM.isInSystemHeader(loc))
            return;
        if (!nameTok.getIdentifierInfo()) return;

        MacroRecord rec;
        rec.name = nameTok.getIdentifierInfo()->getName().str();
        rec.functionLike = mi->isFunctionLike();
        rec.variadic = mi->isVariadic();
        for (const clang::IdentifierInfo* p : mi->params())
            rec.params.push_back(p ? p->getName().str() : std::string());
        for (const clang::Token& t : mi->tokens()) {
            STok st;
            st.spelling = PP.getSpelling(t);
            st.isId = (t.getIdentifierInfo() != nullptr);
            st.leadingSpace = t.hasLeadingSpace();
            if (t.is(clang::tok::hash) || t.is(clang::tok::hashhash))
                rec.hasHashOps = true;
            rec.body.push_back(std::move(st));
        }
        rec.file = SM.getFilename(loc).str();
        rec.line = SM.getSpellingLineNumber(loc);
        // Latest definition wins; a redefinition clears a prior #undef flag.
        table[rec.name] = std::move(rec);
    }

    void MacroUndefined(const clang::Token& nameTok, const clang::MacroDefinition&,
                        const clang::MacroDirective*) override {
        if (!nameTok.getIdentifierInfo()) return;
        auto it = table.find(nameTok.getIdentifierInfo()->getName().str());
        if (it != table.end())
            it->second.undefined = true; // keep the definition, just flag it
    }

private:
    clang::Preprocessor& PP;
    clang::SourceManager& SM;
    MacroTable& table;
};

// Walk the translation unit and record every enum constant defined in the
// codebase's own sources (skipping system/builtin headers, mirroring macros).
class EnumCollector : public clang::RecursiveASTVisitor<EnumCollector> {
public:
    EnumCollector(clang::ASTContext& ctx, EnumTable& table)
        : SM(ctx.getSourceManager()), table(table) {}

    bool VisitEnumDecl(clang::EnumDecl* ED) {
        clang::SourceLocation loc = ED->getLocation();
        if (loc.isInvalid() || SM.isWrittenInBuiltinFile(loc) ||
            SM.isWrittenInScratchSpace(loc) || SM.isInSystemHeader(loc))
            return true;

        const std::string enumName = ED->getName().str(); // "" if anonymous
        const bool scoped = ED->isScoped();
        for (clang::EnumConstantDecl* ec : ED->enumerators()) {
            EnumRecord rec;
            rec.name = ec->getName().str();
            rec.enumName = enumName;
            rec.scoped = scoped;
            llvm::SmallString<32> buf;
            ec->getInitVal().toString(buf); // base-10 by default
            rec.value = std::string(buf.str());
            clang::SourceLocation eloc = ec->getLocation();
            rec.file = SM.getFilename(eloc).str();
            rec.line = SM.getSpellingLineNumber(eloc);

            std::string key = (scoped && !enumName.empty())
                                  ? enumName + "::" + rec.name
                                  : rec.name;
            table[std::move(key)] = std::move(rec);
        }
        return true;
    }

private:
    clang::SourceManager& SM;
    EnumTable& table;
};

class EnumConsumer : public clang::ASTConsumer {
public:
    explicit EnumConsumer(EnumTable& table) : table(table) {}
    void HandleTranslationUnit(clang::ASTContext& ctx) override {
        EnumCollector(ctx, table).TraverseDecl(ctx.getTranslationUnitDecl());
    }

private:
    EnumTable& table;
};

// A full parse is required to see enum declarations; the preprocessor still
// runs during parsing, so the macro PPCallbacks fire exactly as before.
class MacroCollectAction : public clang::ASTFrontendAction {
public:
    MacroCollectAction(MacroTable& macros, EnumTable& enums)
        : macros(macros), enums(enums) {}

protected:
    bool BeginSourceFileAction(clang::CompilerInstance& CI) override {
        clang::Preprocessor& pp = CI.getPreprocessor();
        pp.addPPCallbacks(std::make_unique<MacroCollector>(pp, macros));
        return true;
    }

    std::unique_ptr<clang::ASTConsumer>
    CreateASTConsumer(clang::CompilerInstance&, llvm::StringRef) override {
        return std::make_unique<EnumConsumer>(enums);
    }

private:
    MacroTable& macros;
    EnumTable& enums;
};

// ---- Recursive expansion (best-effort) ---------------------------------

std::vector<STok> expand(const std::vector<STok>& in, const MacroTable& table,
                         std::set<std::string> disabled, bool& flagged, int depth) {
    std::vector<STok> out;
    if (depth > 64) { // runaway guard (should not trigger given `disabled`)
        flagged = true;
        return in;
    }
    const size_t n = in.size();
    size_t i = 0;
    while (i < n) {
        const STok& t = in[i];
        auto it = t.isId ? table.find(t.spelling) : table.end();
        if (it == table.end() || disabled.count(t.spelling)) {
            out.push_back(t);
            ++i;
            continue;
        }
        const MacroRecord& m = it->second;

        // Best-effort: never expand macros that need faithful #/##/variadic handling.
        if (m.hasHashOps || m.variadic) {
            flagged = true;
            out.push_back(t);
            ++i;
            continue;
        }

        if (!m.functionLike) {
            std::set<std::string> sub = disabled;
            sub.insert(m.name);
            std::vector<STok> ex = expand(m.body, table, sub, flagged, depth + 1);
            if (!ex.empty()) ex.front().leadingSpace = t.leadingSpace;
            out.insert(out.end(), ex.begin(), ex.end());
            ++i;
            continue;
        }

        // Function-like: only an invocation if the next token is '('.
        size_t j = i + 1;
        if (j >= n || in[j].spelling != "(") {
            out.push_back(t); // bare function-like macro name, not a call
            ++i;
            continue;
        }

        // Parse the argument list with balanced-paren, top-level-comma splitting.
        std::vector<std::vector<STok>> args;
        std::vector<STok> cur;
        int paren = 0;
        bool closed = false;
        size_t k = j;
        for (; k < n; ++k) {
            const std::string& s = in[k].spelling;
            if (s == "(") {
                if (++paren == 1) continue; // skip the opening paren of the call
            } else if (s == ")") {
                if (--paren == 0) {
                    args.push_back(cur);
                    closed = true;
                    ++k;
                    break;
                }
            } else if (s == "," && paren == 1) {
                args.push_back(cur);
                cur.clear();
                continue;
            }
            cur.push_back(in[k]);
        }

        // MACRO() with no parameters -> zero args.
        if (closed && args.size() == 1 && args[0].empty() && m.params.empty())
            args.clear();

        if (!closed || args.size() != m.params.size()) {
            flagged = true; // malformed or arity mismatch: leave call untouched
            out.push_back(t);
            ++i;
            continue;
        }

        // Argument prescan: expand each argument before substitution.
        std::vector<std::vector<STok>> exArgs;
        exArgs.reserve(args.size());
        for (auto& a : args)
            exArgs.push_back(expand(a, table, disabled, flagged, depth + 1));

        // Substitute parameters in the body.
        std::vector<STok> substituted;
        for (const STok& bt : m.body) {
            int pidx = -1;
            if (bt.isId)
                for (size_t p = 0; p < m.params.size(); ++p)
                    if (m.params[p] == bt.spelling) { pidx = (int)p; break; }
            if (pidx >= 0) {
                const auto& rep = exArgs[pidx];
                for (size_t r = 0; r < rep.size(); ++r) {
                    STok rt = rep[r];
                    if (r == 0) rt.leadingSpace = bt.leadingSpace;
                    substituted.push_back(rt);
                }
            } else {
                substituted.push_back(bt);
            }
        }

        // Rescan the result with this macro disabled (prevents recursion).
        std::set<std::string> sub = disabled;
        sub.insert(m.name);
        std::vector<STok> ex = expand(substituted, table, sub, flagged, depth + 1);
        if (!ex.empty()) ex.front().leadingSpace = t.leadingSpace;
        out.insert(out.end(), ex.begin(), ex.end());
        i = k; // continue past the consumed ')'
    }
    return out;
}

std::string render(const std::vector<STok>& toks) {
    std::string s;
    for (size_t i = 0; i < toks.size(); ++i) {
        if (i > 0 && toks[i].leadingSpace) s += ' ';
        s += toks[i].spelling;
    }
    return s;
}

} // namespace

void collectMacrosToJson(const std::string& code,
                         const std::vector<std::string>& args,
                         const std::string& filename,
                         const std::string& outJsonPath) {
    MacroTable table;
    EnumTable enums;
    bool ok = clang::tooling::runToolOnCodeWithArgs(
        std::make_unique<MacroCollectAction>(table, enums), code, args, filename,
        "metapro-macro-collector");
    if (!ok)
        spdlog::warn("Macro/enum collection failed for {}", filename);

    // Merge into any existing JSON so results accumulate across files.
    nlohmann::json root = nlohmann::json::object();
    {
        std::ifstream ifs(outJsonPath);
        if (ifs.good()) {
            try {
                ifs >> root;
            } catch (...) {
                root = nlohmann::json::object();
            }
            if (!root.is_object()) root = nlohmann::json::object();
        }
    }

    for (const auto& kv : table) {
        const MacroRecord& rec = kv.second;
        bool flagged = false;
        std::vector<STok> ex = expand(rec.body, table, {rec.name}, flagged, 0);

        nlohmann::json j;
        j["kind"] = "macro";
        j["name"] = rec.name;
        j["file"] = rec.file;
        j["line"] = rec.line;
        j["function_like"] = rec.functionLike;
        j["variadic"] = rec.variadic;
        j["params"] = rec.params;
        j["raw_body"] = render(rec.body);
        j["expanded_body"] = render(ex);
        j["undefined"] = rec.undefined;
        j["needs_manual"] = rec.hasHashOps || rec.variadic || flagged;
        root[rec.name] = std::move(j);
    }

    for (const auto& kv : enums) {
        // A macro of the same name shadows the enum constant in real code;
        // never clobber an existing macro record with an enum entry.
        if (root.contains(kv.first) &&
            root[kv.first].value("kind", std::string()) == "macro")
            continue;

        const EnumRecord& rec = kv.second;
        nlohmann::json j;
        j["kind"] = "enum_constant";
        j["name"] = rec.name;
        j["file"] = rec.file;
        j["line"] = rec.line;
        // Mirror the macro record shape so consumers use a single schema. An
        // enum constant behaves like an object-like macro whose body is its
        // integer value.
        j["function_like"] = false;
        j["variadic"] = false;
        j["params"] = nlohmann::json::array();
        j["raw_body"] = rec.value;
        j["expanded_body"] = rec.value;
        j["undefined"] = false;
        j["needs_manual"] = false;
        // Enum-specific extras.
        j["enum"] = rec.enumName;
        j["scoped"] = rec.scoped;
        j["value"] = rec.value;
        root[kv.first] = std::move(j);
    }

    std::ofstream ofs(outJsonPath);
    ofs << root.dump(2);
    ofs.close();
    spdlog::debug("Collected {} macros and {} enum constants from {} into {}",
                  table.size(), enums.size(), filename, outJsonPath);
}
