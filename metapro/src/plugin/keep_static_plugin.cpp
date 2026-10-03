/*
    Clang plugin keeping the static functions of the program in the binary.

    A function with internal linkage that its own translation unit never calls is dead code: the compiler
    drops it before the linker sees anything, at every optimization level, and no flag of clang changes
    that (-fno-inline only stops the substitution of a body at a call site, and a function nothing calls
    has no call site; -fkeep-inline-functions is accepted but does nothing, -fkeep-static-functions is
    GCC only). A patch expression calling such a function then finds no symbol to call.

    The instrumenter writes `__attribute__((used))` in front of the static functions of the files it
    rewrites, which covers a .c file. It cannot cover a header: metapro instruments .c files only, and a
    `static inline` helper of a header -- av_clip(), get_bits() and the rest of what a project keeps in
    its headers -- is exactly the kind of callee a patch reaches for. This plugin attaches the same
    attribute to the AST instead of the source, so a header is covered without being rewritten.

    It has to run before the main action: CodeGenModule decides whether to emit a function when it
    handles that top level declaration, so an attribute attached afterwards comes too late.

    Two filters keep the marking to where it is needed, because emitting a function that was dead code
    turns whatever it calls into a link time requirement. ffmpeg's `doc/print_options` links a handful of
    objects and no library, so keeping the helpers of its headers left `av_log2`, `av_strerror` and
    `avio_seek` undefined in it.

    * Only a translation unit metapro instrumented is marked, recognised by the runtime header the
      instrumentation includes. A patch expression runs in an instrumented function, so a callee only has
      to have a body in those files; every other file of the program is left exactly as it was, including
      the auxiliary programs a build makes for itself.
    * Within one, system headers are skipped, and when METAPRO_KEEP_STATIC_ROOTS names one or more path
      prefixes (separated by ':'), only the files below them are kept -- buildProject() sets it to the
      source tree it is building.
*/
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Decl.h>
#include <clang/AST/DeclBase.h>
#include <clang/AST/DeclGroup.h>
#include <clang/Basic/SourceLocation.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendPluginRegistry.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

namespace {

/*
    The absolute, dot free form of a path. A build hands the compiler whatever spelling it likes, e.g.
    `libavcodec/h264dec.c` with -I., so the spelling of a file and the spelling of a root only compare
    once both are resolved against the directory the compiler runs in.
*/
std::string absolutePath(llvm::StringRef path) {
    if (path.empty()) return std::string();
    llvm::SmallString<256> resolved(path);
    llvm::sys::fs::make_absolute(resolved);
    llvm::sys::path::remove_dots(resolved, /*remove_dot_dot=*/true);
    return std::string(resolved.str());
}

/* The prefixes of METAPRO_KEEP_STATIC_ROOTS, or empty when it names none */
std::vector<std::string> keptRoots() {
    std::vector<std::string> roots;
    const char* env = getenv("METAPRO_KEEP_STATIC_ROOTS");
    if (env == nullptr) return roots;
    std::string value(env);
    size_t start = 0;
    while (start <= value.size()) {
        size_t end = value.find(':', start);
        if (end == std::string::npos) end = value.size();
        std::string root = absolutePath(value.substr(start, end - start));
        if (!root.empty()) roots.push_back(root);
        start = end + 1;
    }
    return roots;
}

/* A declaration of the runtime header, so a translation unit that includes it can be told apart */
const char* const INSTRUMENTED_MARKER = "__metapro_func_var_init_c";

class KeepStaticConsumer : public clang::ASTConsumer {
    clang::ASTContext* ctxt = nullptr;
    std::vector<std::string> roots = keptRoots();
    bool instrumented = false;

    /*
        Whether the meta-program instrumented this translation unit, i.e. whether a patch expression can
        run in it. The instrumentation includes the runtime header as the first line of the file, so its
        declarations are in the translation unit before any definition of the file is parsed.
    */
    bool isInstrumentedTU() {
        if (instrumented) return true;
        clang::IdentifierInfo& marker = ctxt->Idents.get(INSTRUMENTED_MARKER);
        instrumented = !ctxt->getTranslationUnitDecl()->lookup(clang::DeclarationName(&marker)).empty();
        return instrumented;
    }

    /* Whether a definition written here is one of the program's own, i.e. one worth keeping */
    bool isKeptFile(clang::SourceLocation loc) const {
        if (loc.isInvalid()) return false;
        const clang::SourceManager& sm = ctxt->getSourceManager();
        // A system header is not the program, and a location the compiler made up has no file at all
        if (sm.isInSystemHeader(loc) || sm.isInSystemMacro(loc)) return false;
        llvm::StringRef file = sm.getFilename(sm.getExpansionLoc(loc));
        if (file.empty()) return false;
        if (roots.empty()) return true; // No roots given: everything that is not a system header
        std::string resolved = absolutePath(file);
        for (const std::string& root : roots) {
            // A root holds a file when the file is it, or lies below it: /a/b is not a root of /a/bc
            if (resolved == root) return true;
            if (resolved.size() > root.size() && resolved.compare(0, root.size(), root) == 0 &&
                    resolved[root.size()] == '/') {
                return true;
            }
        }
        return false;
    }

    void markStatics(clang::Decl* decl) {
        if (auto* func = llvm::dyn_cast<clang::FunctionDecl>(decl)) {
            if (func->isThisDeclarationADefinition() &&
                    func->getStorageClass() == clang::SC_Static &&
                    !func->hasAttr<clang::UsedAttr>() &&
                    isKeptFile(func->getBeginLoc())) {
                func->addAttr(clang::UsedAttr::CreateImplicit(*ctxt));
            }
            return; // A function defined inside another one is out of reach of a patch anyway
        }
        // A declaration holding others, e.g. `extern "C" { ... }` or a namespace
        if (auto* context = llvm::dyn_cast<clang::DeclContext>(decl)) {
            for (clang::Decl* nested : context->decls()) markStatics(nested);
        }
    }

public:
    void Initialize(clang::ASTContext& context) override { ctxt = &context; }

    bool HandleTopLevelDecl(clang::DeclGroupRef declGroup) override {
        if (!isInstrumentedTU()) return true;
        for (clang::Decl* decl : declGroup) markStatics(decl);
        return true;
    }
};

class KeepStaticAction : public clang::PluginASTAction {
public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance&,
            llvm::StringRef) override {
        return std::make_unique<KeepStaticConsumer>();
    }

    bool ParseArgs(const clang::CompilerInstance&, const std::vector<std::string>&) override {
        return true;
    }

    /* Before, so that the attribute is on the declaration by the time CodeGen handles it */
    PluginASTAction::ActionType getActionType() override {
        return PluginASTAction::AddBeforeMainAction;
    }
};

} // namespace

static clang::FrontendPluginRegistry::Add<KeepStaticAction> X("metapro-keep-static",
        "keeping the static functions of the program in the binary, so a patch can call them");
