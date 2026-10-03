// mutator_launch.cpp — Dyninst-based function replacer, "launch-suspended"
// variant. Use this when the target is a short-lived process (e.g. a
// libxml2 fuzz target that reads one PoC file and exits) instead of a
// long-running server: instead of attaching to an already-running process
// (which requires it to still be alive), THIS mutator owns the process's
// lifecycle — it launches the target itself via Dyninst, which
// forks+execs it and halts it (ptrace-stopped) before any of its own code
// runs. The patch is applied while it's frozen, then it's resumed — so it
// runs to completion already patched. No target source/build changes.
//
// Supports replacing MULTIPLE functions in one launch (needed when a
// dev.patch touches more than one function — replacing only one leaves the
// bug reachable through the others). Each (so, function) pair may point at
// a different .so; a .so repeated across pairs (multiple patched functions
// in the same file) is loaded only once.
//
// Usage:
//   ./mutator_launch <N> <so1> <func1[=newname1]> [<so2> <func2[=newname2]> ...] <target-binary> [args-to-target...]
//
// Examples:
//   ./mutator_launch 1 /path/to/patched.so compute ./toy_vuln
//   ./mutator_launch 2 buf.so xmlBufGrow xmlIO.so xmlParserInputBufferGrow /out/my/xml poc_input
#include "BPatch.h"
#include "BPatch_process.h"
#include "BPatch_image.h"
#include "BPatch_object.h"
#include "BPatch_module.h"
#include "BPatch_function.h"
#include "BPatch_snippet.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

using Clock = std::chrono::steady_clock;
static double ms_since(const Clock::time_point& t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

static void usage(const char* argv0) {
    fprintf(stderr,
        "usage: %s <N> <so1> <func1> [<so2> <func2> ...] <target-binary> [args-to-target...]\n",
        argv0);
}

static std::vector<std::string> split_comma(const char* s) {
    std::vector<std::string> out;
    if (!s) return out;
    std::string cur;
    for (const char* p = s; ; p++) {
        if (*p == ',' || *p == '\0') {
            if (!cur.empty()) out.push_back(cur);
            cur.clear();
            if (*p == '\0') break;
        } else {
            cur.push_back(*p);
        }
    }
    return out;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    int n = atoi(argv[1]);
    if (n <= 0) { usage(argv[0]); return 1; }

    // argv layout: [0]=prog [1]=N  [2 .. 2+2N-1]=(so,func) pairs  [2+2N]=target  [2+2N+1 ..]=target args
    int pairsStart = 2;
    int targetIdx = pairsStart + 2 * n;
    if (argc <= targetIdx) { usage(argv[0]); return 1; }

    struct Patch { std::string so; std::string func; };
    std::vector<Patch> patches;
    for (int i = 0; i < n; i++) {
        patches.push_back({argv[pairsStart + 2*i], argv[pairsStart + 2*i + 1]});
    }
    const char* targetBin = argv[targetIdx];

    std::vector<const char*> targetArgv;
    for (int i = targetIdx; i < argc; i++) targetArgv.push_back(argv[i]);
    targetArgv.push_back(nullptr);

    BPatch bpatch;
    Clock::time_point t_start = Clock::now();

    fprintf(stderr, "[mutator_launch] launching (suspended): %s (%d function replacement(s))\n", targetBin, n);
    BPatch_process* app = bpatch.processCreate(targetBin, targetArgv.data());
    if (!app) {
        fprintf(stderr, "[mutator_launch] FAILED: processCreate\n");
        return 1;
    }
    // processCreate() returns with the process already stopped before its
    // own code runs — no explicit stopExecution() needed here. All the
    // one-time analysis (SymtabAPI/DWARF/ParseAPI CFG construction, over the
    // target binary and everything statically linked into it) happens
    // inside this call: getImage() below is confirmed near-instant (just
    // returns the already-built image), so there's nothing to gain from
    // timing it separately — launch_ms below covers processCreate+getImage
    // together as "the one-time, per-session cost."
    BPatch_image* img = app->getImage();
    double launch_ms = ms_since(t_start);
    Clock::time_point t_patch_start = Clock::now();

    std::map<std::string, BPatch_object*> loadedLibs;  // so path -> loaded object (load each .so once)

    // Optional: MUTATOR_SYNC_GLOBALS=name1,name2,... — file-scope globals
    // (e.g. ZEND_TLS pcre2 contexts in php-src) that the patched function
    // reads/writes. Recompiling the patched file into its own .so gives it
    // its OWN, separately-allocated copy of every such global — the main
    // binary's copy (already initialized by the target's normal one-time
    // module-init code) and the .so's copy (never initialized, since only
    // the main binary's init code ever runs) are different memory. If the
    // replaced function touches one uninitialized, it crashes on unrelated
    // state, not on the bug under test. Fix: snapshot each named global's
    // value from the main binary BEFORE loading any .so (image is
    // unambiguous at that point — only the main binary's objects exist),
    // then after each .so loads, copy that snapshot into the .so's own
    // same-named global so both copies start in sync. No effect unless this
    // env var is set — existing callers are unaffected.
    std::vector<std::string> syncGlobals = split_comma(getenv("MUTATOR_SYNC_GLOBALS"));
    std::map<std::string, std::vector<char>> globalSnapshots;
    for (const auto& name : syncGlobals) {
        BPatch_variableExpr* var = img->findVariable(name.c_str(), false);
        if (!var) {
            fprintf(stderr, "[mutator_launch] WARNING: sync global '%s' not found in main image, skipping\n", name.c_str());
            continue;
        }
        unsigned int size = var->getSize();
        std::vector<char> buf(size);
        if (!var->readValue(buf.data(), (int)size)) {
            fprintf(stderr, "[mutator_launch] WARNING: failed to read sync global '%s' from main image, skipping\n", name.c_str());
            continue;
        }
        unsigned long long hex = 0;
        memcpy(&hex, buf.data(), size < sizeof(hex) ? size : sizeof(hex));
        fprintf(stderr, "[mutator_launch] snapshotted global '%s' (%u bytes) from main image, value=0x%llx\n", name.c_str(), size, hex);
        globalSnapshots[name] = std::move(buf);
    }

    // Every function to replace is looked up in the target BEFORE any patch library is loaded:
    // once libpatch.so is loaded, findFunction() on the whole image also returns the patched copy
    // that libpatch.so itself defines under the same name, and replacing that one too turns the
    // wrapper -> patched function call into an endless loop (seen with patches that touch 2+
    // functions, where the second lookup came after the first library load).
    std::vector<std::vector<BPatch_function*>> oldFuncsPerPatch;
    for (const auto& p0 : patches) {
        std::string name = p0.func;
        size_t eq0 = name.find('=');
        if (eq0 != std::string::npos) name = name.substr(0, eq0);
        std::vector<BPatch_function*> found;
        img->findFunction(name.c_str(), found);
        oldFuncsPerPatch.push_back(std::move(found));
    }

    size_t patchIdx = 0;
    for (const auto& p0 : patches) {
        // A function argument may be "old=new" when the replacement has another name than the
        // function it replaces (the wrapper that keeps libpatch.so's global data in step with the
        // program's); every message below still names the function being replaced.
        Patch p = p0;
        std::string newName = p0.func;
        size_t eq = p0.func.find('=');
        if (eq != std::string::npos) {
            p.func = p0.func.substr(0, eq);
            newName = p0.func.substr(eq + 1);
        }
        std::vector<BPatch_function*>& oldFuncs = oldFuncsPerPatch[patchIdx++];
        if (oldFuncs.empty()) {
            fprintf(stderr, "[mutator_launch] FAILED: old function '%s' not found in target image\n", p.func.c_str());
            return 1;
        }
        fprintf(stderr, "[mutator_launch] found old function '%s' (%zu candidate(s))\n", p.func.c_str(), oldFuncs.size());

        BPatch_object* obj = nullptr;
        auto it = loadedLibs.find(p.so);
        if (it != loadedLibs.end()) {
            obj = it->second;
        } else {
            fprintf(stderr, "[mutator_launch] loading patched library: %s\n", p.so.c_str());
            obj = app->loadLibrary(p.so.c_str());
            if (!obj) {
                fprintf(stderr, "[mutator_launch] FAILED: loadLibrary %s\n", p.so.c_str());
                return 1;
            }
            loadedLibs[p.so] = obj;

            if (!globalSnapshots.empty()) {
                std::vector<BPatch_module*> mods;
                obj->modules(mods);
                for (const auto& kv : globalSnapshots) {
                    BPatch_variableExpr* dst = nullptr;
                    for (BPatch_module* m : mods) {
                        dst = m->findVariable(kv.first.c_str());
                        if (dst) break;
                    }
                    if (!dst) {
                        fprintf(stderr, "[mutator_launch] sync global '%s' not present in %s, skipping\n",
                                kv.first.c_str(), p.so.c_str());
                        continue;
                    }
                    if (!dst->writeValue(kv.second.data(), (int)kv.second.size())) {
                        fprintf(stderr, "[mutator_launch] WARNING: failed to sync global '%s' into %s\n",
                                kv.first.c_str(), p.so.c_str());
                    } else {
                        fprintf(stderr, "[mutator_launch] synced global '%s' into %s\n",
                                kv.first.c_str(), p.so.c_str());
                    }
                }
            }
        }

        std::vector<BPatch_function*> newFuncs;
        obj->findFunction(newName.c_str(), newFuncs);
        if (newFuncs.empty()) {
            fprintf(stderr, "[mutator_launch] FAILED: new function '%s' not found in loaded library\n", newName.c_str());
            return 1;
        }
        BPatch_function* newFunc = newFuncs[0];
        fprintf(stderr, "[mutator_launch] found new function '%s' in loaded library\n", newName.c_str());

        // A name can match more than one function in the target image (e.g. a `static` function
        // compiled into two objects that are both linked in), and findFunction()'s order is not
        // stable between runs. Replacing only the first candidate therefore patched the copy that
        // actually runs in some runs and a dead copy in others, so every candidate is replaced.
        for (size_t k = 0; k < oldFuncs.size(); k++) {
            fprintf(stderr, "[mutator_launch] candidate %zu of '%s' at %p\n", k, p.func.c_str(),
                    oldFuncs[k]->getBaseAddr());
            bool ok = app->replaceFunction(*oldFuncs[k], *newFunc);
            if (!ok) {
                fprintf(stderr, "[mutator_launch] FAILED: replaceFunction for '%s' (candidate %zu)\n",
                        p.func.c_str(), k);
                return 1;
            }
        }
        fprintf(stderr, "[mutator_launch] replaceFunction OK for '%s' (%zu candidate(s) replaced)\n",
                p.func.c_str(), oldFuncs.size());
    }

    double patch_apply_ms = ms_since(t_patch_start);
    fprintf(stderr, "[mutator_launch] all %d replacement(s) OK — resuming target (already patched).\n", n);
    Clock::time_point t_run_start = Clock::now();
    app->continueExecution();

    // Pump Dyninst's event loop until the (now-patched) target exits, so
    // its stdout/stderr/exit code are the real, complete run.
    while (!app->isTerminated()) {
        bpatch.waitForStatusChange();
    }
    double run_ms = ms_since(t_run_start);
    double total_ms = ms_since(t_start);
    fprintf(stderr, "[mutator_launch] target exited (termination status=%d).\n",
            (int)app->terminationStatus());
    fprintf(stderr,
        "[TIMING] launch_ms=%.3f patch_apply_ms=%.3f run_ms=%.3f total_ms=%.3f\n",
        launch_ms, patch_apply_ms, run_ms, total_ms);

    return 0;
}
