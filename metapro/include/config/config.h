#pragma once

#include <string>
#include <set>
#include <vector>
#include <curl/curl.h>
#include <cstdint>

class Config {
private:
    Config(): patchId(1) {
        curl_global_init(CURL_GLOBAL_ALL);
        curl=curl_easy_init();
        isDebugForCXX=false;
    }
    Config(Config const& ref): patchId(ref.patchId) {}
    Config& operator=(Config const& ref) { return *this; }
    ~Config() {
        curl_easy_cleanup(curl);
        curl_global_cleanup();
    }
public:
    /* Required arguments */
    std::string workDir; // Program root directory
    std::string programId; // Program ID
    std::set<std::string> failingTests; // Failing tests
    std::set<std::string> passingTests; // Passing tests
    std::string buildCmd; // Command for building the program
    std::string testCmd; // Command for testing the program
    std::vector<std::string> buildOptions; // Options to generate the AST

    /* Options */
    bool flRunAllTests; // Run all tests instead of running partial tests during FL 
    std::string outputDirectory; // Output directory
    std::string sourceDir; // Directory to source files
    std::string metaproPath; // Path to metapro root directory
    std::string targetFile; // buggy file to patch
    size_t targetLine; // Buggy line to patch
    bool noCompileMetaprogram; // Do not compile metaprogram
    std::set<std::string> noTemplates; // Ignored templates
    uint32_t maxFLRank; // Maximum FL rank to generate patches
    uint32_t fieldDepth; // Depth of the field to generate field access patches
    uint32_t processId; // ID of this metapro process. It is not a PID!
    bool skipCPP; // Whether to skip C++ files when generating patches
    bool storePatches; // Whether to store per-candidate patched source files under <outputDirectory>/patches

    /* Used during runtime */
    uint64_t patchId = 1;
    CURL *curl;
    bool isDebugForCXX; // Whether the program is compiled in debug mode (-D_GLIBCXX_DEBUG) in C++ to use different runtime library. No effect in C.
    uint64_t genTime = 0; // Time for generating metaprogram (milisecond), except building and bear time
    uint64_t buildTime = 0; // Time for building metaprogram (milisecond), except bear

    static Config& getConfig() {
        static Config config;
        return config;
    }
};
