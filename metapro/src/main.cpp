#include "llvm/Support/CommandLine.h"
#include "spdlog/spdlog.h"
#include <set>
#include <spdlog/common.h>
#include <string>
#include <boost/filesystem.hpp>
#include <chrono>

#include "fl/fl.h"
#include "patch/patch.h"
#include "patch/patch_generator.h"
#include "config/config.h"
#include "patch/metaprogram_writer.h"
#include "utils/path.h"
#include "utils/string.h"
#include "utils/project.h"
#include "json/struct_information.h"
#include "json/location_information.h"
#include "json/type_information.h"
#include "json/function_information.h"
#include "json/var_information.h"
#include "postprocess/postprocessor.h"

llvm::cl::OptionCategory metaproCategory("metapro options category");

llvm::cl::opt<std::string> workDir(llvm::cl::Positional, llvm::cl::desc("<workdir>"), llvm::cl::Required,
        llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> programId(llvm::cl::Positional, llvm::cl::desc("<prog ID>"),
        llvm::cl::Required, llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> buildCmd(llvm::cl::Positional, llvm::cl::desc("<cmd to build>"),
        llvm::cl::Required, llvm::cl::cat(metaproCategory));

llvm::cl::opt<std::string> outputDir("output-dir", llvm::cl::desc("Output directory. Default is <workdir>/output"), llvm::cl::init("output"),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> runAllTests("fl-all-tests", llvm::cl::desc("Run all passing tests when FL, instead of some of them"), llvm::cl::init(false),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> buildOptions("build-options", llvm::cl::desc("Additional options to build program. Seperated with ','"), llvm::cl::init(""),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> metaproPath("metapro-path", llvm::cl::desc("Path to metapro root directory"), llvm::cl::init(""),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> targetFile("buggy-file", llvm::cl::desc("Buggy file to patch"), llvm::cl::init(""),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<size_t> targetLine("buggy-line", llvm::cl::desc("Buggy line to patch"), llvm::cl::init(0),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> noCompileMetaprogram("no-compile-meta", llvm::cl::desc("Do not compile metaprogram"), llvm::cl::init(false),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> woTemplates("wo-templates",
            llvm::cl::desc("Templates that do not want to generate patches. Seperated with ','"),
            llvm::cl::init(""),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> fl("fl",
            llvm::cl::desc("FL method. Available methods: perfect, generic, all. Default: all"),
            llvm::cl::init("generic"), llvm::cl::cat(metaproCategory));
llvm::cl::opt<uint32_t> maxFLRank("max-fl-rank",
            llvm::cl::desc("Generate patches in top-N locations. Default is 0 (every location)"), llvm::cl::init(0),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<uint32_t> fieldDepth("field-depth",
            llvm::cl::desc("Depth of the fields when using fields for the patches. Default is 2."), llvm::cl::init(2),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> logMode("log-mode",
            llvm::cl::desc("Mode for logging: info, debug. Default: info"), llvm::cl::init("info"),
            llvm::cl::cat(metaproCategory));
llvm::cl::opt<uint32_t> procId("proc-id",
            llvm::cl::desc("Process ID of this process"), llvm::cl::init(0), llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> testCmd("test-cmd", llvm::cl::desc("For gcov FL: command to run each test case. Use '@@' for test case. If '@@' not exist, test case will be provided via stdin."),
        llvm::cl::init(""), llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> failingTests("failing-tests", llvm::cl::desc("For gcov FL: a list of failing tests. Seperated by ','"),
        llvm::cl::init(""), llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> passingTests("passing-tests", llvm::cl::desc("For gcov FL: a list of passing tests. Seperated by ','"),
        llvm::cl::init(""), llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> flFile("fl-file", llvm::cl::desc("For generic FL: result file path from third-party FL tool"),
        llvm::cl::init(""), llvm::cl::cat(metaproCategory));
llvm::cl::opt<std::string> sourceDir("source-dir", llvm::cl::desc("Directory to source files. Default is <workdir>/source."),
        llvm::cl::init("source"), llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> removeSourceAndOutDir("remove-metapro-src-out-dir", llvm::cl::desc("Remove output and source directory of meta-program instead of overwriting"),
        llvm::cl::init(false), llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> buildWithAsan("build-with-asan", llvm::cl::desc("Build metaprogram with ASan"), llvm::cl::init(false), llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> buildWithUBsan("build-with-ubsan", llvm::cl::desc("Build metaprogram with ASan+UBSan"), llvm::cl::init(false), llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> skipCPP("skip-cpp", llvm::cl::desc("Skip C++ files when generating patches"), llvm::cl::init(false), llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> woNopInst("no-nop-inst", llvm::cl::desc("Do not instrument final binary to apply the patch later"), llvm::cl::init(false), llvm::cl::cat(metaproCategory));
llvm::cl::opt<bool> storePatches("store-patches", llvm::cl::desc("Store per-candidate patched source files under <output-dir>/patches. Default: false"), llvm::cl::init(false), llvm::cl::cat(metaproCategory));
llvm::cl::extrahelp moreDesc(
    "\nBuild commaand:\n"
    "    <cmd to build> is the command to build the target program. It should be able to build the program from scratch.\n"
    "    In command, specify <source> for source directory. metapro will copy source to several directory to build in several purposes.\n"
    "    For example in magma benchmarks: python3 path/subject/build.py <source> -o ./metapro-bin -j 10\n"
    "\nHow to use each FL:\n"
    "    - gcov:    Use Gcov to get the coverage and apply spectrum-based FL. Use --test-cmd option to povide the command to run single test case.\n"
    "               It runs failing and passing tests. It needs a lot of time to run tests.\n"
    "               In default, it runs the tests near the failing tests only. To run all passing tests, use --fl-all-tests option.\n"
    "    - func:    Generate patches for every statement in single function. --buggy-file and --buggy-line options required.\n"
    "    - ast:     Analyze AST to get call graph and generate patches for every statement in every function in call graph.\n"
    "               --buggy-file and --buggy-line options required.\n"
    "    - infer:   Generate patches at the location reported by the alarm by infer.\n"
    "               If --buggy-file is specified, generate patches for the specified file.\n"
    "               If --buggy-file and --buggy-line is specified, generate patches for the specified file and line, if alarmed by infer.\n"
    "    - perfect: Generate patches at single provided location. --buggy-file and --buggy-line options required.\n"
    "    - generic: Use FL result generated by third-party FL tool. The format should be the lines of <file>:<line>, where <file> represents relational path to source file from root directory of program.\n"
    "    -          If --buggy-target is specified, generate patches for the specified file.\n"
    "\nSupported patch templates:\n"
    "    - REPLACE_CONDITION:  Replace condition of if, for and while statements.\n"
    "    - INSERT_EXPR:        Smilar as INSERT_RETURN, but insert new expr instead of return statement.\n"
    "    - INSERT_NOT_NULL_CHECKER: Insert if statement and move original statement to then branch of new if statement.\n"
    "\nIn default, every template is enabled. "
);
        
int main(int argc, char const *argv[],char* envp[])
{
    llvm::cl::HideUnrelatedOptions(metaproCategory);
    llvm::cl::ParseCommandLineOptions(argc, argv, "Usage: metapro [options...] <workdir> <prog ID> <cmd to build>\n");

    // init options and args
    if (logMode.getValue()=="info")
        spdlog::set_level(spdlog::level::info);
    else if (logMode.getValue()=="debug")
        spdlog::set_level(spdlog::level::debug);
    else{
        spdlog::error("Unknown log mode: {}",logMode.getValue());
        return 1;
    }
    std::string tempWorkdir=workDir.getValue();
    if (workDir.getValue().back()=='/') {
        tempWorkdir=workDir.getValue().substr(0,workDir.getValue().length()-1);
    }
    if (tempWorkdir.front()=='~') {
        tempWorkdir=replaceString(tempWorkdir,"~",getenv("HOME"));
    }
    else if (tempWorkdir.front()!='/') {
        tempWorkdir=std::string(getenv("PWD"))+"/"+tempWorkdir;
    }
    Config::getConfig().workDir=tempWorkdir;
    spdlog::debug("workDir: {}",Config::getConfig().workDir);
    Config::getConfig().flRunAllTests=runAllTests.getValue();
    spdlog::debug("flRunAllTests: {}",Config::getConfig().flRunAllTests);
    if (buildOptions.getValue()!=""){
        std::string options=buildOptions.getValue();
        while (options.find(",")!=std::string::npos) {
            std::string option=options.substr(0,options.find(","));
            Config::getConfig().buildOptions.push_back("-"+option);
            options=options.substr(options.find(",")+1);
        }
        Config::getConfig().buildOptions.push_back("-"+options);
    }
    spdlog::debug("{} build options",Config::getConfig().buildOptions.size());
    std::string tempOutputDir=outputDir.getValue();
    if (outputDir.getValue().back()=='/') {
        tempOutputDir=outputDir.getValue().substr(0,outputDir.getValue().length()-1);
    }
    if (tempOutputDir.front()=='~') {
        tempOutputDir=replaceString(tempOutputDir,"~",getenv("HOME"));
    }
    else if (tempOutputDir.front()!='/') {
        tempOutputDir=Config::getConfig().workDir+"/"+tempOutputDir;
    }
    Config::getConfig().outputDirectory=tempOutputDir;
    spdlog::debug("outputDirectory: {}",Config::getConfig().outputDirectory);
    std::string tempSourceDir=sourceDir.getValue();
    if (sourceDir.getValue().back()=='/') {
        tempSourceDir=sourceDir.getValue().substr(0,sourceDir.getValue().length()-1);
    }
    if (tempSourceDir.front()=='~') {
        tempSourceDir=replaceString(tempSourceDir,"~",getenv("HOME"));
    }
    else if (tempSourceDir.front()!='/') {
        tempSourceDir=Config::getConfig().workDir+"/"+tempSourceDir;
    }
    Config::getConfig().sourceDir=tempSourceDir;
    spdlog::debug("sourceDir: {}",Config::getConfig().sourceDir);
    Config::getConfig().metaproPath=metaproPath.getValue();
    spdlog::debug("metaproPath: {}",Config::getConfig().metaproPath);
    Config::getConfig().targetFile=targetFile.getValue();
    spdlog::debug("targetFile: {}",Config::getConfig().targetFile);
    Config::getConfig().targetLine=targetLine.getValue();
    spdlog::debug("targetLine: {}",Config::getConfig().targetLine);
    Config::getConfig().noCompileMetaprogram=noCompileMetaprogram.getValue();
    spdlog::debug("noCompileMetaprogram: {}",Config::getConfig().noCompileMetaprogram);
    if (woTemplates.getValue()!="") {
        std::string argv=woTemplates.getValue();
        size_t curPos=argv.find(",");
        while (curPos!=std::string::npos) {
            std::string templateName=argv.substr(0,curPos);
            Config::getConfig().noTemplates.insert(templateName);
            argv=argv.substr(curPos+1);
            curPos=argv.find(",");
        }
        Config::getConfig().noTemplates.insert(argv);
    }
    Config::getConfig().maxFLRank=maxFLRank.getValue();
    spdlog::debug("maxFLRank: {}",Config::getConfig().maxFLRank);
    Config::getConfig().fieldDepth=fieldDepth.getValue();
    spdlog::debug("fieldDepth: {}",Config::getConfig().fieldDepth);
    Config::getConfig().programId=programId.getValue();
    spdlog::debug("programId: {}",Config::getConfig().programId);
    Config::getConfig().buildCmd=buildCmd.getValue();
    spdlog::debug("buildCmd: {}",Config::getConfig().buildCmd);
    Config::getConfig().testCmd=testCmd.getValue();
    spdlog::debug("testCmd: {}",Config::getConfig().testCmd);
    std::string ft=failingTests.getValue();
    spdlog::debug("failingTests: {}",failingTests.getValue());
    size_t curPos=ft.find(",");
    while (curPos!=std::string::npos) {
        std::string testStr=ft.substr(0,curPos);
        Config::getConfig().failingTests.insert(testStr);
        ft=ft.substr(curPos+1);
        curPos=ft.find(",");
    }
    Config::getConfig().failingTests.insert(ft);
    Config::getConfig().processId=procId.getValue();
    spdlog::debug("processId: {}",Config::getConfig().processId);

    std::string pt=passingTests.getValue();
    spdlog::debug("passingTests: {}",passingTests.getValue());
    curPos = pt.find(",");
    while (curPos!=std::string::npos) {
        std::string testStr=pt.substr(0,curPos);
        Config::getConfig().passingTests.insert(testStr);
        pt=pt.substr(curPos+1);
        curPos=pt.find(",");
    }
    Config::getConfig().passingTests.insert(pt);
    Config::getConfig().skipCPP=skipCPP.getValue();
    if (Config::getConfig().skipCPP) {
        spdlog::debug("Skipping C++ files");
    }
    Config::getConfig().storePatches=storePatches.getValue();
    spdlog::debug("storePatches: {}",Config::getConfig().storePatches);

    // Check original source dir exist
    if (!boost::filesystem::exists(boost::filesystem::path(Config::getConfig().sourceDir))) {
        spdlog::error("Source directory does not exist: {}",Config::getConfig().sourceDir);
        return 1;
    }
    boost::filesystem::path outputDirPath(Config::getConfig().outputDirectory);
    boost::filesystem::path sourceDirPath(Config::getConfig().workDir+"/metapro-source");
    if (removeSourceAndOutDir.getValue()) {
        // Force to remove output and meta-program source directory
        if (boost::filesystem::exists(outputDirPath)) {
            boost::filesystem::remove_all(outputDirPath);
        }
        if (boost::filesystem::exists(sourceDirPath)) {
            boost::filesystem::remove_all(sourceDirPath);
        }
    }

    if (!boost::filesystem::exists(outputDirPath)) {
        boost::filesystem::create_directory(outputDirPath);
    }
    if (Config::getConfig().storePatches && !boost::filesystem::exists(Config::getConfig().outputDirectory+"/patches")) {
        boost::filesystem::create_directory(Config::getConfig().outputDirectory+"/patches");
    }
    if (!boost::filesystem::exists(Config::getConfig().outputDirectory+"/original")) {
        boost::filesystem::create_directory(Config::getConfig().outputDirectory+"/original");
    }
    if (!boost::filesystem::exists(Config::getConfig().outputDirectory+"/temp")) {
        boost::filesystem::create_directory(Config::getConfig().outputDirectory+"/temp");
    }
    if (!boost::filesystem::exists(Config::getConfig().outputDirectory+"/variables")) {
        boost::filesystem::create_directory(Config::getConfig().outputDirectory+"/variables");
    }
    // Copy source into metapro source
    if (!boost::filesystem::exists(sourceDirPath)) {
        copyRecursive(boost::filesystem::path(Config::getConfig().sourceDir),sourceDirPath);
    }

    // Restore source files from stored originals
    if (!removeSourceAndOutDir.getValue()) {
        std::string originalDir=Config::getConfig().outputDirectory+"/original";
        if (boost::filesystem::exists(originalDir)) {
            for (const auto& entry: boost::filesystem::directory_iterator(originalDir)) {
                boost::filesystem::path outfilename = entry.path();
                std::string originalFilename = outfilename.string();

                std::string filename=outfilename.filename().string();
                if (filename.substr(0,7)=="__orig_") {
                    filename=replaceString(filename,"#","/");

                    std::string fullName=Config::getConfig().sourceDir + "/" + filename.substr(7);
                    copyFile(originalFilename,fullName);
                    fullName = boost::filesystem::canonical(Config::getConfig().workDir + "/metapro-source/" + filename.substr(7)).string();
                    copyFile(originalFilename,fullName);
                }
            }
        }
    }

    // FL
    spdlog::info("Run FL");
    std::vector<FaultLocalizer::ResultRecord> flResult;
    if (fl.getValue()=="gcov"){
        GcovFaultLocalizer fl(Config::getConfig().workDir+"/fl.json");
        flResult=fl.getCandidates();
    }
    else if (fl.getValue()=="func") {
        if (Config::getConfig().targetFile=="" || Config::getConfig().targetLine==0) {
            spdlog::error("Target file and line are required for function fault localization");
            return 1;
        }
        FunctionFaultLocalizer fl(Config::getConfig().targetFile,Config::getConfig().targetLine);
        flResult=fl.getCandidates();
    }
    else if (fl.getValue()=="perfect") {
        if (Config::getConfig().targetFile=="" || Config::getConfig().targetLine==0) {
            spdlog::error("Target file and line are required for perfect fault localization");
            return 1;
        }
        SourcePosition loc(Config::getConfig().targetFile,Config::getConfig().targetLine);
        FaultLocalizer::ResultRecord record(loc);
        flResult.push_back(record);
    }
    else if (fl.getValue()=="infer") {
        InferFaultLocalizer fl(Config::getConfig().workDir+"/infer-out");
        flResult=fl.getCandidates();
    }
    else if (fl.getValue()=="ast") {
        if (Config::getConfig().targetFile=="" || Config::getConfig().targetLine==0) {
            spdlog::error("Target file and line are required for function fault localization");
            return 1;
        }
        ASTFaultLocalizer fl(Config::getConfig().targetFile,Config::getConfig().targetLine);
        flResult=fl.getCandidates();
    }
    else if (fl.getValue()=="generic") {
        if (flFile=="") {
            spdlog::error("You must provide the result of FL from third-party FL tool with --fl-file to use generic FL.");
            return 1;
        }
        GeneralFaultLocalizer fl(flFile);
        flResult=fl.getCandidates();
    }
    else if (fl.getValue()=="all") {
        flResult.clear();
    }
    else{
        spdlog::error("Unknown FL method: {}",fl.getValue());
        return 1;
    }

    // Generate patches
    spdlog::info("Generate patches");
    StructInformationFile structInfoFile;
    LocationInformation locationInfo(Config::getConfig().outputDirectory+"/location-info.json");
    TypeInformation typeInfo(Config::getConfig().outputDirectory+"/type-info.json");
    VarInformation varInfo(Config::getConfig().outputDirectory+"/variables");
    FunctionInformation functionInfo(Config::getConfig().outputDirectory+"/function-info.json");
    Generator generator(flResult,structInfoFile, locationInfo, typeInfo, varInfo, functionInfo);
    std::set<std::string> patches=generator.generate();

    if (boost::filesystem::exists(boost::filesystem::path(Config::getConfig().workDir+"/metapro-source"))) {
        removeFile(Config::getConfig().workDir+"/metapro-source");
    }
    copyFile(Config::getConfig().sourceDir,Config::getConfig().workDir+"/metapro-source");
    // Store jmpIds to json
    std::map<std::string, std::map<uint64_t, uint64_t>> jmpIds = generator.jmpIDMaps;
    std::string jmpIdFilePath = Config::getConfig().outputDirectory + "/jmp-ids.json";
    nlohmann::json jmpIdJson = nlohmann::json::object();
    for (const auto& filePair : jmpIds) {
        const std::string& filename = filePair.first;
        const std::map<uint64_t, uint64_t>& idMap = filePair.second;
        jmpIdJson[filename] = nlohmann::json::object();
        for (const auto& idPair : idMap) {
            uint64_t line = idPair.first;
            uint64_t id = idPair.second;
            jmpIdJson[filename][std::to_string(line)] = id;
        }
    }
    std::ofstream jmpIdFile(jmpIdFilePath);
    if (!jmpIdFile.is_open()) {
        spdlog::error("Failed to open jmp ID file for writing: {}", jmpIdFilePath);
        return 1;
    }
    jmpIdFile << jmpIdJson.dump(4);
    jmpIdFile.close();

    // Clean build
    uint64_t cleanBuildTime = 0;
    if (!Config::getConfig().noCompileMetaprogram) {
        spdlog::info("Clean build meta-program");
        std::map<std::string, std::string> env;
        if (Config::getConfig().metaproPath!="") {
            env["METAPRO_PATH"]=Config::getConfig().metaproPath;
            env["CC"]=Config::getConfig().metaproPath+"/wrapper/metapro-tcc";
            env["CXX"]=Config::getConfig().metaproPath+"/wrapper/metapro-tcxx";
        }
        else{
            env["CC"] = "metapro-tcc";
            env["CXX"] = "metapro-tcxx";
        }
        if (Config::getConfig().isDebugForCXX) {
            env["METAPRO_DEBUG_MODE"]="1";
        }
            
        env["METAPRO_CC"] = "clang";
        env["METAPRO_CXX"] = "clang++";
        env["CFLAGS"] = "-fno-omit-frame-pointer -ferror-limit=0 -O0 -g";
        env["CXXFLAGS"] = "-fno-omit-frame-pointer -ferror-limit=0 -O0 -g";
        env["LDFLAGS"] = "";
        // env["METAPRO_DEBUG_CC"] = "1";
        if (buildWithAsan.getValue()) {
            spdlog::info("Build with ASAN");
            env["CFLAGS"] += " -fsanitize=address";
            env["CXXFLAGS"] += " -fsanitize=address";
            env["LDFLAGS"] += " -fsanitize=address";
            env["ASAN_OPTIONS"] = "detect_leaks=0";
        }
        if (buildWithUBsan.getValue()) {
            spdlog::info("Build with UBSAN");
            env["CFLAGS"] += " -fsanitize=undefined -fno-sanitize-recover=all";
            env["CXXFLAGS"] += " -fsanitize=undefined -fno-sanitize-recover=all";
            env["LDFLAGS"] += " -fsanitize=undefined";
        }
        // Clean build
        uint64_t startTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        int res=buildProject(Config::getConfig().workDir+"/metapro-source",env,
                            buildWithAsan.getValue() || buildWithUBsan.getValue() ? "asan-bin" : "bin",
                            "clean-build.log", true);
        cleanBuildTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() - startTime;
        if (res!=0) {
            spdlog::error("Clean build meta-program failed");
            return 1;
        }
    }

    // Write patches
    spdlog::info("Write patches");
    for (std::string pair:patches) {
        if (!Config::getConfig().noCompileMetaprogram){
            // Write metaprogram source to source file
            std::string newFilename=Config::getConfig().outputDirectory+"/"+replaceString(pair,"/","#");
            copyFile(newFilename, Config::getConfig().workDir+"/metapro-source/"+pair);

            // Post-process
            // PostProcessor processor(pair.first, locationInfo, generator.jmpIDMaps[pair.first], flResult);
            // processor.startTraverse();
        }
    }

    // Store patch info to file
    structInfoFile.store(Config::getConfig().outputDirectory+"/struct-info.json");
    locationInfo.store();
    typeInfo.store();
    varInfo.store();
    functionInfo.store();

    // Build metaprogram
    if (!Config::getConfig().noCompileMetaprogram) {
        spdlog::info("Build meta-program");
        std::map<std::string, std::string> env;
        if (Config::getConfig().metaproPath!="") {
            env["METAPRO_PATH"]=Config::getConfig().metaproPath;
            env["CC"]=Config::getConfig().metaproPath+"/wrapper/metapro-tcc";
            env["CXX"]=Config::getConfig().metaproPath+"/wrapper/metapro-tcxx";
        }
        else{
            env["CC"] = "metapro-tcc";
            env["CXX"] = "metapro-tcxx";
        }
        if (Config::getConfig().isDebugForCXX) {
            env["METAPRO_DEBUG_MODE"]="1";
        }
            
        env["METAPRO_CC"] = "clang";
        env["METAPRO_CXX"] = "clang++";
        env["CFLAGS"] = "-fno-omit-frame-pointer -ferror-limit=0 -g -O0";
        env["CXXFLAGS"] = "-fno-omit-frame-pointer -ferror-limit=0 -g -O0";
        env["LDFLAGS"] = "";
        if (!woNopInst.getValue()) {
            // env["METAPRO_PASS"] = "1";
            // env["METAPRO_PASS_DIR"] = Config::getConfig().outputDirectory;
            // env["METAPRO_PASS_PATCH_LOC_INFO"] = Config::getConfig().outputDirectory+"/location-info.json";
        }
        if (logMode.getValue() == "debug") {
            env["METAPRO_DEBUG_MODE"]="1";
        }
        if (buildWithAsan.getValue()) {
            env["CFLAGS"] += " -fsanitize=address";
            env["CXXFLAGS"] += " -fsanitize=address";
            env["LDFLAGS"] += " -fsanitize=address";
            env["ASAN_OPTIONS"] = "detect_leaks=0";
        }
        if (buildWithUBsan.getValue()) {
            env["CFLAGS"] += " -fsanitize=undefined -fno-sanitize-recover=all";
            env["CXXFLAGS"] += " -fsanitize=undefined -fno-sanitize-recover=all";
            env["LDFLAGS"] += " -fsanitize=undefined";
        }

        uint64_t startTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        // Build meta-program without clean to compute build time
        int res=buildProject(Config::getConfig().workDir+"/metapro-source",env,
                            buildWithAsan.getValue() || buildWithUBsan.getValue() ? "asan-bin" : "bin",
                            "build-san.log", true, true);
        uint64_t buildTime = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count() - startTime;
        Config::getConfig().buildTime = buildTime;
        if (res!=0) {
            spdlog::error("Build meta-program failed");
            return 1;
        }
        else {
            spdlog::info("Meta-program built!");
        }

        if (buildWithAsan.getValue() || buildWithUBsan.getValue()) {
            spdlog::info("Build meta-program without ASan");
            std::map<std::string, std::string> wo_env;
            if (Config::getConfig().metaproPath!="") {
                wo_env["METAPRO_PATH"]=Config::getConfig().metaproPath;
                wo_env["CC"]=Config::getConfig().metaproPath+"/wrapper/metapro-tcc";
                wo_env["CXX"]=Config::getConfig().metaproPath+"/wrapper/metapro-tcxx";
            }
            else{
                wo_env["CC"] = "metapro-tcc";
                wo_env["CXX"] = "metapro-tcxx";
            }
            if (Config::getConfig().isDebugForCXX) {
                wo_env["METAPRO_DEBUG_MODE"]="1";
            }
                
            wo_env["METAPRO_CC"] = "clang";
            wo_env["METAPRO_CXX"] = "clang++";
            wo_env["CFLAGS"] = "-pthread -ferror-limit=0 -g -O0";
            wo_env["CXXFLAGS"] = "-pthread -ferror-limit=0 -g -O0";
            wo_env["LDFLAGS"] = "-pthread";
            res=buildProject(Config::getConfig().workDir+"/metapro-source",wo_env,"bin", "build-wo-san.log", true);
            if (res!=0) {
                spdlog::error("Build meta-program without ASAN failed");
                return 1;
            }

            // Touch and build patched files again
            for (std::string pair:patches) {
                std::string filepath=Config::getConfig().workDir+"/metapro-source/"+pair;
                boost::filesystem::last_write_time(filepath, std::time(nullptr));
            }

            if (!woNopInst.getValue()) {
                // wo_env["METAPRO_PASS"] = "1";
                // wo_env["METAPRO_PASS_DIR"] = Config::getConfig().outputDirectory;
                // wo_env["METAPRO_PASS_PATCH_LOC_INFO"] = Config::getConfig().outputDirectory+"/location-info.json";
            }
            if (logMode.getValue() == "debug") {
                wo_env["METAPRO_DEBUG_MODE"]="1";
            }
            res=buildProject(Config::getConfig().workDir+"/metapro-source",wo_env,"bin", "build-wo-san-pass.log", true, true);
            if (res!=0) {
                spdlog::error("Build meta-program without ASAN failed");
                return 1;
            }
            else {
                spdlog::info("Meta-program built without ASAN!");
            }
        }
    }

    spdlog::info("Meta-program generated in {} ms", Config::getConfig().genTime);
    spdlog::info("Meta-program clean built in {} ms", cleanBuildTime);
    spdlog::info("Meta-program built in {} ms", Config::getConfig().buildTime);

    return 0;
}
