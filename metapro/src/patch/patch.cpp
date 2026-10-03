#include "patch/patch.h"
#include "utils/path.h"
#include "config/config.h"
#include "patch/patch_generator.h"
#include "fl/fl.h"
#include "utils/string.h"
#include "preprocess/preprocessor.h"
#include "preprocess/macro_collector.h"
#include "utils/project.h"
#include "patch/metaprogram_writer.h"

#include "clang/AST/AST.h"
#include "clang/Tooling/Tooling.h"
#include "clang/Frontend/CompilerInvocation.h"
#include "clang/Basic/Diagnostic.h"
#include "spdlog/spdlog.h"
#include <boost/filesystem/convenience.hpp>
#include <fstream>
#include <boost/filesystem.hpp>
#include <iostream>
#include <cctype>
#include <clang/Frontend/ASTConsumers.h>
#include <future>
#include <chrono>

#include <string>
#include <unistd.h>

static std::string readCodeToString(const std::string &file) {
    FILE* f = fopen(file.c_str(), "r");
    if (f == NULL)
        return "";
    char tmp[1024];
    int ret;
    std::string code = "";
    while ((ret = fread(tmp, 1, 1000, f)) != 0) {
        tmp[ret] = 0;
        code += tmp;
    }
    fclose(f);
    return code;
}

bool isMacroWithNumber(std::string name,std::string value) {
    for (char c:name) {
        // Check if name is valid
        if (!isalpha(c) && !isdigit(c) && c!='_') {
            return false;
        }
    }

    for (char c:value) {
        // Check if value is valid
        if (!isdigit(c)) {
            return false;
        }
    }
    return true; // Every chars valid
}

bool isFileBlacklisted(std::string filename) {
    std::set<std::string> blacklist = {
        // ffmpeg
        "libavcodec/aacenc.c", "libavcodec/dpxenc.c", "libavcodec/j2kenc.c", "libavcodec/libvorbisenc.c",
        "libavcodec/lscrdec.c", "libavcodec/mjpegenc_common.c", "libavcodec/mpeg4videoenc.c",
        "libavcodec/opus_parser.c", "libavcodec/opus_silk.c", "libavcodec/h264pred.c", "libavcodec/motion_est.c",
        "libavcodec/vp8dsp.c", "libavcodec/fdctdsp.c", "libavcodec/idctdsp.c", "libavcodec/pixblockdsp.c",
        "libavcodec/rdft.c", "libavcodec/xvididct.c", "libavcodec/h264chroma.c", "libavcodec/h264dsp.c",
        "libavcodec/h264qpel.c", "libavcodec/me_cmp.c", "libavcodec/mpegvideo.c", "libavcodec/mpegvideodsp.c",
        "libavcodec/qpeldsp.c", "libavcodec/vc1dsp.c", "libavcodec/videodsp.c", "libavcodec/wmv2dsp.c",
        "libavcodec/blockdsp.c", "libavcodec/h263dsp.c", "libavcodec/hpeldsp.c", "libavcodec/mpegvideoencdsp.c",
        "libavformat/allformats.c", "libavcodec/bitstream_filters.c", "libavcodec/parsers.c", "libavcodec/cbs.c",
        "libavcodec/lossless_audiodsp.c", "libavcodec/encode.c", "libavcodec/avcodec.c", "libavcodec/lossless_videodsp.c",
        "libavcodec/mpeg12framerate.c", "libavformat/demux.c",
        // gpac
        "src/scene_manager/loader_xmt.c", "src/jsmods/core.c", "src/evg/stencil.c",
        // libxml2
        "xmlschemastypes.c", "xmlschemas.c", "schematron.c",
        // ndpi
        "src/lib/protocols/s7comm.c",
        // php-src
        "ext/opcache/jit/ir/ir_strtab.c",
    };
    if (blacklist.find(filename) != blacklist.end())
        return true;
    else return false;
}

Generator::Generator(std::vector<FaultLocalizer::ResultRecord>& flResult, StructInformationFile &structInfo,
        LocationInformation &locationInfo, TypeInformation &typeInfo, VarInformation &varInfo,
        FunctionInformation &functionInfo):
            flResult(flResult),structInfoFile(structInfo), locationInfo(locationInfo),
            typeInfo(typeInfo),varInfo(varInfo),functionInfo(functionInfo) {
    // Build program with bear to get compile options
    if (!boost::filesystem::exists(Config::getConfig().workDir+"/compile_commands.json")) {
        spdlog::info("Cannot find compile_commands.json in output directory, try to build with bear");
        int res=buildWithBear(Config::getConfig().workDir+"/metapro-source");
        if (res!=0) throw std::runtime_error("Cannot build project with bear");
        else if (!boost::filesystem::exists(Config::getConfig().workDir+"/compile_commands.json")) {
            throw std::runtime_error("Cannot find compile_commands.json in output directory");
        }
    }
    std::ifstream ifs(Config::getConfig().workDir+"/compile_commands.json");

    json root=json::parse(ifs);
    ifs.close();

    for (json entry:root) {
        std::string filename=entry["file"];
        if (filename[0]!='/') {
            // bear 2.x does not store full path
            std::string _temp=entry["directory"];
            filename=_temp+"/"+filename;
        }
        filename = boost::filesystem::path(filename).lexically_normal().string(); // Some system files does not exist to use canonical()
        // Filter out for ffmpeg due to huge project
        if (Config::getConfig().workDir.find("ffmpeg") != std::string::npos) {
            if (filename.find("libavcodec") == std::string::npos &&
                filename.find("libavformat") == std::string::npos &&
                filename.find("libavutil/aes.c") == std::string::npos)
                continue;
            if (filename.find("libavcodec/x86") != std::string::npos)
                continue;
        }
        else if (Config::getConfig().workDir.find("ndpi") != std::string::npos) {
            if (filename.find("third_party") != std::string::npos)
            // Exclude ndpi third party codes
                continue;
            if (Config::getConfig().buildCmd.find("42514313") == std::string::npos && filename.find("fuzz/") != std::string::npos)
                continue;
        }
        else if (Config::getConfig().workDir.find("php-src") != std::string::npos) {
            if (filename.find("ext/opcache/jit/dynasm") != std::string::npos || filename.find("ext/hash/sha3") != std::string::npos)
                continue;
            if (filename.find("gen_ir_fold_hash.c") != std::string::npos)
                continue;
        }
        std::vector<std::string> args;
        for (size_t i=0;i<entry["arguments"].size();i++) {
            if (!endsWith(filename,entry["arguments"][i]) && i!=0 && entry["arguments"][i]!="-c")
                args.push_back(entry["arguments"][i]);
        }
        args.push_back(entry["directory"]);
        compileOptions[filename] = args;

        // Store code
        std::string relativePath=boost::filesystem::relative(filename, Config::getConfig().workDir + "/metapro-source").string();
        if (flResult.size() > 0) {
            // FL: generic
            bool isSuspicious=false;
            for (FaultLocalizer::ResultRecord record:flResult) {
                if (record.loc.file == relativePath) {
                    isSuspicious=true;
                    break;
                }
            }
            if (!isSuspicious) continue;
        }
        if (isSystemHeader(filename) || sourceCodes.find(relativePath) != sourceCodes.end() ||
                isFileBlacklisted(relativePath) || (boost::filesystem::extension(boost::filesystem::path(filename)) != ".c" &&
                boost::filesystem::extension(boost::filesystem::path(filename)) != ".cpp" &&
                boost::filesystem::extension(boost::filesystem::path(filename)) != ".cc")) {
            continue;
        }
        
        if (relativePath[0] == '.' && relativePath[1] == '.')
            continue; // Skip not related to source files
        if (relativePath.find("build") == 0)
            continue; // Skip files generated by build system
        spdlog::debug("Parsing file: "+relativePath);
        std::string code = readCodeToString(filename);
        if (code.rfind(METAPROGRAM_C_INCLUDE, 0) != 0 && code.rfind(METAPROGRAM_CXX_INCLUDE, 0) != 0) {
            if (isCXX(relativePath))
                sourceCodes[relativePath] = METAPROGRAM_CXX_INCLUDE + code;
            else
                sourceCodes[relativePath] = METAPROGRAM_C_INCLUDE + code;
        }
        else {
            sourceCodes[relativePath] = code;
        }
        // Write code to source file
        std::ofstream ofs(filename);
        ofs << sourceCodes[relativePath];
        ofs.close();
    }
}

std::vector<Patch*> Generator::generatorHelper(std::vector<std::string> args, std::string fullFilename, std::string filename) {
    std::string target_dir=args[args.size()-1];
    args.pop_back();
    char* orig_dir=getcwd(nullptr,0);
    chdir(target_dir.c_str());

    // Preprocess source file
    size_t prepos=fullFilename.find_last_of('/');
    args.push_back("-I"+fullFilename.substr(0,prepos));
    if (Config::getConfig().metaproPath!="") {
        args.push_back("-I"+Config::getConfig().metaproPath+"/include");
    }
    else {
        args.push_back("-I/usr/local/include/metapro/include");
    }
    size_t srcDirPos=fullFilename.find_last_of('/');
    if (srcDirPos!=std::string::npos) {
        args.push_back("-I"+fullFilename.substr(0,srcDirPos));
    }
    args.push_back("-Wno-strict-prototypes"); // Silence warnings from runtime library
    std::string code=readCodeToString(fullFilename);
    if (code.rfind(METAPROGRAM_C_INCLUDE, 0) != 0 && code.rfind(METAPROGRAM_CXX_INCLUDE, 0) != 0) {
        if (isCXX(filename)) {
            code = METAPROGRAM_CXX_INCLUDE + code;
        }
        else{
            code = METAPROGRAM_C_INCLUDE + code;
        }
    }

    spdlog::info("Generating patches for file: "+filename);

    // Collect + canonicalize every macro definition (incl. #undef'd and
    // function-like) into a JSON file for later automated patching.
    collectMacrosToJson(code, args, fullFilename,
        Config::getConfig().outputDirectory+"/macros.json");

    std::unique_ptr<clang::ASTUnit> preunit=clang::tooling::buildASTFromCodeWithArgs(
        code,
        args,
        fullFilename
    );
    if (!preunit || preunit->getDiagnostics().hasErrorOccurred()) {
        spdlog::warn("Compilation error while building AST for {}; skipping.", filename);
        chdir(orig_dir);
        free(orig_dir);
        return {};
    }

    copyFile(fullFilename, Config::getConfig().outputDirectory+"/original/__orig_"+replaceString(filename,"/","#"));
    Preprocessor preprocessor(&preunit->getASTContext(),fullFilename,code);
    preprocessor.TraverseDecl(preunit->getASTContext().getTranslationUnitDecl());
    preprocessor.applyPreprocess();
    std::ifstream ifs(fullFilename);
    // Read entire preprocessed code into string
    std::string processedCode((std::istreambuf_iterator<char>(ifs)),(std::istreambuf_iterator<char>()));
    ifs.close();
    tempSourceCodes[filename] = processedCode;
    preunit.reset();

    std::string tempCodePath=Config::getConfig().outputDirectory+"/temp/__temp_"+replaceString(filename,"/","#");

    copyFile(fullFilename,tempCodePath);

    std::unique_ptr<clang::ASTUnit> unit=clang::tooling::buildASTFromCodeWithArgs(
        readCodeToString(tempCodePath),
        args,
        tempCodePath
    );
    if (!unit || unit->getDiagnostics().hasErrorOccurred()) {
        spdlog::warn("Compilation error while rebuilding AST for {}; skipping.", filename);
        chdir(orig_dir);
        free(orig_dir);
        return {};
    }

    clang::ASTContext& ctxt=unit->getASTContext();

    // Collect suspicious line from FL result
    std::vector<unsigned int> suspiciousLines;
    size_t curRank=0;
    for (size_t i=0;i<flResult.size();i++) {
        if (Config::getConfig().maxFLRank>0 && i>=Config::getConfig().maxFLRank) break;
        if (flResult[i].loc.file == filename) {
            suspiciousLines.push_back(flResult[i].loc.line);
            curRank++;
        }
    }
    clang::TranslationUnitDecl* decl=ctxt.getTranslationUnitDecl();
    PatchGenerator pg(&ctxt,suspiciousLines,tempCodePath,filename,unit->getPreprocessor(), structInfoFile, locationInfo, typeInfo, varInfo, functionInfo);
    pg.TraverseDecl(decl);
    ctxts[filename] = &ctxt;
    sourceManagers[filename] = &ctxt.getSourceManager();
    jmpIDMaps[filename] = pg.jmpIDs;

    chdir(orig_dir);
    free(orig_dir);
    // boost::filesystem::remove(tempCodePath);
    std::vector<Patch*> filePatches = pg.getPatches();
    if (filePatches.size() > 0) {
        std::string relativePath=boost::filesystem::relative(fullFilename, Config::getConfig().workDir + "/metapro-source").string();
        if (Config::getConfig().storePatches) {
            PatchWriter writer(relativePath, filePatches);
            writer.write();
        }
        MetaprogramWriter metaproWriter(relativePath, filePatches, locationInfo, pg.jmpIDs);
        metaproWriter.write();
    }
    // delete pg;
    return filePatches;
}

std::set<std::string> Generator::generate() {
    // Generate patches
    std::map<std::string,std::future<std::vector<Patch*>>> futures;
    for (std::pair<std::string,std::string> pair:sourceCodes) {
        if (Config::getConfig().skipCPP && isCXX(pair.first)) {
            // Skip C++ if skip-cpp option is set
            continue;
        }

        std::vector<std::string> args = Config::getConfig().buildOptions;
        std::string fullFilename=Config::getConfig().workDir + "/metapro-source/" + pair.first;
        fullFilename=boost::filesystem::canonical(fullFilename).string();
        if (compileOptions.find(fullFilename)!=compileOptions.end()) {
            for (std::string arg:compileOptions[fullFilename]) {
                if (!(arg.size()>4 && arg[0]!='-' && (arg.substr(arg.size()-2,2)==".c" || arg.substr(arg.size()-4,4)==".cpp" || arg.substr(arg.size()-3,3)==".cc")))
                    args.push_back(arg);
                if (arg=="-D_GLIBCXX_DEBUG" || arg=="-D _GLIBCXX_DEBUG")
                    Config::getConfig().isDebugForCXX=true;
            }
        }
        else {
            spdlog::warn("Cannot find compile options for "+fullFilename+", may be header file?");
            continue;
        }

        // std::future<std::vector<MajorPatch*>> curResult = std::async(std::launch::async, &Generator::generatorHelper, this, args, fullFilename, pair.first);
        // futures[pair.first] = std::move(curResult);
        auto clock = std::chrono::system_clock::now();
        uint64_t startTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(clock.time_since_epoch()).count());
        std::vector<Patch*> patches = generatorHelper(args, fullFilename, pair.first);
        uint64_t execTime = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count()) - startTime;
        Config::getConfig().genTime += execTime;
        if (patches.size() > 0) {
            patchedFiles.insert(pair.first);
            spdlog::info("Found {} patches for {}",patches.size(),pair.first);

            // Delete patches
            for (Patch* patch:patches) {
                delete patch;
            }
        }
    }

    return patchedFiles;
}

std::string Generator::getSourceCode(std::string filename) {
    return tempSourceCodes[filename];
}

clang::ASTContext* Generator::getTranslationUnit(std::string filename) {
    return ctxts[filename];
}