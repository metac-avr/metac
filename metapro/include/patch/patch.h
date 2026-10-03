#pragma once

#include <set>
#include <string>
#include <vector>
#include <map>
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"

#include "fl/fl.h"
#include "patch/patch_generator.h"
#include "json/struct_information.h"
#include "json/location_information.h"
#include "json/function_information.h"

static const std::string METAPROGRAM_C_INCLUDE="#include \"_runtime_c.h\"\n";
static const std::string METAPROGRAM_CXX_INCLUDE="#include \"_runtime_cxx.h\"\n";

/* Replace int/uint function call */
static const std::string METAPROGRAM_C_INT_FUNC_PTR_TYPE="__metapro_int_func_type_c";
static const std::string METAPROGRAM_C_UINT_FUNC_PTR_TYPE="__metapro_uint_func_type_c";
static const std::string METAPROGRAM_C_VOID_FUNC_PTR_TYPE="__metapro_void_func_type_c";
static const std::string METAPROGRAM_CXX_INT_FUNC_PTR_TYPE="__metapro_int_func_type_cxx";
static const std::string METAPROGRAM_CXX_UINT_FUNC_PTR_TYPE="__metapro_uint_func_type_cxx";
static const std::string METAPROGRAM_CXX_VOID_FUNC_PTR_TYPE="__metapro_void_func_type_cxx";

/* Marker that this block is added by metapro, not the original source code */
static const std::string METAPROGRAM_C_MARKER="__metapro_mark_block_c";
static const std::string METAPROGRAM_CXX_MARKER="__metapro_mark_block_cxx";

class Generator {
private:
    std::vector<FaultLocalizer::ResultRecord>& flResult;
    std::map<std::string,clang::ASTContext*> ctxts;
    std::map<std::string,clang::SourceManager*> sourceManagers;
    std::set<std::string> patchedFiles;
    std::map<std::string,std::string> sourceCodes;
    std::map<std::string,std::string> tempSourceCodes;
    std::map<std::string,std::vector<std::string>> compileOptions;

    StructInformationFile &structInfoFile;
    LocationInformation &locationInfo;
    TypeInformation &typeInfo;
    VarInformation &varInfo;
    FunctionInformation &functionInfo;
    std::vector<Patch*> generatorHelper(std::vector<std::string> args, std::string fullFilename, std::string filename);
public:
    std::map<std::string, std::map<uint64_t, uint64_t>> jmpIDMaps; // For longjmp for continue/break, map filename to the map of line number to jmpID
    Generator(std::vector<FaultLocalizer::ResultRecord>& flResult,
            StructInformationFile &structInfo, LocationInformation &locationInfo, TypeInformation &typeInfo,
            VarInformation &varInfo, FunctionInformation &functionInfo);
    std::set<std::string> generate();
    std::string getSourceCode(std::string filename);
    clang::ASTContext* getTranslationUnit(std::string filename);
    clang::SourceManager* getSourceManager(std::string filename) {
        return sourceManagers[filename];
    }
};

class PatchWriter {
private:
    std::vector<Patch*> patches;
    std::string filename;
public:
    PatchWriter(std::string filename,std::vector<Patch*> patches): filename(filename),
                    patches(patches) {};
    void write();
};