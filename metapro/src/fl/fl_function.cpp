#include "fl/fl.h"
#include "config/config.h"
#include "utils/project.h"
#include "utils/path.h"
#include "utils/string.h"

#include <fstream>
#include <spdlog/spdlog.h>

FunctionFaultLocalizer::FunctionFaultLocalizer(const std::string targetFile, const uint32_t targetLine) {
    spdlog::info("Running function fault localization");
    std::string workdir=Config::getConfig().workDir;

    if (boost::filesystem::exists(workdir+"/metapro-func-"+std::to_string(Config::getConfig().processId)+"-source")) {
        boost::filesystem::remove_all(workdir+"/metapro-func-"+std::to_string(Config::getConfig().processId)+"-source");
    }
    copyRecursive(boost::filesystem::path(Config::getConfig().sourceDir),
                    boost::filesystem::path(workdir+"/metapro-func-"+std::to_string(Config::getConfig().processId)+"-source"));

    // Run FL
    std::map<std::string, std::string> envMap;
    envMap["CFLAGS"]="-fplugin="+Config::getConfig().metaproPath+"/build/libmetapro-func-finder.so";
    envMap["CXXFLAGS"]=envMap["CFLAGS"];
    envMap["CC"]="clang";
    envMap["CXX"]="clang++";
    envMap["METAPRO_FUNC_FINDER_TARGET_FILE"]=split(targetFile,'/').back();
    envMap["METAPRO_FUNC_FINDER_TARGET_LINE"]=std::to_string(targetLine);
    envMap["METAPRO_FUNC_FINDER_OUTPUT_FILE"]=Config::getConfig().outputDirectory+"/func-result-"+std::to_string(Config::getConfig().processId)+".txt";
    int result=buildProject(Config::getConfig().workDir+"/metapro-func-"+std::to_string(Config::getConfig().processId)+"-source", envMap);
    if (result!=0) {
        spdlog::error("Building program with func-finder plugin failed with code: {}", result);
        exit(1);
    }
    spdlog::debug("Build program with func-find mode");
    std::ifstream fin(Config::getConfig().outputDirectory+"/func-result-"+std::to_string(Config::getConfig().processId)+".txt");
    if (!fin.good()) {
        spdlog::error("Failed to open func-result.txt");
        exit(1);
    }
    uint32_t beginLine,endLine;
    fin >> beginLine >> endLine;
    fin.close();
    spdlog::debug("Begin line: {}, end line: {}",beginLine,endLine);

    for (uint32_t i=beginLine;i<=endLine;i++) {
        SourcePosition loc(targetFile,i);
        ResultRecord record(loc);
        candidateResults.push_back(record);
    }
}