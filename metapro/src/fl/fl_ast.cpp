#include "fl/fl.h"
#include "config/config.h"
#include "utils/project.h"
#include "utils/path.h"
#include "utils/string.h"

#include <fstream>
#include <spdlog/spdlog.h>

ASTFaultLocalizer::ASTFaultLocalizer(const std::string targetFile, const uint32_t targetLine) {
    spdlog::info("Running AST fault localization");
    std::string workdir=Config::getConfig().workDir;

    if (boost::filesystem::exists(workdir+"/metapro-ast-"+std::to_string(Config::getConfig().processId)+"-source")) {
        boost::filesystem::remove_all(workdir+"/metapro-ast-"+std::to_string(Config::getConfig().processId)+"-source");
    }
    copyRecursive(boost::filesystem::path(Config::getConfig().sourceDir),
                    boost::filesystem::path(workdir+"/metapro-ast-"+std::to_string(Config::getConfig().processId)+"-source"));

    // Run FL
    std::map<std::string, std::string> envMap;
    envMap["CFLAGS"]="-fplugin="+Config::getConfig().metaproPath+"/build/libmetapro-ast-plugin.so";
    envMap["CXXFLAGS"]=envMap["CFLAGS"];
    envMap["CC"]="clang";
    envMap["CXX"]="clang++";
    envMap["METAPRO_AST_FL_TARGET_FILE"]=split(targetFile,'/').back();
    envMap["METAPRO_AST_FL_TARGET_LINE"]=std::to_string(targetLine);
    envMap["METAPRO_AST_FL_OUTPUT_FILE"]=Config::getConfig().outputDirectory+"/ast-fl-collect-"+std::to_string(Config::getConfig().processId)+".txt";

    // Collect call graph
    envMap["METAPRO_AST_FL_MODE"]="collect";
    envMap["METAPRO_AST_FL_TARGET_OUTPUT_FILE"]=Config::getConfig().outputDirectory+"/ast-fl-target-"+std::to_string(Config::getConfig().processId)+".txt";
    boost::filesystem::remove(Config::getConfig().outputDirectory+"/ast-fl-collect-"+std::to_string(Config::getConfig().processId)+".txt");
    int result=buildProject(Config::getConfig().workDir+"/metapro-ast-"+std::to_string(Config::getConfig().processId)+"-source",envMap);
    if (result!=0) {
        spdlog::error("Building program with ast-fl plugin failed with code: {}", result);
        exit(1);
    }

    std::ifstream collect_fin(Config::getConfig().outputDirectory+"/ast-fl-collect-"+std::to_string(Config::getConfig().processId)+".txt");
    if (!collect_fin.good()) {
        spdlog::error("Failed to open ast-fl-collect.txt");
        exit(1);
    }
    std::map<std::string, std::map<std::string, std::vector<std::string>>> callGraph;
    std::string line;
    std::string file;
    std::string curFunc;
    std::string curFile;
    while (std::getline(collect_fin, line)) {
        if (line[0]!='\t') {
            // File
            curFile = line;
            callGraph[curFile] = std::map<std::string, std::vector<std::string>>();
        }
        else if (line[0] == '\t' && line[1] != '\t') {
            // Target file name
            curFunc = line.substr(1);
            callGraph[curFile][curFunc] = std::vector<std::string>();
        }
        else {
            callGraph[curFile][curFunc].push_back(line.substr(2));
        }
    }
    collect_fin.close();

    // Convert
    std::map<std::string, std::map<std::string, std::string>> callers; // {function: {caller, file of caller}}
    for (const auto& [file, funcs] : callGraph) {
        for (const auto& [func, callees] : funcs) {
            for (const auto& callee : callees) {
                if (callGraph.count(callee) == 0) {
                    callers[callee] = std::map<std::string, std::string>();
                }
                callers[callee][func] = file;
            }
        }
    }

    std::ifstream target_fin(Config::getConfig().outputDirectory+"/ast-fl-target-"+std::to_string(Config::getConfig().processId)+".txt");
    std::string temp_func;
    std::getline(target_fin, temp_func);
    target_fin.close();

    std::vector<std::string> curFuncs;
    curFuncs.push_back(temp_func);
    std::set<std::pair<std::string, std::string>> targetFuncs;
    for (uint32_t i=0;i<3;i++) {
        std::vector<std::string> cur_callers;
        for (std::string caller:curFuncs) {
            if (callers.find(caller)!=callers.end()) {
                cur_callers.push_back(caller);
                for (std::map<std::string, std::string>::value_type next_caller:callers[caller]) {
                    targetFuncs.insert(std::make_pair(next_caller.first, next_caller.second));
                }
            }
        }
        curFuncs = cur_callers;
    }

    // Run with call graph
    std::ofstream target_of(Config::getConfig().outputDirectory+"/ast-fl-funcs-"+std::to_string(Config::getConfig().processId)+".txt");
    for (std::pair<std::string, std::string> func:targetFuncs) {
        target_of << func.second << ":" << func.first << std::endl; // file, func
    }
    target_of << targetFile << ":" << temp_func << std::endl;
    target_of.close();
    envMap["METAPRO_AST_FL_MODE"]="fl";
    envMap["METAPRO_AST_FL_OUTPUT_FILE"]=Config::getConfig().outputDirectory+"/ast-fl-result-"+std::to_string(Config::getConfig().processId)+".txt";
    envMap["METAPRO_AST_FL_INPUT_FILE"]=Config::getConfig().outputDirectory+"/ast-fl-funcs-"+std::to_string(Config::getConfig().processId)+".txt";
    boost::filesystem::remove(Config::getConfig().outputDirectory+"/ast-fl-result.txt");
    result=buildProject(Config::getConfig().workDir+"/metapro-ast-"+std::to_string(Config::getConfig().processId)+"-source", envMap);
    if (result!=0) {
        spdlog::error("Building program with ast-fl plugin failed with code: {}", result);
        exit(1);
    }
    spdlog::debug("Build program with ast-fl mode");
    std::ifstream fin(Config::getConfig().outputDirectory+"/ast-fl-result-"+std::to_string(Config::getConfig().processId)+".txt");
    if (!fin.good()) {
        spdlog::error("Failed to open ast-fl-result.txt");
        exit(1);
    }
    std::vector<std::pair<std::string,uint32_t>> lines;
    while (!fin.eof()) {
        std::string file;
        uint32_t line;
        std::getline(fin, file);
        if (file.empty()) continue;
        size_t index=file.find(":");
        line=std::stoi(file.substr(index+1));
        file=file.substr(0,index);
        lines.push_back(std::make_pair(file, line));
    }
    fin.close();
    spdlog::debug("Total lines: {}",lines.size());

    for (uint32_t i=0;i<lines.size();i++) {
        std::string file=lines[i].first;
        uint32_t index=file.find("metapro-ast-"+std::to_string(Config::getConfig().processId)+"-source");
        file=file.substr(index+20+std::to_string(Config::getConfig().processId).size());
        SourcePosition loc(file,lines[i].second);
        ResultRecord record(loc);
        candidateResults.push_back(record);
    }
}