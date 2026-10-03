// Copyright (C) 2016 Fan Long, Martin Rianrd and MIT CSAIL 
// Prophet
// 
// This file is part of Prophet.
// 
// Prophet is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// Prophet is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with Prophet.  If not, see <http://www.gnu.org/licenses/>.
#include "config/config.h"
#include "fl/fl.h"
#include "utils/path.h"
#include "utils/timer.h"
#include "utils/project.h"
#include "utils/string.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "spdlog/spdlog.h"
#include <nlohmann/json.hpp>

#include <map>
#include <queue>
#include <fstream>
#include <assert.h>
#include <dirent.h>
#include <iostream>
#include <list>
#include <unistd.h>
#include <boost/filesystem.hpp>
#include <string>
#include <cmath>

#define SIGMA 1000000
#define LOC_LIMIT 4980
#define LOC2_LIMIT 20

std::vector<SourcePosition> FaultLocalizer::getCandidateLocations() {
    std::vector<SourcePosition> ret;
    ret.clear();
    for (size_t i = 0; i < candidateResults.size(); i++)
        ret.push_back(candidateResults[i].loc);
    return ret;
}

void FaultLocalizer::printResult(const std::string &outfile) {
    std::ofstream fout(outfile.c_str(), std::ofstream::out);
    assert( fout.is_open() );
    for (size_t i = 0; i < candidateResults.size(); ++i) {
        ResultRecord tmp = candidateResults[i];
        fout << tmp.loc.file << ":" << tmp.loc.line << ":" << tmp.primeScore << ":" << tmp.secondScore << std::endl;
    }
    fout.close();
}

using json=nlohmann::json;

GcovFaultLocalizer::GcovFaultLocalizer(const std::string &resultFile): FaultLocalizer() {
    spdlog::info("Using gcov FL result");
    std::ifstream jsonFile(resultFile.c_str());
    if (!jsonFile.good()) {
        spdlog::error("Cannot open gcov FL result file");
        return; // TODO: temporary change to continue with no FL result. Meta-program will not be generated.
        // exit(1);
    }

    json j=json::parse(jsonFile);
    jsonFile.close();

    for (json& element:j) {
        std::string fileName=element["file"];
        int line=element["line"];
        double score=element["score"];
        SourcePosition loc(fileName,(size_t) line);
        ResultRecord tmp(loc, (int64_t)std::round(score*100000));

        candidateResults.push_back(tmp);
    }
}


InferFaultLocalizer::InferFaultLocalizer(const std::string &resultPath) {
    spdlog::info("Using Infer FL result");
    std::ifstream jsonFile((resultPath+"/report.json").c_str());
    if (!jsonFile.good()) {
        spdlog::error("Cannot open Infer FL result file");
        return;
    }

    json j=json::parse(jsonFile);
    jsonFile.close();

    for (json& element:j) {
        std::string fileName=element["file"];
        if (fileName.find("test")!=std::string::npos) continue; // Ignore test files
        if (Config::getConfig().targetFile!="" && fileName!=Config::getConfig().targetFile)
            continue; // Ignore non-target files if target file is specified but target line is not
        size_t line=element["line"];
        
        SourcePosition loc(fileName, line);
        ResultRecord tmp(loc);

        candidateResults.push_back(tmp);
    }

    if (Config::getConfig().targetFile!="" && Config::getConfig().targetLine!=0){
        SourcePosition loc(Config::getConfig().targetFile,Config::getConfig().targetLine);
        ResultRecord tmp(loc);
        candidateResults.push_back(tmp);
    }
}

GeneralFaultLocalizer::GeneralFaultLocalizer(const std::string& resultFile) {
    spdlog::info("Using generic FL result parser");
    if (!boost::filesystem::exists(resultFile)) {
        spdlog::error("FL result file {} not exist",resultFile);
        return;
    }
    std::ifstream file(resultFile);
    if (!file.good()) {
        spdlog::error("Cannot open FL result file: {}",resultFile);
        return;
    }

    std::vector<std::string> targetFiles;
    if (Config::getConfig().targetFile != "") {
        targetFiles = split(Config::getConfig().targetFile, ',');
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::vector<std::string> tokens = split(line, ':');
        if (targetFiles.size() > 0) {
            bool skip=true;
            for (std::string targetFile : targetFiles) {
                std::string fileName = split(tokens[0],'/').back();
                if (split(targetFile,'/').back() == fileName) {
                    // Skip if target file is specified and this loc is different file
                    skip=false;
                    break;
                }
            }
            if (skip) continue;
        }
        // Ignore some known non-source files in poppler
        if (tokens[0].size() > 9 && tokens[0].substr(0,9) == "freetype2") continue; // Ignore some popper source files
        else if (tokens[0].size() > 6 && tokens[0].substr(tokens[0].size()-6) == ".gperf") continue;
        else if (tokens[0] == "fofi/FoFiIdentifier.cc") continue;
        else if (tokens[0] == "goo/GooString.cc") continue;
        SourcePosition loc(tokens[0], std::stoll(tokens[1]));
        ResultRecord tmp(loc);
        candidateResults.push_back(tmp);
    }
    file.close();
}