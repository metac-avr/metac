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
#pragma once

#include <string>
#include <vector>
#include <set>
#include <map>
#include <sstream>

#include "llvm/Support/raw_ostream.h"

struct SourcePosition {
    const std::string file;
    size_t line;

    SourcePosition(const std::string filename, size_t line_number): file(filename), line(line_number) {}
};

class FaultLocalizer {
public:
    class ResultRecord {
    public:
        int64_t primeScore;
        int64_t secondScore;
        SourcePosition loc;
        uint64_t pid;

        ResultRecord(SourcePosition loc, int64_t primeScore = 1, int64_t secondScore = 0, uint64_t pid = 0):
                        primeScore(primeScore), secondScore(secondScore), loc(loc), pid(pid) {}
    };

protected:
    std::vector<ResultRecord> candidateResults;
    FaultLocalizer() {}

public:
    std::vector<SourcePosition> getCandidateLocations();
    std::vector<ResultRecord> getCandidates(){return candidateResults;}
    virtual void printResult(const std::string &outfile);
};

class GcovFaultLocalizer: public FaultLocalizer {
public:
    GcovFaultLocalizer(const std::string &resultFile);
};

class FunctionFaultLocalizer: public FaultLocalizer {
public:
    FunctionFaultLocalizer(const std::string targetFile, const uint32_t targetLine);
};

class InferFaultLocalizer: public FaultLocalizer {
public:
    InferFaultLocalizer(const std::string &resultPath);
};

class ASTFaultLocalizer: public FaultLocalizer {
public:
    ASTFaultLocalizer(const std::string targetFile, const uint32_t targetLine);
};

/**
 * Fault localizer that just parse FL result file.
 * 
 * File format: <file>:<line>
 * <file> should be relational path from the root directory of the program.
 */
class GeneralFaultLocalizer: public FaultLocalizer {
public:
    GeneralFaultLocalizer(const std::string& resultFile);
};