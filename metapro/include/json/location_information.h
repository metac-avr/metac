#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <set>
#include <fstream>

using json=nlohmann::json;

class LocationInformation {
public:
    struct SourceLocationInfo {
        std::string file;
        uint32_t startLine;
        uint32_t startColumn;
        uint32_t endLine;
        uint32_t endColumn;
        uint64_t jmpId; // For continue/break/goto stmt

        SourceLocationInfo(std::string file, uint32_t startLine, uint32_t startColumn,
                           uint32_t endLine, uint32_t endColumn, uint64_t jmpId) :
            file(file), startLine(startLine), startColumn(startColumn),
            endLine(endLine), endColumn(endColumn), jmpId(jmpId) {}

        bool operator<(const SourceLocationInfo& other) const {
            if (file != other.file) {
                return file < other.file;
            } else if (startLine != other.startLine) {
                return startLine < other.startLine;
            } else {
                return startColumn < other.startColumn;
            }
        }
    };

private:
    json root;
    std::set<SourceLocationInfo> locations;
    std::string jsonFile;

public:
    LocationInformation(std::string outputFile): root(json::array()), jsonFile(outputFile) {}
    void addLocation(const std::string& file, uint32_t startLine, uint32_t startColumn,
                     uint32_t endLine, uint32_t endColumn, uint64_t jmpId) {
        SourceLocationInfo loc(file, startLine, startColumn, endLine, endColumn, jmpId);
        if (locations.find(loc) == locations.end()) {
            locations.insert(loc);
        }
    }

    void store() {
        for (const SourceLocationInfo& loc : locations) {
            json locJson;
            locJson["file"] = loc.file;
            locJson["start_line"] = loc.startLine;
            locJson["start_column"] = loc.startColumn;
            locJson["end_line"] = loc.endLine;
            locJson["end_column"] = loc.endColumn;
            locJson["jmp_id"] = loc.jmpId;
            root.push_back(locJson);
        }
        std::ofstream out(jsonFile);
        out << root.dump(4);
        out.close();
    }
};