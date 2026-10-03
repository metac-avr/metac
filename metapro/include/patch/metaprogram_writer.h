#pragma once

#include "clang/AST/AST.h"

#include "patch/patch.h"
#include "json/location_information.h"

class MetaprogramWriter {
private:
    std::vector<Patch*> patches;
    std::string filename;
    uint64_t patchOffset;

    LocationInformation& locationInfo;
    std::map<uint64_t, uint64_t>& jmpIDs; // For longjmp for continue/break, map line number to jmpID
public:
    MetaprogramWriter(std::string filename, std::vector<Patch*> patches, LocationInformation& locationInfo, std::map<uint64_t, uint64_t>& jmpIDs):
                      filename(filename), patches(patches),patchOffset(0),locationInfo(locationInfo), jmpIDs(jmpIDs) {};
    void write();
};