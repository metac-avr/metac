#pragma once

#include <string>
#include <boost/filesystem.hpp>

std::string trimPath(std::string str, std::string sub_str);
int32_t copyFile(std::string source, std::string dest);
int32_t removeFile(std::string file);
bool isSystemHeader(const std::string &filename);
bool isCXX(std::string filename);
void copyRecursive(const boost::filesystem::path &src, const boost::filesystem::path &dst);