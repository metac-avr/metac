#include "utils/path.h"

#include <string>
#include <boost/filesystem.hpp>

std::string trimPath(std::string str, std::string sub_str) {
    if (*sub_str.end()!='/') sub_str+='/';
    std::string ret = str;
    size_t idx = ret.find(sub_str);
    if (idx == std::string::npos) return ret;
    else return ret.substr(idx+sub_str.size());
}

int32_t removeFile(std::string file){
    std::string cmd = "rm -rf "+file;
    return std::system(cmd.c_str());
}

int32_t copyFile(std::string source, std::string dest) {
    std::string cmd = "cp -rf "+source+" "+dest;
    return std::system(cmd.c_str());
}

bool isSystemHeader(const std::string &filename) {
    if (filename.size() < 4) return false;
    else if (filename.substr(filename.size()-2,2)==".h") return true;
    else if (filename.substr(filename.size()-4,4)==".hpp") return true;
    else if (filename.substr(filename.size()-4,4)==".hxx") return true;
    else if (filename.substr(filename.size()-2,2)==".y") return true;
    else if (filename.substr(filename.size()-2,2)==".l") return true;
    return filename.substr(0,4) == "/usr";
}

bool isCXX(std::string filename) {
    return filename.substr(filename.size()-4) == ".cpp" || filename.substr(filename.size()-3) == ".cc" || 
            filename.substr(filename.size()-4) == ".cxx";
}

void copyRecursive(const boost::filesystem::path &src, const boost::filesystem::path &dst)
{
  if (boost::filesystem::exists(dst)){
    throw std::runtime_error(dst.generic_string() + " exists");
  }

  if (boost::filesystem::is_symlink(src)) {
    // Do not copy symlink; usually unnecessary
    return;
  }
  if (boost::filesystem::is_directory(src)) {
    boost::filesystem::create_directories(dst);
    for (boost::filesystem::directory_entry& item : boost::filesystem::directory_iterator(src)) {
      copyRecursive(item.path(), dst/item.path().filename());
    }
  } 
  else if (boost::filesystem::is_regular_file(src)) {
    boost::filesystem::copy(src, dst);
  } 
  else {
    throw std::runtime_error(dst.generic_string() + " not dir or file");
  }
}