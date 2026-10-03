#pragma once

#include <string>
#include <map>

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"

int buildProject(std::string sourceDir, std::map<std::string, std::string> &env, std::string output="",
                std::string logFile="build.log",
                bool isMetaprogram=false, bool skipConfigure=false);
int buildWithBear(std::string soureceDir);
int testProject(std::string path, std::map<std::string, std::string> &env, int32_t testId);
