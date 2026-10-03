#include <string>
#include <map>
#include <spdlog/spdlog.h>
#include <boost/process.hpp>

#include "config/config.h"
#include "utils/project.h"
#include "utils/string.h"

std::map<std::string, std::string> ori_env_map;

void pushEnvMap(const std::map<std::string, std::string> &envMap) {

    ori_env_map.clear();
    for (std::map<std::string, std::string>::const_iterator it = envMap.begin();
            it != envMap.end(); ++it) {
        char *old_v = getenv(it->first.c_str());
        if (old_v != NULL)
            ori_env_map[it->first] = old_v;
        int res = setenv(it->first.c_str(), it->second.c_str(), 1);
    }
}

void popEnvMap(const std::map<std::string, std::string> &envMap) {
    for (std::map<std::string, std::string>::const_iterator it = envMap.begin();
            it != envMap.end(); ++it) {
        int res;
        if (ori_env_map.count(it->first) == 0)
            res = unsetenv(it->first.c_str());
        else
            res = setenv(it->first.c_str(), ori_env_map[it->first].c_str(), 1);
    }
    ori_env_map.clear();
}

int buildProject(std::string sourceDir, std::map<std::string, std::string> &env, std::string output,
                std::string logFile,
                bool isMetaprogram, bool skipConfigure) {
    if (isMetaprogram) {
        env["CC"] = "metapro-tcc";
        env["CXX"] = "metapro-tcxx";
        // env["CC"] = "clang";
        // env["CXX"] = "clang++";
        env["METAPRO_PATH"] = Config::getConfig().metaproPath;
        /* The tree being built is what the keep-static plugin keeps the static functions of, so the
           system headers it also sees stay out of the binary. See src/plugin/keep_static_plugin.cpp */
        env["METAPRO_KEEP_STATIC_ROOTS"] = sourceDir;
    }
    pushEnvMap(env);
    std::string cmd = Config::getConfig().buildCmd;
    size_t pos = cmd.find("<source>");
    if (pos != std::string::npos) {
        cmd = replaceString(cmd, "<source>", sourceDir);
    }
    if (output != "")
        cmd += " -o " + Config::getConfig().outputDirectory + "/" + output + " ";
    if (skipConfigure) {
        cmd += " --skip-configure ";
    }
    else {
        cmd += " -j 10 ";
    }
    cmd += " > "+Config::getConfig().outputDirectory+"/" + logFile + " 2>&1";
    int result= std::system(cmd.c_str());
    popEnvMap(env);
    return result;
}

int buildWithBear(std::string sourceDir) {
    // Check bear version
    boost::process::ipstream verOutput;
    int res=boost::process::system("bear --version", boost::process::std_out > verOutput);
    if (res!=0) {
        spdlog::error("Cannot find bear");
        return 1;
    }
    std::string bearResult;
    std::getline(verOutput,bearResult);
    std::string bearVersion=bearResult.substr(0,bearResult.find(" "));
    if (bearVersion=="bear") {
        bearVersion=bearResult.substr(bearResult.find(" ")+1);
    }

    spdlog::debug("Running bear version {}",bearVersion);
    std::map<std::string,std::string> new_env;
    new_env["CC"] = "clang";
    new_env["CXX"] = "clang++";
    pushEnvMap(new_env);
    std::string cmd = "bear ";
    if (bearVersion[0]=='2')
        cmd += "--cdb ";
    else
        cmd += "--output ";
    cmd += Config::getConfig().workDir+"/compile_commands.json ";
    if (bearVersion[0]=='3')
        cmd += "-- ";
    std::string buildCmd = Config::getConfig().buildCmd;
    if (Config::getConfig().buildCmd.find("<source>")!=std::string::npos) {
        buildCmd = replaceString(buildCmd, "<source>", sourceDir);
    }
    cmd+=buildCmd+" --skip-build-driver -j 10 > "+Config::getConfig().outputDirectory+"/bear.log 2>&1";
    int result= std::system(cmd.c_str());
    popEnvMap(new_env);
    spdlog::debug("Bear finished: {}",result);
    return result;
}

int testProject(std::string path, std::map<std::string, std::string> &env, int32_t testId) {
    pushEnvMap(env);
    std::string cmd = "cd "+path+" && "+Config::getConfig().testCmd+" "+std::to_string(testId);
    int result= std::system(cmd.c_str());
    popEnvMap(env);
    return result;
}