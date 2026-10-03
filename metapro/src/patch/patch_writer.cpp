#include "patch/patch.h"
#include "patch/template.h"
#include "patch/patch_generator.h"
#include "config/config.h"
#include "utils/string.h"
#include "utils/path.h"
#include "config/clang_macro.h"

#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/Basic/SourceManager.h"
#include "clang/Basic/SourceLocation.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "spdlog/spdlog.h"
#include <map>
#include <stdexcept>
#include <vector>
#include <string>
#include <fstream>

void PatchWriter::write() {
    for (Patch* patch:patches) {
        if (patch->id == 0) continue; // Skip instrumentation
        // Backup original file
        std::string newFilename=Config::getConfig().outputDirectory+"/patches/"+std::to_string(patch->id)+
                                    "-"+replaceString(filename,"/","#")+"-"+patch->patchTemplate.toString();
        if (isCXX(filename)) newFilename+=".cpp";
        else newFilename+=".c";

        clang::ASTContext* ctxt=patch->ctxt;
        clang::SourceLocation loc;
        clang::Rewriter rewriter(ctxt->getSourceManager(), ctxt->getLangOpts());
        if (patch->patchTemplate == PatchTemplate::REPLACE_CONDITION) {
            ReplaceConditionPatch* replacePatch=(ReplaceConditionPatch*) patch;
            loc=replacePatch->range.getBegin();
            rewriter.ReplaceText(replacePatch->range, replacePatch->patchString);
        }
        else if (patch->patchTemplate == PatchTemplate::INSERT) {
            InsertPatch* insertPatch=(InsertPatch*) patch;
            loc=insertPatch->insertLoc;
            rewriter.InsertTextAfter(loc, insertPatch->patchString);
        }
        else if (patch->patchTemplate == PatchTemplate::INSERT_NOT_NULL_CHECKER) {
            InsertNotNullChecker* insertPatch=(InsertNotNullChecker*) patch;
            loc=insertPatch->insertLoc;
            rewriter.InsertTextAfter(loc, insertPatch->patchString);
        }
        else {
            // Unknown template, error!
            spdlog::error("Unknown template: "+patch->patchTemplate.toString());
            exit(1);
        }

        // Write to file
        clang::SourceManager& sm=ctxt->getSourceManager();
        std::string newCode=rewriter.getRewrittenText(clang::SourceRange(sm.getLocForStartOfFile(sm.getFileID(loc)),
                                                                         sm.getLocForEndOfFile(sm.getFileID(loc))));
        std::ofstream newFile(newFilename.c_str(),std::ofstream::out);
        newFile << newCode;
        newFile.close();
    }
}