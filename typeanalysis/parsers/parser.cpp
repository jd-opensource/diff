#include "analysis.h"

static cl::opt<string> genepath("genepath", cl::desc("Specify output filename"), cl::Required, cl::init("."));

namespace llvm {
    struct Parser : public ModulePass {
        static char ID;
        bool flag;

        
        TypeAnalysis *analyzer = NULL;

        Parser() : ModulePass(ID) {
            this->flag = false;
        }

        Parser(bool flag) : ModulePass(ID) {
            this->flag = flag;
        }

        std::string readAnnotate(llvm::Function* f){
            std::string annotation = "";
            GlobalVariable *glob = f->getParent()->getGlobalVariable("llvm.global.annotations");
            if (glob != NULL){
                if (ConstantArray *ca = dyn_cast<ConstantArray>(glob->getInitializer())) {
                    for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
                        
                        if (ConstantStruct *structAn = dyn_cast<ConstantStruct>(ca->getOperand(i))) {
                            
                            #if LLVM_VERSION_MAJOR >= 17
                                if (Function *expr = dyn_cast<Function>(structAn->getOperand(0)->stripPointerCasts()  )) {
                                    if (expr == f) {
                                        if(GlobalVariable *annoteStr = dyn_cast<GlobalVariable>(structAn->getOperand(1)->stripPointerCasts() )){
                                            if (ConstantDataSequential *data = dyn_cast<ConstantDataSequential>(annoteStr->getInitializer())) {
                                                if (data->isString()) {
                                                    annotation += data->getAsString().str() + " ";
                                                }
                                            }

                                        }
                                    }
                                }
                            #else
                                if (ConstantExpr *expr = dyn_cast<ConstantExpr>(structAn->getOperand(0))) {
                                    if (expr->getOpcode() == Instruction::BitCast && expr->getOperand(0) == f) {
                                        ConstantExpr *note = cast<ConstantExpr>(structAn->getOperand(1));
                                        if (note->getOpcode() == Instruction::GetElementPtr) {
                                            if (GlobalVariable *annoteStr = dyn_cast<GlobalVariable>(note->getOperand(0))) {
                                                if (ConstantDataSequential *data = dyn_cast<ConstantDataSequential>(annoteStr->getInitializer())) {
                                                    if (data->isString()) {
                                                        annotation += data->getAsString().str() + " ";
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            
                            #endif
                            
                        }
                    }
                }
            }
            return annotation;
        }




        bool toAnalysis(bool flag, llvm::Function *f, std::string attribute) {
            //errs() << "Running toObfuscate On " << attribute << "\n";

            std::string attr = attribute;
            std::string attrNo = "no" + attr;

            if (f->isDeclaration()) {
                return false;
            }

            if(f->hasAvailableExternallyLinkage() != 0) {
                return false;
            }

            std::string annotate = readAnnotate(f);

            if (annotate.find(attrNo) != std::string::npos) {
                return false;
            }

            if (annotate.find(attr) != std::string::npos) {
                return true;
            }

            return flag;

        }

        bool runOnModule(Module &M) override {            
            string modulename =  M.getName().data();

            this->analyzer = new TypeAnalysis();
            
            for (Module::iterator iter = M.begin(); iter != M.end(); iter++) {
                Function* F = &*iter;

                if (!toAnalysis(this->flag,  F, "bcf")) {
                    continue;
                }

                if(F != NULL && F->hasName()){
                }
             
                this->analyzer->analysedfuns.insert(F);
                this->analyzer->curfunction = F;
                this->analyzer->analysis_function(F);
    
            }


            struct stat ss;

            char curfile[1024];
            if (stat(genepath.c_str(), &ss) != 0){
                analysis_error("path %s not exist", genepath.c_str());
            }else if(!S_ISDIR(ss.st_mode)){
                analysis_error("%s is not a directory", genepath.c_str());
            }else{
                sprintf(curfile, "%s/%s.json5", realpath(genepath.c_str(), NULL), cusuffix( basename(M.getName().data()) ));
            }

            this->analyzer->dumps(curfile);

            return true;

        }

        char *cusuffix(const char* myStr) {
            char *retStr;
            char *lastExt;
            if (myStr == NULL) return NULL;
            if ((retStr = (char*)malloc (strlen (myStr) + 1)) == NULL) return NULL;
            strcpy (retStr, myStr);
            lastExt = strrchr (retStr, '.');
            if (lastExt != NULL)
                *lastExt = '\0';
            return retStr;
        }
    };

    Pass *createParserPass(bool flag) {
        return new Parser(flag);
    }
}

char Parser::ID = 0;

static RegisterPass<Parser> X("parser", "function parser");

static void registerParserPass(const PassManagerBuilder &, llvm::legacy::PassManagerBase &PM) {
    PM.add(new Parser(false));
}

static RegisterStandardPasses RegisterMyPass(PassManagerBuilder::EP_EnabledOnOptLevel0, registerParserPass);

