#pragma once

#ifndef LLVM_ALL_H
#define LLVM_ALL_H

#include "llvm/Pass.h"
#include "llvm/CodeGen/ISDOpcodes.h"

#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/PointerIntPair.h"
#include "llvm/ADT/iterator_range.h"

#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/NoFolder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/User.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Dominators.h"

#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/CodeExtractor.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Scalar.h"
#include "llvm/Transforms/IPO.h"


#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/TargetSelect.h"
#include "llvm/Support/Casting.h"


#include "llvm/PassRegistry.h"
#include "llvm/Passes/PassBuilder.h"


#include <sys/time.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <execinfo.h> 
#include <dlfcn.h>
#include <cxxabi.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <sstream>

#include <iostream>
#include <map>
#include <set>
#include <random>
#include <unordered_set>
#include <vector>
#include <array>
#include <algorithm>
#include <list>
#include <memory>
#include <fcntl.h>
#include <sys/stat.h>
#include <fstream>
#include <cassert>
#include <cstdint>
#include <iterator>

#include <boost/shared_ptr.hpp>
#include <boost/stacktrace.hpp>

#include "json.hpp"

using namespace llvm;
using namespace std;

using json = nlohmann::json;

#endif