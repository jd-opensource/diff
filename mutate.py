import json5 as json
import random
import math
import os
import subprocess
import ipdb

class Mutate():
    def __init__(self, reinforcename, config="config.json5"):
        self.reinforcename = reinforcename
        self.config = config

        self.preparser_path = None
        self.gdbscript_path = None  

        self.llvm_home = None
        self.clang = None
        self.opt = None
        self.llc = None       
 
        self.plugin_path = None
        self.reinforce_strategies = None
        self.policies = None

        try:
            self.parse_config()
        except Exception as e:
            print("parse json5 config error: %s", e)
            ipdb.post_mortem()
        
        try:
            self.gen_policies()

            self.c2ir("tests/input.c", "tests/input.ll")
            self.collect_meta("tests/input.ll", "tests")

            self.ir2obj("tests/input.ll", "tests/input.o" )
            self.obj2exe("tests/input.o", "tests/a.out")  
       
            self.collect_dynvalue("tests/a.out", "bcftest", "before_dynvalue.json5", "tests/input.json5")
            ############################################################## 
            self.sub_mutate("tests/input.ll", "tests/output.ll")
            self.ir2obj("tests/output.ll", "tests/output.o" )
            self.obj2exe("tests/output.o", "tests/b.out")  
            self.collect_dynvalue("tests/b.out", "bcftest", "after_dynvalue.json5", "tests/input.json5")
        except Exception as e:
            print("get mutate error: %s", e)
            ipdb.post_mortem()

    def parse_config(self):
        with open(self.config, "r", encoding='utf-8') as f:
            json_data = json.load(f)
        
        self.reinforce_strategies = json_data[self.reinforcename]["policies"]
        self.plugin_path = json_data[self.reinforcename]["plugin_path"]
 
        if not os.path.exists(self.plugin_path):
            raise Exception("can't find plugin path for {}".format(self.reinforcename))

        if "llvm_home" in json_data and os.path.exists(json_data["llvm_home"]):
            self.llvm_home = json_data["llvm_home"]
        elif os.environ.get("LLVM_HOME") is not None:
            self.llvm_home = os.environ.get("LLVM_HOME") 
        else:
            raise Exception("get ndk_home error")
         
        #self.llvm_home = "/usr/"
        self.clang = os.path.join(self.llvm_home, "bin/clang")
        if not os.path.exists(self.clang):
            raise Exception("can't find clang in ndk home")

        self.opt = os.path.join(self.llvm_home, "bin/opt")
        if not os.path.exists(self.opt):
            raise Exception("can't find opt in ndk home")

        self.llc = os.path.join(self.llvm_home, "bin/llc")
        if not os.path.exists(self.llc):
            raise Exception("can't find llc in ndk home")

        if not "typeanalysis" in json_data:
            raise Exception("can't find typeanalysis in config.json5")
        elif not os.path.exists(json_data["typeanalysis"]):
            raise Exception("typeanalysis path specify in config.json5 not exist")
        else:
            self.preparser_path = json_data["typeanalysis"]

        if not "gdbscript" in json_data:
            raise Exception("can't find gdbscript in config.json5")
        elif not os.path.exists(json_data["gdbscript"]):
            raise Exception("gdbscript path specify in config.json5 not exist")
        else:
            self.gdbscript_path = json_data["gdbscript"]


    def gen_policies(self):
        # TODO complicate
        choices_num = math.ceil(1.2 * len(self.reinforce_strategies))
        policies = random.choices(self.reinforce_strategies,  k=choices_num)
        self.policies = "-" +  " -".join(policies)


    def c2ir(self, input_c , input_ir):
        cmd = [
            self.clang,
            "-g",
            "-gdwarf-4",
            "-S",
            "-emit-llvm",
            "-fno-discard-value-names",
            input_c,
            "-o",
            input_ir
        ]
        cmd = " ".join(cmd).split(" ")
        subprocess.run(cmd)

    def ir2obj(self, input_ir, input_obj):
        cmd = [
            self.llc, 
            "-filetype=obj", 
            input_ir,
            "-o",
            input_obj
        ]

        cmd = " ".join(cmd).split(" ")
        subprocess.run(cmd)

    def obj2exe(self, input_obj, input_exe):
        cmd = [
            self.clang, 
            input_obj,
            "-o",
            input_exe
        ]

        cmd = " ".join(cmd).split(" ")
        subprocess.run(cmd)

    def collect_meta(self, input_ir, genepath):
        cmd = [
            self.opt,
            "-enable-new-pm=0",
            "-load=" + self.preparser_path,
            "-parser",
            "-S",
            input_ir,
            "-o",
            "tests/tmp.ll",
            "-genepath=" + genepath
        ]
        cmd = " ".join(cmd).split(" ")
        subprocess.run(cmd)

    def collect_dynvalue(self, exefile, debugged_fun, result_file, meta_file):
        cmd = ['gdb',
               '--batch',
               '-ex=py exefile="{}";debugged_fun="{}";result_file="{}";meta_file="{}"'.format(exefile, debugged_fun, result_file, meta_file),
               '-x',
               self.gdbscript_path,
               exefile]
        subprocess.run(cmd)

    def diff(self):
        # TODO
        pass
 
    def sub_mutate(self, input_ir, output_ir):
        cmd = [
            self.opt,
            "-enable-new-pm=0",
            "-load=" + self.plugin_path,
            self.policies,
            "-S",
            input_ir,
            "-o",
            output_ir
        ]
 
        cmd = " ".join(cmd).split(" ")
        subprocess.run(cmd)
        
if __name__ == "__main__":
    try:
        mutate = Mutate("reinforce")
    except Exception as e:
        ipdb.post_mortem()

