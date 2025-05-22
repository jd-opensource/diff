import subprocess

if __name__ == '__main__':
    exefile = "./a.out"
    debugged_fun = "bcftest"
    result_file = "dynvalue.json"
    meta_file = "input.json" 
    command =  ['gdb', 
                '--batch',     
                '-ex=py exefile="{}";debugged_fun="{}";result_file="{}";meta_file="{}"'.format(exefile, debugged_fun, result_file, meta_file),
                '-x', 
                'loadedscript.py', 
                exefile]
    subprocess.run(command)
