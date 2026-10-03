#!/usr/bin/env python3

import sys
import subprocess

def test(id:int):
    if id == 0:
        result=subprocess.run("./prog 2", shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode != 0:
            print('0: FAIL')
            return False
        elif result.stdout.decode('utf-8') != '0 1 \n':
            print('0: FAIL')
            return False
        else:
            print('0: PASS')
            return True
    elif id == 1:
        result=subprocess.run("./prog 5", shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode != 0:
            print('1: FAIL')
            return False
        elif result.stdout.decode('utf-8') != '0 1 2 3 4 \n':
            print('1: FAIL')
            return False
        else:
            print('1: PASS')
            return True
    elif id == 2:
        result=subprocess.run("./prog 7", shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        if result.returncode != 0:
            print('2: FAIL')
            return False
        elif result.stdout.decode('utf-8') != '0 1 2 3 4 \n':
            print('2: FAIL')
            return False
        else:
            print('2: PASS')
            return True
        

arg=sys.argv[1:]
res=True
for i in arg:
    res=test(int(i))

if res:
    exit(0)
else:
    exit(1)