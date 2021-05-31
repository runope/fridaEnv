'''
Author: Runope
Date: 2021-05-31 16:50:17
LastEditors: Runope
LastEditTime: 2021-05-31 16:58:05
Description: run script
contact: runope@qq.com
'''

import os
import sys


srcPath = sys.argv[1]

if __name__ == "__main__":
    os.system('yarn frida-compile src/' + srcPath + '.ts -o dist/_' + srcPath + '.js -w')
    pass