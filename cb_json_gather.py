#!/usr/bin/python
# -*- encoding: utf-8 -*-
"""
 Cuckoo Sandbox json Report Gatther
 @author: Dong-ha, Lee (ldh0227)
 @contact: ldh0227@kaist.ac.kr
 @copyright: All information in this Code belong to the Cyber ​​Security Research Center, Korea Advanced Institute of Science and Technology.
 @license: LGPL
 @summary:
    report.json file to ./output/(BIANRY_MD5)_cb(CUCKOO_VERSION).json
"""
import os
import time
import sys
import json
import shutil
import fnmatch

def locate(pattern, root=os.curdir):
    '''Locate all files matching supplied filename pattern in and below
    supplied root directory.'''
    for path, dirs, files in os.walk(os.path.abspath(root)):
        for filename in fnmatch.filter(files, pattern):
            yield os.path.join(path, filename)

if __name__ == "__main__":    
    lstRoot = [
               "/home/csrc/cuckoo-0.5/storage/analyses/", # Cuckoo 0.5 Storage Path
               "/home/csrc/cuckoo_0.6/storage/analyses/"  # Cuckoo 0.6 Storage Path
               ]
    
    iWorkCount = 0
    
    for strRoot in lstRoot:
        for strJsonRepoName in locate("report.json", strRoot):
            iWorkCount = iWorkCount + 1
            print str(iWorkCount) + " Working on "+strJsonRepoName+" ...",
            
            try:
                fpInput = open(strJsonRepoName, "r")
            except IOError:
                print("[E] Check "+strJsonRepoName+"file!")
                quit()
            
            try:
                jsonData = json.load(fpInput)
            except ValueError:
                print("[E] No json Detected!")
                quit() 
            
            try:    
                strMD5 = jsonData['virustotal']['md5']
                if len(strMD5) != 32:
                    strMD5 = jsonData['behavior']['processes'][0]['process_name']
            except:
                strMD5 = jsonData['behavior']['processes'][0]['process_name']
                
            strCBVer = jsonData['info']['version']
                
            fpInput.close()
            
            shutil.copyfile(strJsonRepoName, "./output/"+strMD5.lower()+"_cb"+strCBVer+".json")
    
            print " done!"
            