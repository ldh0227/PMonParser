#!/usr/bin/python
# -*- encoding: utf-8 -*-
"""
 Cuckoo Sandbox json Report Parser no filter
 @author: Dong-ha, Lee (ldh0227)
 @contact: ldh0227@kaist.ac.kr
 @copyright: All information in this Code belong to the Cyber ​​Security Research Center, Korea Advanced Institute of Science and Technology.
 @license: LGPL
 @summary:
    json type Cuckoo Sandbox Report to CSV format.
    All Event Log base Windows API.
"""
import os
import time
import sys
import json
import unicodecsv

lstSysdir = [
             "\\WINDOWS\\SYSTEM"
             "\\WINDOWS\\SYSTEM32"                                  
             ]

lstProcDA = {
         "PROCESS_TERMINATE":                  0x0001,
         "PROCESS_CREATE_THREAD":              0x0002,
         "PROCESS_SET_SESSIONID":              0x0004,
         "PROCESS_VM_OPERATION":               0x0008,
         "PROCESS_VM_READ":                    0x0010,
         "PROCESS_VM_WRITE":                   0x0020,
         "PROCESS_DUP_HANDLE":                 0x0040,
         "PROCESS_CREATE_PROCESS":             0x0080,
         "PROCESS_SET_QUOTA":                  0x0100,
         "PROCESS_SET_INFORMATION":            0x0200,
         "PROCESS_QUERY_INFORMATION":          0x0400,
         "PROCESS_SUSPEND_RESUME":             0x0800,
         "PROCESS_QUERY_LIMITED_INFORMATION":  0x1000,
         
         "SYNCHRONIZE":     0x00100000
        }

lstFileDA = {
         "GENERIC_READ":        0x80000000,
         "GENERIC_WRITE":       0x40000000,
         "GENERIC_EXECUTE":     0x20000000,
         "GENERIC_ALL":         0x10000000,
        }

def ChkProcOpenDA(strDA):
    strRet = []

    if int(strDA, 16) == 0x001f0fff: # PROCESS_ALL_ACCESS for Windows XP
        strRet.append("PROCESS_ALL_ACCESS")
    # elif int(strDA, 16) == 0x001fffff: # PROCESS_ALL_ACCESS for Windows Vista or Higher
    #    strRet.append("PROCESS_ALL_ACCESS")
    else:
        for curDA in lstProcDA.keys():
            if lstProcDA[curDA] & int(strDA, 16):
                strRet.append(curDA) 
    
    return strRet

def ChkFileOpenDA(strDA):
    strRet = []

    for curDA in lstFileDA.keys():
        if lstFileDA[curDA] & int(strDA, 16):
            strRet.append(curDA) 
    
    return strRet

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python "+__file__+" [Cuckoobox Json Report]")        
    
    strJsonRepoName = sys.argv[1]
    
    try:
        fpInput = open(strJsonRepoName, "r")
    except IOError:
        print("[E] Check "+strJsonRepoName+"file!")
    
    try:
        jsonData = json.load(fpInput)
    except ValueError:
        print("[E] No json Detected!")
        quit()        
    
    strMD5 = jsonData['virustotal']['md5']
    if len(strMD5) != 32:
        strMD5 = jsonData['behavior']['processes'][0]['process_name']
        
    strCBVer = jsonData['info']['version']
        
    # Make Output CSV File
    try:
        fpOutput = open(".\\csv\\PD_MAL_CB_"+strCBVer+"_"+strMD5+".csv", "w")
        print("[I] Output Filename : "+".\\csv\\RAW_CB_"+strCBVer+"_"+strMD5+".csv")
    except IOError:
        print("[E] While Create PD_MAL_"+strMD5+".csv file!")

    csvWriter = unicodecsv.writer(fpOutput, encoding='utf-8')        
        
    iWorkCount = 0
    
    for curProc in jsonData['behavior']['processes']:
        for curCall in curProc['calls']:
            iWorkCount = iWorkCount + 1
            
            # Write Data Initial
            curWork['TimeStamp'] = curCall['timestamp']
            curWork['ProcessName'] = curProc['process_name']
            curWork['PID'] = curProc['process_id']
            curWork['TypeID'] = curCall['api']
            curWork['Arg1'] = ''
            curWork['Arg2'] = ''
            curWork['Arg3'] = ''
            curWork['Arg4'] = ''
            curWork['Arg5'] = ''
            curWork['Arg6'] = ''
            
            
        
    fpInput.close()