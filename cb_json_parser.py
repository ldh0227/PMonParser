#!/usr/bin/python
# -*- encoding: utf-8 -*-

import time
import sys
import json
import unicodecsv

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
    
    # Set Flag Array for Match Feature Count    
    flagFeatFound = []    
    for i in range(31):
        flagFeatFound.append(False)
    
    lstFeatAPI = [["NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess", "NTCreateProcessInternalW", "ShellExecuteExW", "CreateRemoteThread"],
                  ["NtTerminateProcess"],
                  ["NtOpenProcess"],
                  ["ReadProcessMemory", "NtReadVirtualMemory"],
                  ["NtWriteVirtualMemory", "WriteProcessMemory"],
                  ["bind", "listen"],
                  ["InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW", "InternetReadFile"],
                  ["FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW"],
                  ["NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess", "NTCreateProcessInternalW", "ShellExecuteExW", "CreateRemoteThread"],
                  ["NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess", "NTCreateProcessInternalW", "ShellExecuteExW", "CreateRemoteThread"],
                  ["LdrLoadDll"],
                  ["NtCreateFile", "NtOpenFile"],
                  ["NtCreateMutant"],
                  ["bind", "listen"],
                  ["NtCreateFile"],
                  ["MoveFileWithProgressW", "CopyFileA", "CopyFileW", "CopyFileExW"],
                  ["DeleteFileA", "DeleteFileW"],
                  ["NtCreateFile"],
                  ["NtCreateFile"],
                  ["FindFirstFileExA", "FindFirstFileExW"],
                  ["NtCreateFile"],
                  ["NtCreateFile"],
                  ["NtCreateFile"],
                  ["NtCreateFile"],
                  ["CreateServiceA", "CreateServiceW", "NtCreateKey"],
                  ["DeleteService"],
                  ["NtSetValueKey"],
                  ["NtSetValueKey"],
                  ["NtSetValueKey"],
                  ["NtSetValueKey"],
                  ["NtSetValueKey"], ]
    
    strMD5 = jsonData['virustotal']['md5']
    if len(strMD5) != 32:
        strMD5 = jsonData['behavior']['processes'][0]['process_name']
        
    strCBVer = jsonData['info']['version']
        
    # Make Output CSV File
    try:
        fpOutput = open(".\\csv\\PD_MAL_CB_"+strCBVer+"_"+strMD5+".csv", "w")
    except IOError:
        print("[E] While Create PD_MAL_"+strMD5+".csv file!")

    csvWriter = unicodecsv.writer(fpOutput, encoding='utf-8')        
    
    # csvWriter.writerow([iWorkCount, 1, strUser, strDateTime, strProcName, strPID, strTypeID, strCont1, strCont2, strCont3, strCont4, strCont5, strCont6])
    # csvWriter.writerow(["Log IDX", "Host IDX", "Username", "Timestamp", "Process Name", "ProcessID", "FeatureID", "API", "ThreadID", "Arguments"])
    
    iWorkCount = 0
    
    curWork = {}
    
    # Make Process Information for Log Wide.
    ProcessInfos = {}
    ProcHandleInfos = {}
    FileHandleInfos = {}
    
    for curProc in jsonData['behavior']['processes']:
        ProcessInfos[curProc['process_id']] = curProc['process_name']
        ProcessInfos[str(curProc['process_id'])+"_pid"] = curProc['parent_id']
        ProcHandleInfos[curProc['process_id']] = {}
        FileHandleInfos[curProc['process_id']] = {}
    
    try:    
        for curProc in jsonData['behavior']['processes']:
            for curCall in curProc['calls']:
                iFeatIdx = 0
                for curFeatAPI in lstFeatAPI:
                    iFeatIdx = iFeatIdx + 1
                    try:
                        curFeatAPI.index(curCall['api'])
                    except ValueError:                    
                        continue
                    
                    curWork['iFeatIdx'] = iFeatIDx
                    
                    if iFeatIdx == 1:
                        if curCall['api'].find('NtCreateProcess') != -1:
                            curWork['Arg1'] = curCall['arguments']['Filename']
                        elif curCall['api'] == 'NtCreateUserProcess':
                            print "do something"
                        elif curCall['api'] == 'NtCreateProcessInternalW':
                            print "do something"
                        elif curCall['api'] == 'ShellExecuteExW':
                            print "do something"
                        elif curCall['api'] == 'CreateRemoteThread':
                            print "do something"
                    elif iFeatIdx == 2:
                        print "do something"
                    elif iFeatIdx == 3:
                        print "do something"
                    elif iFeatIdx == 4:
                        print "do something"
                    elif iFeatIdx == 5:
                        print "do something"
                    elif iFeatIdx == 6:
                        print "do something"
                    elif iFeatIdx == 7:
                        print "do something"
                    elif iFeatIdx == 8:
                        print "do something"
                    elif iFeatIdx == 9:
                        print "do something"
                    elif iFeatIdx == 10:
                        print "do something"
                    elif iFeatIdx == 11:
                        print "do something"
                    elif iFeatIdx == 12:
                        print "do something"
                    elif iFeatIdx == 13:
                        print "do something"
                    elif iFeatIdx == 14:
                        print "do something"
                    elif iFeatIdx == 15:
                        print "do something"
                    elif iFeatIdx == 16:
                        print "do something"
                    elif iFeatIdx == 17:
                        print "do something"
                    elif iFeatIdx == 18:
                        print "do something"
                    elif iFeatIdx == 19:
                        print "do something"
                    elif iFeatIdx == 20:
                        print "do something"
                    elif iFeatIdx == 21:
                        print "do something"
                    elif iFeatIdx == 22:
                        print "do something"
                    elif iFeatIdx == 23:
                        print "do something"
                    elif iFeatIdx == 24:
                        print "do something"
                    elif iFeatIdx == 25:
                        print "do something"
                    elif iFeatIdx == 26:
                        print "do something"
                    elif iFeatIdx == 27:
                        print "do something"
                    elif iFeatIdx == 28:
                        print "do something"
                    elif iFeatIdx == 29:
                        print "do something"
                    elif iFeatIdx == 30:
                        print "do something"
                    elif iFeatIdx == 31:
                        print "do something"
                        
                    iWorkCount = iWorkCount + 1
                    #csvWriter.writerow([iWorkCount, 1, "csrc", curCall['timestamp'], curProc['process_name'], curProc['process_id'], iFeatIdx, curCall['api'], curCall['thread_id'], curCall['arguments']])                    
                    
                    flagFeatFound[iFeatIdx-1] = True
    except ValueError:
        print("[E] This log doesn't have Behavior Log!")
        
    fpInput.close()

    print "[F] All Matched Feature Count : "+str(flagFeatFound.count(True))
    strMatched = ""
    iMatchedIdx = 0
    for iMatched in flagFeatFound:
        iMatchedIdx = iMatchedIdx + 1
        if iMatched == True:
            strMatched = strMatched + str(iMatchedIdx) + ", "
    print "[F] Matched Feature Index : "+strMatched