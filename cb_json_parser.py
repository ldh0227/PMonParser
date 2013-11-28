#!/usr/bin/python
# -*- encoding: utf-8 -*-
"""
 Cuckoo Sandbox json Report Parser
 @author: Dong-ha, Lee (ldh0227)
 @contact: ldh0227@kaist.ac.kr
 @copyright: All information in this Code belong to the Cyber ​​Security Research Center, Korea Advanced Institute of Science and Technology.
 @license: LGPL
 @summary:
    json type Cuckoo Sandbox Report to CSV format.
    Not all Event Log. Only 31 Category with some Windows API
"""
import os
import time
import sys
import json
import unicodecsv
import find_fake

lstSysdir = [
             "\\WINDOWS\\SYSTEM"
             "\\WINDOWS\\SYSTEM32"                                  
             ]

lstDA = {             
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

lstDA = {             
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
        for curDA in lstDA.keys():
            if lstDA[curDA] & int(strDA, 16):
                strRet.append(curDA) 
    
    return strRet

def ChkFileOpenDA(strDA):
    strRet = []

    for curDA in lstDA.keys():
        if lstDA[curDA] & int(strDA, 16):
            strRet.append(curDA) 
    
    return strRet

def isSystemDir(strPath):
    bRet = False
        
    lstDir = os.path.splitdrive(strPath)
    tmpDir = lstDir[1]
    
    for curSysdir in lstSysdir:
        if tmpDir == lstSysdir:
            bRet = True
            break
    
    return bRet

def isContainSystemDir(strPath):
    bRet = False
    
    lstDir = os.path.splitdrive(strPath)
    tmpDir = lstDir[1]
    
    for curSysdir in lstSysdir:
        if tmpDir.find(lstSysdir) == 0:
            bRet = True
            break
    
    return bRet

def isHostsPath(strPath):
    bRet = ""
    
    # for Linux
    if strPath == "/etc":
        bRet = "Linux"
    
    # for Windows 95, 98, 98SE, ME
    elif os.path.splitdrive(strPath)[1].upper() == "\\WINDOWS":
        bRet = "Win9x"
    
    # NT Base 32bit (NT, 2000, XP 32bit, 2003, Vista, 7, 8)
    elif os.path.splitdrive(strPath)[1].upper() == "\\WINDOWS\\SYSTEM\\DRIVERS\\ETC":
        bRet = "Win32"
    
    # NT Base 64bit (NT, 2000, XP 32bit, 2003, Vista, 7, 8)
    elif os.path.splitdrive(strPath)[1].upper() == "\\WINDOWS\\SYSWOW64\\DRIVERS\\ETC":
        bRet = "Win64"
        
    return bRet

def isTempDir(strPath):
    bRet = False
    
    if strPath.upper().find("\\TEMP\\") != -1:        
        bRet = True
    
    return bRet
    
def isInetTempDir(strPath):
    bRet = False
    
    if strPath.upper().find("\\TEMPORARY INTERNET FILES\\") != -1:
        bRet = True
    
    return bRet

def isExecFile(strPath):
    bRet = False
    
    strExt = os.path.splitext(strPath)[1].upper()
    
    lstExec = ["EXE", "DLL", "SYS", "SCR", "TMP"]
    
    for curExec in lstExec:
        if strExt == curExec:
            bRet = True

    return bRet

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
    
    lstFeatAPI = [["CreateProcessInternalW", "ShellExecuteExW"],
                  ["NtTerminateProcess"],
                  ["NtOpenProcess"],
                  ["ReadProcessMemory", "NtReadVirtualMemory"],
                  ["NtWriteVirtualMemory", "WriteProcessMemory"],
                  ["bind", "listen"],
                  ["URLDownloadToFileW", "InternetConnectA", "InternetConnectW", "InternetOpenUrlA", "InternetOpenUrlW", "HttpOpenRequestA", "HttpOpenRequestW", "connect", "send"],
                  ["FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW"],
                  ["CreateProcessInternalW", "ShellExecuteExW"],
                  ["CreateProcessInternalW", "ShellExecuteExW"],
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
    BindHandleInfos = {}
    InetHandleInfos = {}
    
    for curProc in jsonData['behavior']['processes']:
        ProcessInfos[curProc['process_id']] = curProc['process_name']
        ProcessInfos[str(curProc['process_id'])+"_pid"] = curProc['parent_id']
        ProcHandleInfos[curProc['process_id']] = {}
        FileHandleInfos[curProc['process_id']] = {}
        InetHandleInfos[curProc['process_id']] = {}
    
    csvWriter.writerow([ProcessInfos])
    
    try:    
        for curProc in jsonData['behavior']['processes']:
            ProcHandleInfos[curProc['process_id']] = {}
            curProcHandleTable = ProcHandleInfos[curProc['process_id']]
            curFileHandleTable = FileHandleInfos[curProc['process_id']]
            curBindHandleTable = BindHandleInfos[curProc['process_id']]
            curInetHandleTable = InetHandleInfos[curProc['process_id']]
            curProcTasksCount = 0
            
            for curCall in curProc['calls']:
                iFeatIdx = 0
                                
                # If Handle Close be needed
                # if curCall['api'] = "NtClose":                    
                #     curProcHandleTable.pop(curCall['arguments'][0]['value'])
                #     curFileHandleTable.pop(curCall['arguments'][0]['value'])
                
                for curFeatAPI in lstFeatAPI:
                    iFeatIdx = iFeatIdx + 1
                    try:
                        curFeatAPI.index(curCall['api'])
                    except ValueError:                    
                        continue
                    
                    # Write Data Initial
                    curWork['TimeStamp'] = curCall['timestamp']
                    curWork['ProcessName'] = curProc['process_name']
                    curWork['PID'] = curProc['process_id']                    
                    curWork['TypeID'] = iFeatIdx
                    curWork['Arg1'] = ''
                    curWork['Arg2'] = ''
                    curWork['Arg3'] = ''
                    curWork['Arg4'] = ''
                    curWork['Arg5'] = ''
                    curWork['Arg6'] = ''                    
                    
                    if iFeatIdx == 1:
                        # When Other Process Create Event occur                    
                        if curCall['api'] == 'CreateProcessInternalW':
                            if curCall['status'] == "SUCCESS":
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                
                                # Process Handle Table Setting 
                                # Set Arg2 from Process Name
                                try:
                                    curProcHandleTable[curCall['arguments'][5]['value']] = ProcessInfos[curCall['arguments'][3]['value']]
                                    curWork['Arg2'] = "ProcName: "+ProcessInfos[curCall['arguments'][3]['value']]
                                except:
                                    if curCall['arguments'][0]['value'] != "":
                                        curProcHandleTable[curCall['arguments'][5]['value']] = str(curCall['arguments'][0]['value'])
                                        curWork['Arg2'] = "ProcName: "+curCall['arguments'][0]['value']
                                    else:
                                        curProcHandleTable[curCall['arguments'][5]['value']] = str(curCall['arguments'][1]['value'])
                                        curWork['Arg2'] = "ProcNameFromCmdLine: "+curCall['arguments'][1]['value']
                                
                                # Set Arg3 from Child Process PID
                                curWork['Arg3'] = "ChildPID: "+str(curCall['arguments'][3]['value'])
                                
                                # Set Arg4 from Process Command Line
                                curWork['Arg4'] = "CmdLine: "+str(curCall['arguments'][1]['value'])                                
                                                                    
                        elif curCall['api'] == 'ShellExecuteExW':
                            if curCall['status'] == "SUCCESS":
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                
                                # Set Arg1 from Process Name for Path!
                                curWork['Arg2'] = curCall['arguments'][0]['value']
                                
                                # Get basename(filename) and Find PID from json
                                tmpProcName = os.path.basename(curCall['arguments'][0]['value'])
                                try:
                                    curWork['Arg3'] = "ChildPID: "+ProcessInfos.keys()[ProcessInfos.values().index('tmpProcName')]
                                except:
                                    curWork['Arg3'] = "ChildPID: NotFound"
                           
                                # Set Arg4 from Process Command LIne    
                                curWork['Arg4'] = curCall['arguments'][0]['value']+" "+curCall['arguments'][1]['value']
                                                        
                    elif iFeatIdx == 2:
                        # When Other Process Terminate Event occur
                        curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                        curWork['Arg2'] = "PROCESSHANDLE: "+curCall['arguments'][0]['value']
                        curWork['Arg3'] = "ExitCode: "+curCall['arguments'][1]['value']
                                                
                        try:
                            curWork['Arg4'] = "PROCESSNAME: "+curProcHandleTable[curCall['arguments'][0]['value']]
                        except:
                            curWork['Arg4'] = "PROCESSNAME: NotFound"
                        
                    elif iFeatIdx == 3:
                        # When Other Process Open Event occur
                        if int(curProc['process_id']) != int(curCall['arguments'][2]['value'], 16):
                            lstDA = ChkProcOpenDA(curCall['arguments'][1]['value'])
                            strDA = '|'.join(lstDA)
                            
                            # if find All NtOpenProcess Remove for and if
                            for strMatch in ["PROCESS_VM_READ", "PROCESS_VM_WRITE", "PROCESS_TERMINATE"]:
                                if strDA.find(strMatch) != -1:
                                    curProcHandleTable[curCall['arguments'][0]['value']] = str(int(curCall['arguments'][2]['value'], 16))
                                                                                                            
                                    curWork['Arg1'] = "STATUS: "+curCall['status']
                                    curWork['Arg2'] = "TargetPID: "+str(int(curCall['arguments'][2]['value'], 16))
                                    curWork['Arg3'] = "DesireAccess: "+strDA
                                    break
                                
                    elif iFeatIdx == 4:
                        # When Other Process Memory Read event occur
                        if curCall['arguments'][0]['value'] != "0xffffffff":
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "TargetPID: "+curProcHandleTable[curCall['arguments'][0]['value']]
                            curWork['Arg3'] = "BaseAddress: "+curCall['arguments'][1]['value']
                            curWork['Arg4'] = "Buffer: "+curCall['arguments'][2]['value']
                            
                    elif iFeatIdx == 5:
                        # When Other Process Memory Write event occur
                        if curCall['arguments'][0]['value'] != "0xffffffff":
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "TargetPID: "+curProcHandleTable[curCall['arguments'][0]['value']]
                            curWork['Arg3'] = "BaseAddress: "+curCall['arguments'][1]['value']
                            curWork['Arg4'] = "Buffer: "+curCall['arguments'][2]['value']
                            
                    elif iFeatIdx == 6:
                        # When Port Bind and Listen!
                        if curCall['api'] == "bind":
                            curBindHandleTable[curCall['arguments'][0]['value']] = str(curCall['arguments'][1]['value'])+":"+str(curCall['arguments'][2]['value'])
                        elif curCall['api'] == "listen":
                            try:
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                curWork['Arg2'] = "OpenPort: "+curBindHandleTable[curCall['arguments'][0]['value']]
                            except:
                                continue
                    
                    elif iFeatIdx == 7:
                        # Any Network Connection
                        lstFeat7API = ["URLDownloadToFileW", "InternetConnectA", "InternetConnectW", "InternetOpenUrlA", "InternetOpenUrlW", "HttpOpenRequestA", "HttpOpenRequestW"]
                        
                        # Parse Each API
                        if curCall['api'] == "URLDownloadToFileW" != -1:
                            # Cuckoomon.dll only hook URLDownloadToFileW
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "URL: "+curCall['arguments'][0]['value']
                            curWork['Arg3'] = "LocalPath: "+curCall['arguments'][1]['value']
                        elif curCall['api'].find("InternetConnect") != -1:
                            # InternetConnectA, InternetConnectW Same Arguments
                            # Add InternetConnection to List
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "Server: "+curCall['arguments'][1]['value']+":"+curCall['arguments'][2]['value']
                            if (curCall['arguments'][3]['value'] != "") & curCall['arguments'][4]['value'] !="":
                                curWork['Arg3'] = "Option(Username/Password): "+curCall['arguments'][3]['value']+"/"+curCall['arguments'][4]['value']
                            else:
                                curWork['Arg3'] = "Option(Username/Password): Empty"
                            curInetHandleTable[curCall['arguments'][0]['value']] = curCall['arguments'][1]['value']+":"+curCall['arguments'][2]['value']
                            
                        elif curCall['api'].find("HttpOpenRequest") != -1:
                            # HttpOpenRequestA, HttpOpenRequestW Same Arguments
                            # Get Server Info from Table
                            tmpServer = curInetHandleTable[curCall['arguments'][0]['value']]
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "URL: "+tmpServer+curCall['arguments'][1]['value']
                            
                        elif curCall['api'].find("InternetOpenUrl") != -1:
                            # InternetOpenUrlA, InternetOpenUrlW Same Arguments
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "URL: "+curCall['arguments'][1]['value']
                            
                        elif curCall['api'] == "connect":
                            # Current Cuckoomon.dll (0.6) isn't Parse Parameter Correctly.
                            foo = "bar"     
                        
                    elif iFeatIdx == 8:
                        # Some FindWindow for Find specific Process
                        # "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW"
                        curCall['Arg1'] = "STATUS: "+str(curCall['status'])
                        curCall['Arg2'] = "ClassName: "+curCall['arguments'][0]['value']
                        curCall['Arg3'] = "WindowName: "+curCall['arguments'][1]['value']
                        
                    elif iFeatIdx == 9:
                        foot = "Bar"
                    elif iFeatIdx == 10:
                        foot = "Bar"
                    elif iFeatIdx == 11:
                        foot = "Bar"
                    elif iFeatIdx == 12:
                        foot = "Bar"
                    elif iFeatIdx == 13:
                        if curCall['status'] == "SUCCESS":
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "MutexName: "+curCall['arguments'][1]['value']
                            
                    elif iFeatIdx == 14:
                        # When Port Bind and Listen!
                        if curCall['api'] == "bind":
                            curBindHandleTable[curCall['arguments'][0]['value']] = str(curCall['arguments'][1]['value'])+":"+str(curCall['arguments'][2]['value'])
                        elif curCall['api'] == "listen":
                            try:
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                curWork['Arg2'] = "OpenPort: "+curBindHandleTable[curCall['arguments'][0]['value']]
                            except:
                                continue
                            
                    elif iFeatIdx == 15:
                        # When File Create
                        # CREATE_NEW = 1, CREATE_ALWAYS = 2
                        if (curCall['arguments'][3]['value'] == 1) | (curCall['arguments'][3]['value'] == 2):
                            if isSystemDir(os.path.dirname(curCall['arguments'][2]['value'])):
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                curWork['Arg2'] = "Filename: "+curCall['arguments'][2]['value']
                                curWork['Arg3'] = "DesireAccess: "+ChkFileOpenDA(curCall['arguments'][1]['value'])

                    elif iFeatIdx == 16:
                        strExistName = curCall['arguments'][0]['value']
                        strNewName = curCall['arguments'][1]['value']
                        
                        if isSystemDir(os.path.dirname(strExistName)) & isSystemDir(os.path.dirname(strNewName)):
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "ExistingName: "+strExistName
                            curWork['Arg3'] = "NewName: "+strNewName
                            
                    elif iFeatIdx == 17:
                        if isSystemDir(os.path.dirname(curCall['arguments'][0]['value'])):
                            curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                            curWork['Arg2'] = "Filename: "+curCall['arguments'][0]['value']
                        
                    elif iFeatIdx == 18:
                        if (curCall['arguments'][3]['value'] == 1) | (curCall['arguments'][3]['value'] == 2):
                            if isTempDir(os.path.dirname(curCall['arguments'][2]['value'])) & isExecFile(curCall['arguments'][2]['value']):
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                curWork['Arg2'] = "Filename: "+curCall['arguments'][2]['value']
                                curWork['Arg3'] = "DesireAccess: "+ChkFileOpenDA(curCall['arguments'][1]['value'])
                            
                    elif iFeatIdx == 19:
                        if (curCall['arguments'][3]['value'] == 1) | (curCall['arguments'][3]['value'] == 2):
                            if isInetTempDir(os.path.dirname(curCall['arguments'][2]['value'])) & isExecFile(curCall['arguments'][2]['value']):
                                curWork['Arg1'] = "STATUS: "+str(curCall['status'])
                                curWork['Arg2'] = "Filename: "+curCall['arguments'][2]['value']
                                curWork['Arg3'] = "DesireAccess: "+ChkFileOpenDA(curCall['arguments'][1]['value'])
                                
                    elif iFeatIdx == 20:
                        strSearchFile = curCall['arguments'][0]['value']
                        
                        if strSearchFile.find("*") != -1 & strSearchFile.find("?") != -1:
                            curWork['Arg1'] =  "STATUS: "+curCall['status']
                            curWork['Arg1'] =  "SearchFilename: "+curCall['arguments'][0]['value']
                            
                    elif iFeatIdx == 21:
                        if curCall['status'] == SUCCESS:
                            if isExecFile(curCall['arguments'][2]['value']):
                                curWork['Arg1'] = "STATUS: "+curCall['status']
                                curWork['Arg2'] = "Filename: "+curCall['arguments'][2]['value']
                                    
                    elif iFeatIdx == 22:
                        # Open SUCCESS with WRITE Access
                        if (curCall['arguments'][3]['value'] == 3) | (curCall['arguments'][3]['value'] == 4):
                            if curCall['status'] == SUCCESS:
                                strDA = ChkFileOpenDA(curCall['arguments'][1]['value'])
                                strFilename = curCall['arguments'][2]['value']
                                if (strDA.find("GENERIC_ALL") != -1) | (strDA.find("GENERIC_WRITE") != -1):
                                    if isHostsPath(os.path.dirname(strFilename)) != "" & os.path.basename(strFilename) == "hosts":
                                        curWork['Arg1'] = "STATUS: "+curCall['status']
                                        curWork['Arg2'] = "Filename: "+strFilename
                                        curWork['Arg3'] = "DesireAccess: "+strDA                                        
                                    
                    elif iFeatIdx == 23:
                        # Open SUCCESS with WRITE Access
                        if (curCall['arguments'][3]['value'] == 3) | (curCall['arguments'][3]['value'] == 4):
                            if curCall['status'] == SUCCESS:
                                strDA = ChkFileOpenDA(curCall['arguments'][1]['value'])
                                strFilename = curCall['arguments'][2]['value']
                                if (strDA.find("GENERIC_ALL") != -1) | (strDA.find("GENERIC_WRITE") != -1):
                                    if isHostsPath(os.path.dirname(strFilename)) != "" & os.path.basename(strFilename) == "hosts.ics":
                                        curWork['Arg1'] = "STATUS: "+curCall['status']
                                        curWork['Arg2'] = "Filename: "+strFilename
                                        curWork['Arg3'] = "DesireAccess: "+strDA
                                        
                    elif iFeatIdx == 24:
                        curProcTasksCount = curProcTasksCount + 1
                        if (curCall['arguments'][3]['value'] == 1) | (curCall['arguments'][3]['value'] == 2):
                            if curCall['status'] == SUCCESS:
                                strDA = ChkFileOpenDA(curCall['arguments'][1]['value'])
                                strFilename = curCall['arguments'][2]['value']
                                if (strDA.find("GENERIC_ALL") != -1) | (strDA.find("GENERIC_WRITE") != -1):
                                    if os.path.splitdrive(os.path.dirname(strFilename))[1].upper() == "\\WINDOWS\\TASKS":
                                        curProcTasksCount = curProcTasksCount + 1

                                        curWork['Arg1'] = "STATUS: "+curCall['status']
                                        curWork['Arg2'] = "Filename: "+strFilename
                                        curWork['Arg3'] = "CreateJobCount: "+curProcTasksCount
                                    
                    elif iFeatIdx == 25:
                        foot = "Bar"
                    elif iFeatIdx == 26:
                        foot = "Bar"
                    elif iFeatIdx == 27:
                        foot = "Bar"
                    elif iFeatIdx == 28:
                        foot = "Bar"
                    elif iFeatIdx == 29:
                        foot = "Bar"
                    elif iFeatIdx == 30:
                        foot = "Bar"
                    elif iFeatIdx == 31:
                        foot = "Bar"
                        
                    if curWork['Arg1'] != '':
                        iWorkCount = iWorkCount + 1
                        csvWriter.writerow([iWorkCount, 1, "csrc", curWork['TimeStamp'], curWork['ProcessName'], curWork['PID'], curWork['TypeID'], curWork['Arg1'], curWork['Arg2'], curWork['Arg3'], curWork['Arg4'], curWork['Arg5'], curWork['Arg6']])                    
                    
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