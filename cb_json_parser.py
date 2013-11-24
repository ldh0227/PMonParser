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
    
    jsonData = json.load(fpInput)
    
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
    
    jsonData[]