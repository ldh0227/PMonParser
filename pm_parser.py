#!/usr/bin/python
# -*- encoding: utf-8 -*-

import time
import sys
import unicodecsv

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("Usage: python "+__file__+" [CSV File Name] [DATE]")        
    
    try:
        fpInput = open(sys.argv[1], "r")
    except IOError:
        print("[E] Check "+sys.argv[1]+"file!")
    
    try:
        fpOutput = open("PD_"+sys.argv[1], "w")
    except IOError:
        print("[E] While Create PD_"+sys.argv[1]+"file!")
        
    
    iLineCount = 0
    iWorkCount = 0
    
    csvReader = unicodecsv.reader(fpInput, encoding='utf-8')
    csvWriter = unicodecsv.writer(fpOutput, encoding='utf-8')
       
    try:
        for row in csvReader:
            if iLineCount == 0:                
                iLineCount = iLineCount + 1
                continue
                        
            iLineCount = iLineCount + 1
            
            strUser = "administrator"
            strDateTime = sys.argv[2] + " " + row[0]
            strProcName = row[1]
            strPID = row[2]
            strOperation = row[3]
            strPath = row[4]
            strResult = row[5]
            strDetail = row[6]
            
            strCont1 = ""
            strCont2 = ""
            strCont3 = ""
            strCont4 = ""
            strCont5 = ""
            strCont6 = ""
            
            bMatched = False
            if strOperation == "Process Create":
                bMatched = True
                strTypeID = 1
                strCont1 = strPath
                strCont2 = strResult
                arrDetail = strDetail.split(",")
                arrCont3 = arrDetail[0].split(" ")
                strCont3 = arrCont3[1]                
                strCont4 = arrDetail[1][16:-2]
            elif strOperation == "IRP_MJ_CREATE":                
                if strDetail.find("OpenResult: Created") != -1:                    
                    if strPath.find("\\WINDOWS\\") != -1:
                        bMatched = True
                        strTypeID = 15
                        strCont1 = strPath
                        strCont2 = strResult
                    elif strPath.find("\\Temp\\") != -1:
                        bMatched = True
                        strTypeID = 18
                        strCont1 = strPath
                        strCont2 = strResult
            
            if bMatched:
                iWorkCount = iWorkCount + 1
                csvWriter.writerow([iWorkCount, 1, strUser, strDateTime, strProcName, strPID, strTypeID, strCont1, strCont2, strCont3, strCont4, strCont5, strCont6])           
            
    except unicodecsv.Error as e:
        sys.exit('[E] file %s, line %d: %s' % (sys.argv[1], csvReader.line_num, e))
    
    print "Parsing Finished.\nTotal "+str(iLineCount)+" line readed.\n Check PD_"+sys.argv[1]+"File."
    
    fpInput.close()
    fpOutput.close()