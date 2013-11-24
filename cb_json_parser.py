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