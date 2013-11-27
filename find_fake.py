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

def 