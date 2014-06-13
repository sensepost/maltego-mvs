#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com // @glennzw

import bvapi
import logging
from MaltegoTransform import *
from dateutil import parser
from humanhash import humanize
from hashlib import sha512
import datetime
import random
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs_bv.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')

bv_User = "youruser"
bv_Pass = "password"
bv_URL = "https://yourBroadViewAPI"

makeHuman = False
humanSalt = "saltIsGoodOnBurgers"
def randIP():
        ip = "x.x." + ".".join(map(str, (random.randint(0, 255)
                        for _ in range(2))))
        return ip

ignoreAccounts = [] #Any BroadView/MVS accounts to ignore

api_service = "http://172.16.29.195:5000/api/v1/query" #Point to AyePeeEye.py service

TRX = MaltegoTransform()
TRX.parseArguments(sys.argv)

logging.debug(sys.argv)

client = bvapi.Client(url=bv_URL, user=bv_User, password=bv_Pass)
status = client.status()
if 'status' not in status or status['status'] != 'success':
    logging.error("Bad Status: '%s'" % str(status))
    exit(-1)
