#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com // @glennzw

from MaltegoTransform import *
import logging
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs_bv.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
from common import *
import datetime

account = int(TRX.getVar("account"))
fromFinding = TRX.getVar("properties.scandetails")
supplied_vkb_id = TRX.getVar("vkb")

scans = client.scans(account)

reqStart = parser.parse(TRX.getVar("startDate", "1970"))
reqEnd = parser.parse(TRX.getVar("endDate", "2050"))
reqAge = TRX.getVar("scanAge")
mostRecent = TRX.getVar("mostRecent", "false")
mostRecent = (mostRecent.lower() == "true")

if reqAge:
    timeDelta = datetime.timedelta(days=int(reqAge))
    now = datetime.datetime.now()
    reqStart = now - timeDelta

if 'status' not in scans or scans['status'] != 'success':
    logging.error("Bad accounts data: '%s'" % str(status))
    exit(-1)

scans = scans['scans']

if mostRecent:
    scans = [scans[0]]

for a in scans:
    status = a.get('status')
    impact = a.get('impact')
    id = a.get('id')
    low = impact.get('low')
    med = impact.get('med')
    high = impact.get('high')
    crit = impact.get('critical')

    initiated = parser.parse(a.get('initiated')).utcnow()
    created = parser.parse(a.get('created')).utcnow()
    completed = a.get('completed')
    if completed:
        completed = parser.parse(completed).utcnow()
    else:
        completed = "Running..."
    progress = str(a.get('progress')) + " %"

    #initiated = initiated.replace(tzinfo=None)

    now = datetime.datetime.now()
    daysOld = int((now - initiated).days)

    if not low:
        low = 0
    if not med:
        med = 0
    if not high:
        high = 0
    if not crit:
        crit = 0

    weight = low + med*10 + high*100 + crit*1000
    threat = "Low"
    if weight > 100:
        threat = "Medium"
    if weight > 500:
        threat = "High"
    if weight > 1000:
        threat = "Critical"

#    if daysOld < 30:
    if initiated >= reqStart and initiated <= reqEnd:

        ignore = True
        if fromFinding:  
            #Fetch all scans for this account, then all scan results, then compare vkb. Cumbersome.
            scan_results = client.scan_data(id)
            scan_results = scan_results['scan']['issues']
            for a in scan_results:
                detail = a.get('issue_detail')
                vkb_id = detail.get('vkb_id')
                logging.debug("Comparing '%s' to '%d'" % (supplied_vkb_id, vkb_id))
                if int(supplied_vkb_id) == int(vkb_id):
                    logging.debug("Including scan %s" % id)
                    ignore = False

        if not fromFinding or (fromFinding and not ignore):

            daysOldDisplay = "(%d days ago)" % daysOld
            NewEnt=TRX.addEntity("sensepost.ScanResult", "%s\n(%d days ago)" %(threat,daysOld))
            NewEnt.addAdditionalFields("low", "Low", "strict", str(low))
            NewEnt.addAdditionalFields("medium", "Medium", "strict", str(med))
            NewEnt.addAdditionalFields("high", "High", "strict", str(high))
            NewEnt.addAdditionalFields("critical", "Critical", "strict", str(crit))
            NewEnt.addAdditionalFields("threat", "Threat", "strict", str(threat))
            NewEnt.addAdditionalFields("Status", "Status", "strict", status)
            NewEnt.addAdditionalFields("progress", "Progress", "strict", progress)    
            NewEnt.addAdditionalFields("initiated", "Initiated", "strict", str(initiated))
            NewEnt.addAdditionalFields("created", "Created", "strict", str(created))
            NewEnt.addAdditionalFields("completed", "Completed", "strict", str(completed))
            NewEnt.addAdditionalFields("account","account","strict",str(account))
            NewEnt.addAdditionalFields("id", "id", "strict", str(id))
        
            if fromFinding:
                NewEnt.addAdditionalFields("vkb", "vkb", "strict", str(vkb_id))
    
            weight = weight / (daysOld+1)
            NewEnt.setWeight(weight)

TRX.returnOutput()
