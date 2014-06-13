#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com // @glennzw

from MaltegoTransform import *
import logging
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs_bv.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
from common import *
import requests
import json

doWeight =  TRX.getVar("doWeight", "false")
doWeight = (doWeight.lower() == "true")
doPublicVulnCheck = TRX.getVar("weightByExploit", "false")
doPublicVulnCheck = (doPublicVulnCheck.lower() == "true")

accounts = client.accounts()
if 'status' not in accounts or accounts['status'] != 'success':
    logging.error("Bad accounts data: '%s'" % str(status))
    exit(-1)
accounts = accounts['accounts']

for idx, a in enumerate(accounts):
    logging.debug("*** Account %d of %d" %(idx, len(accounts)))
    enabled = a.get('enabled')
    #desc = a.get('description')
    name = a.get('name').encode('utf-8')
    id = a.get('id')

    if int(id) in ignoreAccounts:
        logging.debug("Ignoring %s" % id)
        continue

    if makeHuman:
        name = humanize(sha512(name + humanSalt).hexdigest(), words=2)
    entity = name
    weight = 0
    if doWeight:
        latestScan = client.scans(id)['scans'][0]
        status = latestScan.get('status')
        impact = latestScan.get('impact')
        low = impact.get('low')
        med = impact.get('med')
        high = impact.get('high')
        crit = impact.get('critical')
        try:
            initiated = parser.parse(latestScan.get('initiated')).utcnow()
        except:
            initiated = datetime.datetime.now().utcnow()

        if not low:
            low = 0
        if not med:
            med = 0
        if not high:
            high = 0
        if not crit:
            crit = 0

        weight = low + med*10 + high*100 + crit*1000
        logging.debug("Weight for %s is %d" %(name, weight))
        threat = "Low"
        if weight > 100:
            threat = "Medium"
        if weight > 500:
            threat = "High"
        if weight > 1000:
            threat = "Critical"

        oldWeight = weight
        cves= {}
        cvesWithExploits = {}
        exploitThreat = 0
        if doPublicVulnCheck:
            #Check every finding of most recent scan against expdb. So long. This will take.
            scan_results = client.scan_data(id)
            scan_results = scan_results['scan']['issues']
            for a in scan_results:
                detail = a.get('issue_detail')
                cve_string = detail.get('cve_reference')
                cveList = []
                if cve_string:
                    for cve in cve_string.replace("CVE-", '').replace(" ","").split(","):
                        cve = cve.replace("-","")
                        if cve.isdigit():
                            cves[cve] = 1
            _cves = cves.keys()
            cves = ",".join(cves.keys())
            r = requests.get(api_service + "?cve=" + cves)
            if r and r.status_code == 200 and "status" in r.text:
                res = json.loads(r.text)
                data = res.get("data")
                for d in data:
                    score = d.get("score")
                    exploits = d.get("countExploitDB")
                    exploitThreat += score * (exploits*100)
                    for c in _cves:
                        cvesWithExploits[c] = 1
            else:
                print "Unable to query API"
                exit(-1)

        weight = weight + exploitThreat
        logging.debug("Exploit Threat for '%s' is %d" %(name, exploitThreat) )


        #initiated = initiated.replace(tzinfo=None)
        now = datetime.datetime.now()
        logging.debug(initiated)
        daysOld = int((now - initiated).days) 
        weight = weight / (daysOld+1)
        logging.debug("Latest scan for %s is %d days old" %(name, daysOld))
        logging.debug("   Updated weight for %s is %d" %(name, weight))

    entity = "%s\n(%s)" % (name,threat)

    NewEnt=TRX.addEntity("sensepost.SPClient", entity)
    #NewEnt.addAdditionalFields("Description", "Description", "strict", desc)
    NewEnt.addAdditionalFields("Name", "Name", "strict", name)
    NewEnt.addAdditionalFields("account", "account", "strict", str(id))
    if doWeight:
        NewEnt.addAdditionalFields("low", "Low", "strict", str(low))
        NewEnt.addAdditionalFields("medium", "Medium", "strict", str(med))
        NewEnt.addAdditionalFields("high", "High", "strict", str(high))
        NewEnt.addAdditionalFields("critical", "Critical", "strict", str(crit))
        NewEnt.addAdditionalFields("threat", "Threat", "strict", str(threat))
        NewEnt.addAdditionalFields("Status", "Status", "strict", status)
        NewEnt.addAdditionalFields("scanAge", "scanAge", "strict", str(daysOld))
        NewEnt.addAdditionalFields("origWeight", "origWeight", "strict", str(oldWeight))
        NewEnt.addAdditionalFields("numExploits", "numExploits", "strict", str(len(cvesWithExploits.keys())))
    NewEnt.setWeight(int(weight))

TRX.returnOutput()
