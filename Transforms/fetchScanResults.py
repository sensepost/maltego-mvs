#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com // @glennzw

from MaltegoTransform import *
import logging
logging.basicConfig(level=logging.DEBUG,filename='/tmp/maltego_logs_bv.txt',format='%(asctime)s %(levelname)s: %(message)s',datefmt='%Y-%m-%d %H:%M:%S')
from common import *
import json
import requests
import random

account = TRX.getVar("account")
scan_id = TRX.getVar("id")
scan_id = int(scan_id)
searchTerm = TRX.getVar("searchterm")
checkForExploits = TRX.getVar("hasExploit", "false")
checkForExploits = (checkForExploits.lower() == "true")
showCritical = (TRX.getVar("hasCritical","true").lower() == "true")
showHigh = (TRX.getVar("hasHigh","true").lower() == "true")
showMedium = (TRX.getVar("hasMedium","true").lower() == "true")

logging.debug(scan_id)
scan_results = client.scan_data(scan_id)

logging.debug(type(TRX))
logging.debug(TRX)

#isHost = ( TRX.getVar("maltego.IPv4Address") != None)
#isHost = TRX.getVar("maltego.IPv4Address")
isHost = TRX.getVar("ipv4-address")
if isHost:
    isHost = TRX.getVar("ip")

byHost = TRX.getVar("byHost", "false")
byHost = (byHost.lower() == "true")

aggregate = TRX.getVar("aggregate", "false")
aggregate = (aggregate.lower() == "true")

hostList = {}
scanList = {}
exploitList ={}

if 'status' not in scan_results or scan_results['status'] != 'success':
    logging.error("Bad accounts data: '%s'" % str(status))
    exit(-1)

scan_results = scan_results['scan']['issues']

for a in scan_results:
    impact = a.get('impact')
    ip = a.get('ip')
    protocol = a.get('protocol')
    port = a.get('port')
    detail = a.get('issue_detail')
    vkb_id = detail.get('vkb_id')

    cve_string = detail.get('cve_reference')
    cveList = []
    if cve_string:
        cveList = cve_string.replace("CVE-", '').replace(" ","").split(",")

    if checkForExploits:
        expL =[]
        for cve in cveList:
            logging.debug("Checking CVE %s" % cve)
            req = requests.get(api_service + "?exploit=True&cve=" + cve)
            if req and req.status_code == 200:
                result = json.loads(req.text)
                result = result.get("data")
                if len(result)>0 :
                    for sploit in result[0].get("exploitDB"):
                        expL.append(sploit)
        exploitList[vkb_id] = expL

    threat = 1
    if impact == "medium":
        threat = 10
    elif impact == "high":
        threat = 100
    elif impact == "critical":
        threat = 1000

    if threat > 1: #Ignore 'info' for now

        if (isHost and isHost != ip) or searchTerm and searchTerm.lower() not in detail.get('description').lower():
            continue

        if byHost:
            hostList.setdefault(ip, {"medium":0, "high":0, "critical":0, "threat":0})
            hostList[ip][impact] += 1
            hostList[ip]['threat'] += threat
        else:
            detail['impact'] = impact
            detail['protocol'] = protocol
            detail['port'] = port 
            scanList.setdefault(vkb_id, {"numHosts":1, "impact":"", "hosts":[], "details":detail})
            #scanList[vkb_id]['numHosts'] += 1
            scanList[vkb_id]['hosts'].append(ip)
            #scanList[vkb_id]['impact'] = impact

if byHost:
    for host, findings in hostList.iteritems():
        medium, high, critical = findings.get('medium'), findings.get('high'), findings.get('critical')
        if showCritical and critical <=0 or showHigh and high <=0 or showMedium and medium <= 0:
            continue

        realIP=host
        if makeHuman:
            host=randIP()

        _threat = findings.get('threat')
        NewEnt=TRX.addEntity("maltego.IPv4Address", "%s\n(%dC, %dH, %dM)" % (host,critical,high,medium))
        NewEnt.addAdditionalFields("medium", "Medium", "strict", str(medium))
        NewEnt.addAdditionalFields("high", "High", "strict", str(high))
        NewEnt.addAdditionalFields("critical", "Critical", "strict", str(critical))
        NewEnt.addAdditionalFields("account","account","strict",str(account))
        NewEnt.addAdditionalFields("id", "id", "strict", str(scan_id))
        NewEnt.addAdditionalFields("ip", "ip", "strict", str(realIP))
        NewEnt.setWeight(_threat)

else:
    for vkb, result in scanList.iteritems():
        hosts = result.get('hosts')
        result = result['details']
        impact = result.get('impact')
        cve = result.get('cve_reference')
        desc = result.get('description')
        name = result.get('name')
        vkb_id = result.get('vkb_id')
        port = result.get('port')
        proto = result.get('protocol')
        raw = result.get('raw')
        service = result.get('service')
        type = result.get('type')

        if checkForExploits and len(exploitList.get(vkb)) == 0:
            logging.debug("**SPLO Ignoring %s" % vkb)
            continue
    
        logging.debug("** SPLO %s" %str(exploitList.get(vkb)))

        msg = "%s\n(%s)" %(name,impact)
        if aggregate:
            msg = "%s\n(%d hosts)" %(name,len(hosts))

        NewEnt=TRX.addEntity("sensepost.ScanDetails", msg )
        NewEnt.addAdditionalFields("impact", "impact", "strict", impact)
        NewEnt.addAdditionalFields("protocol", "protocol", "strict", proto)
        NewEnt.addAdditionalFields("cve", "cve", "strict", cve)
        NewEnt.addAdditionalFields("desc", "desc", "strict", desc)
        NewEnt.addAdditionalFields("name", "name", "strict", name)
        NewEnt.addAdditionalFields("vkb", "vkb", "strict", str(vkb_id))
        NewEnt.addAdditionalFields("account","account","strict",str(account))

        if checkForExploits:
            NewEnt.addAdditionalFields("exploits", "exploits", "strict", str(len(exploitList.get(vkb))))
        #for sploit in exploitList:
        

        if aggregate:
            NewEnt.addAdditionalFields("numhosts", "numhosts", "strict", str(len(hosts)))
            NewEnt.addAdditionalFields("hosts", "hosts", "strict", str(", ".join(hosts)))
            NewEnt.addAdditionalFields("id", "id", "strict", str(scan_id)) 
            NewEnt.addAdditionalFields("port", "port", "strict", str(port))
        


        NewEnt.setWeight(threat)




TRX.returnOutput()
