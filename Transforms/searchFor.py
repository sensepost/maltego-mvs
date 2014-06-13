#!/usr/bin/env python
# -*- coding: utf-8 -*-
# glenn@sensepost.com // @glennzw

from common import *

searchTerm = sys.argv[1]
print "Searching for ''%s'" %searchTerm

accounts = client.accounts()
accounts = accounts['accounts']
accounts.reverse()

for idx, a in enumerate(accounts[50:]):
    name = a.get('name').encode('utf-8')
    account = a.get('id')

    if int(account) in ignoreAccounts:
        continue

    print "Checking client %d/%d (%s)" %(idx,len(accounts),name)

    scans = client.scans(account)
    scans = scans['scans']
    for scan in scans:
        scan_id = scan.get('id')
        scan_results = client.scan_data(scan_id)
        scan_results = scan_results['scan']['issues']
        for result in scan_results:
            detail = result.get('issue_detail')
            desc = detail.get('description')
            if searchTerm.lower() in desc.lower():
                print "Client '%s' matches '%s' (scan = %s)!" % (account, searchTerm, scan_id)
                print desc
