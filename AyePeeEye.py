#!/usr/bin/python
# glenn@sensepost.com

# This code performs the following:
# * Download CVE NIST XML files
# * Parse CVE XML files into a database (numerous schemas available)
# * Parse and load exploit-db.com CVE .CSV file (see http://www.exploit-db.com/about/)
# * Expose an API to query the above data
# 
# TODO:
# * Add functionality to check for updates from NIST at regular intervals and insert

import urllib
from lxml.etree import parse
from sqlalchemy import *
import re
from dateutil import parser
import sys
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.sql.expression import Insert
import logging
from cpe import CPE
import argparse
from datetime import date
import os
import csv

# Console colors
W  = '\033[0m'  # white (normal)
R  = '\033[31m' # red
G  = '\033[32m' # green
O  = '\033[33m' # orange
B  = '\033[34m' # blue
P  = '\033[35m' # purple
C  = '\033[36m' # cyan
GR = '\033[37m' # gray
BB = '\033[1m'  # Bold
NB = '\033[0m'  # Not bold
F  = '\033[5m'  # Flash
NF = '\033[25m' # Not flash

#Logging
logging.basicConfig(level=logging.DEBUG, format='[%(levelname)s] %(message)s')
logging.addLevelName(logging.INFO,P + "+" + G)
logging.addLevelName(logging.ERROR,R + "!!" + G)
logging.addLevelName(logging.DEBUG,"D")
logging.addLevelName(logging.WARNING, R + "WARNING" + G)
logging.addLevelName(logging.CRITICAL, R + "CRITICAL ERROR" + G)

@compiles(Insert)
def replace_string(insert, compiler, **kw):
    s = compiler.visit_insert(insert, **kw)
    s = s.replace("INSERT INTO", "REPLACE INTO")
    return s

NSMAP = {
    None: 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
    'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4',
}


cve_base="http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-"
year = date.today().year #Future proofing like a boss
cve_urls = [ cve_base + str(x) + ".xml" for x in range(2002,year+1)]


def prefixed(ns_prefix, rest):
    return '{%s}%s' % (NSMAP[ns_prefix], rest)


def get_tables():
    
    table = Table('CVEs',MetaData(),
                              Column('cve', Integer, primary_key=True),
                              Column('pubdate', DateTime),
                              Column('moddate', DateTime),
                              Column('summary', String(length=400)),
                              Column('score', Float),
                              Column('accessVector', String(length=20)),
                              Column('accessComp', String(length=20)),
                              Column('auth', String(length=20)),
                              Column('impactConf', String(length=20)),
                              Column('impactInt', String(length=20)),
                              Column('impactAvail', String(length=20))
            )

    table2 = Table('VulnSoftware', MetaData(),
                              Column('cve', Integer),
                              Column('part', String(length=1)),
                              Column('vendor', String(length=40)),
                              Column('product', String(length=40)),
                              Column('version', String(length=40)),
                              Column('update', String(length=40)),
                              Column('edition', String(length=40))
            )
  

    table3 = Table('exploitdb', MetaData(),
                              Column('id', Integer, primary_key=True),
                              Column('file', String(length=40)),
                              Column('description', String(length=100)),
                              Column('date', DateTime),
                              Column('author', String(length=40)),
                              Column('platform', String(length=20)),
                              Column('type', String(length=10)),
                              Column('port', Integer),
                              Column('CVE', Integer, primary_key=True, autoincrement=False)
                )

    return [table, table2, table3]

tables = {}
db = None

def makeDB(dbms):
    global tables
    global db
    db = create_engine(dbms)
    metadata = MetaData(db)
    tbls = get_tables()
    for tbl in tbls:
        tbl.metadata = metadata
        tables[tbl.name] = tbl
        if not db.dialect.has_table(db.connect(), tbl.name):
            tbl.create()

def populate_exdb(f):
    file=open(f)
    csvReader = csv.reader(file)
    headings = csvReader.next()
    expData = []
    for line in csvReader:
        line = [x.decode('utf-8', 'ignore') for x in line]
        data = dict(zip(headings,line))
        data['CVE'] = data['CVE'].replace("-","")
        data['date'] = parser.parse(data['date'])
        expData.append(data)
    tables['exploitdb'].insert().execute(expData) 

def populate_CVE(root):

    cve_data = []
    vuln_data = []

    for entry in root:
        cve_id = entry.find(prefixed('vuln', 'cve-id')).text
        cve_id = int(re.sub("[^0-9]", "", cve_id))
        pubdate = entry.find(prefixed('vuln', 'published-datetime')).text
        moddate = entry.find(prefixed('vuln', 'last-modified-datetime')).text
        summary = entry.find(prefixed('vuln', 'summary')).text
        
        pubdate = parser.parse(pubdate)
        moddate = parser.parse(moddate)

        vulnSoftware = entry.find(prefixed('vuln', 'vulnerable-software-list'))
        vulnList = []
        unableToParse=0
        if vulnSoftware is not None:
            for v in vulnSoftware:
                try:
                    myCPE = CPE(v.text)
                except NotImplementedError:
                    unableToParse+=1
                    #logging.warning("Unable to parse CPE '%s'" % v.text)
                else:
                    part = myCPE.get_part()[0]
                    vendor = myCPE.get_vendor()[0]
                    product = myCPE.get_product()[0]
                    version = myCPE.get_version()[0]
                    update = myCPE.get_update()[0]
                    edition = myCPE.get_edition()[0]
                    language = myCPE.get_language()[0]
    
                    derpa = {"part" : part, "vendor":vendor, "product":product, "version":version, "update":update, "edition":edition, "language":language, "cve":cve_id}
                    vuln_data.append(derpa)
            
    if unableToParse>0:
        logging.warning("Could not parse %d lines from file." % unableToParse)

        vuln = entry.find(prefixed('vuln','cvss'))
        #metrics = vuln.find(prefixed('cvss','base_metrics'))
        if vuln is not None:
            score = vuln.getchildren()[0].getchildren()[0].text
            accessVector = vuln.getchildren()[0].getchildren()[1].text
            accessComplexity = vuln.getchildren()[0].getchildren()[2].text
            auth = vuln.getchildren()[0].getchildren()[3].text
            impactConf = vuln.getchildren()[0].getchildren()[4].text
            impactInt = vuln.getchildren()[0].getchildren()[5].text
            impactAvail = vuln.getchildren()[0].getchildren()[6].text
       
        if "DO NOT USE THIS CANDIDATE NUMBER" not in summary:
            data = {
                "cve":cve_id,
                "pubdate":pubdate,
                "moddate":moddate,
                "summary":summary,
                "score":score,
                "accessVector":accessVector,
                "accessComp":accessComplexity,
                "auth":auth,
                "impactConf": impactConf,
                "impactInt": impactInt,
                "impactAvail": impactAvail
                }
            cve_data.append(data)

    tables['CVEs'].insert().execute(cve_data)
    tables['VulnSoftware'].insert().execute(vuln_data)


def get_exploitdb_local(cve=None,start=None,end=None,author=None,platform=None,type=None,port=None):

    t1 = tables['exploitdb']
    f = [] #filter
    if cve:
        f.append(t1.c.CVE == cve)
    if start:
        start = parser.parse(start)
        f.append(t1.c.date >= start)
    if end:
        end = parser.parse(end)
        f.append(t1.c.date <= end)
    if author:
        f.append(t1.c.author == author)
    if platform:
        f.append(t1.c.platform == platform)
    if type:
        f.append(t1.c.type == type)
    if port:
        f.append(t1.c.port == int(port))

    s1 = select([t1], and_(*f))
    r1 = db.execute(s1).fetchall()

    results = []
    c1 = t1.columns._data.keys()
    for row in r1:
        new = {}
        for idx,val in enumerate(row):
            new[c1[idx]] = val
        results.append(new)

    toReturn = {"status":"success", "numResults":len(results), "data":results}
    return toReturn

def api_server():
    from flask import Flask, request, jsonify
    app = Flask(__name__)

    @app.route('/api/v1/exploitdb')
    def exdb():
        cve = request.args.get('cve')
        author = request.args.get('author')
        platform = request.args.get('platform')
        start = request.args.get('start')
        end = request.args.get('end')
        type = request.args.get('type')
        port = request.args.get('port')

        check = get_exploitdb_local(cve=cve,author=author,platform=platform,start=start,end=end,type=type,port=port)
        if check:
            return jsonify(check)
        else:
            return jsonify({"status":"fail"})

    @app.route('/api/v1/query')
    def cve():
        cve = request.args.get('cve')
        vulnSw = str(request.args.get('vuln')).lower()
        expDb = str(request.args.get('exploit')).lower()

        vulnSw = (vulnSw == "true")
        expDb = (expDb == "true")

        t_cve = tables['CVEs']
        t_vuln = tables['VulnSoftware']
        results, results2 = [], []

        cves = cve.split(",")
        results = []

        for cve in cves:
            cve = cve.replace("-","")
            exploitDB = get_exploitdb_local(cve=cve) #(cve=cve[:-4] + "-" + cve[-4:])
            countEDB = exploitDB['numResults']
            results2 = []
            f2 = [t_vuln.c.cve == cve ]
            c2 = t_vuln.columns._data.keys()
            s2 = select([t_vuln], and_(*f2))
            r2 = db.execute(s2).fetchall()

            for row in r2:
                new = {}
                for idx,val in enumerate(row):
                    new[c2[idx]] = str(val) #Without str some flasks fail to jsonfiy
                results2.append(new)

            f1 = [t_cve.c.cve == cve]
            c1 = t_cve.columns._data.keys()
            s1 = select([t_cve], and_(*f1))
            r1 = db.execute(s1).fetchall()


            for row in r1:
                new = {'countVulnSoftware':len(results2), 'countExploitDB':countEDB}
                if vulnSw:
                    new['vulnSoftware'] = results2
                if expDb:
                    new['exploitDB'] = exploitDB['data'] #exploitDB['exploits']

                for idx,val in enumerate(row):
                    new[c1[idx]] = val 
                results.append(new)

        toReturn = {"status":"success", "numResults":len(results), "data":results}
        return jsonify(toReturn)

    #app.debug = True
    app.run(host="0.0.0.0")


def parseCVE(file):
    with open(file) as xmlfile:
        tree = parse(xmlfile)
    root = tree.getroot()
    populate_CVE(root) 


if __name__ == "__main__":

    print " SensePost's threat API engine.\n Contact: info@sensepost.com\n"

    cve_local_files = []

    parserz = argparse.ArgumentParser(description="API service.")
    parserz.add_argument("-c", "--cve", help="Download CVE files", action="store_true")
    parserz.add_argument("-o", "--load", help="Download and parse CVE files", action="store_true")
    parserz.add_argument("-l", "--local", help="Parse local CVE file (can specificy multiple", action='append')    
    parserz.add_argument("-x", "--exploitdb", help="Parse local exploit-db.com file (inc CVE). Support this project. See: http://www.exploit-db.com/about/")    
    parserz.add_argument("-d", "--database", help="Specify database format. Default is sqlite in current dir. See http://docs.sqlalchemy.org/en/rel_0_9/dialects/index.html .", default="sqlite:///cve.db")
    parserz.add_argument("-a", "--api", help="Run API server",action="store_true")

    args = parserz.parse_args()

    if len(sys.argv) < 2:
        logging.error("Try -h for help")
        exit(-1)

    logging.info("Ensuring database '%s' is functional" % args.database)   
    makeDB(args.database)

    if args.exploitdb:
        logging.info("Loading exploit-db.com data from '%s'..." % args.exploitdb)
        populate_exdb(args.exploitdb)
        logging.info("Done.")

    if args.local:
        for fname in args.local:
            logging.info("Loading local CVE file '%s'" % fname)
            parseCVE(fname) 
 
    if args.cve or args.load:
        for url in cve_urls:
            logging.info("Downloading '%s'..." % url)
            download = urllib.urlretrieve(url)
            os.rename(download[0],url.split("/")[-1])
        if args.load:
            for url in cve_urls:
                fname = url.split("/")[-1]
                logging.info("Parsing '%s' and populating DB" % fname)
                parseCVE(fname)

    if args.api:
        logging.info("Running API server")
        api_server()
