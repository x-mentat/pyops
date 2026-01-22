#!/usr/bin/python3
import argparse
from datetime import datetime
import sys
import math
import re
import os
import time
import subprocess
import json
from pprint import pprint

AUTHOR = "SnejPro"
VERSION = 1.1

parser = argparse.ArgumentParser()
parser.add_argument("-H", dest="hostname", help="Hostname/IP-adress", type=str, required=True)
parser.add_argument("-v", dest="version", help="SNMP version", type=str, default='3', choices=["1","2c","3"])
parser.add_argument("--port", dest="port", help="SNMP oirt", type=int, default=161)

parser.add_argument("-u", dest="username", help="SNMPv3 - username", type=str)
parser.add_argument("--auth_prot", help="SNMPv3 - authentication protocol", type=str, default="SHA", choices=["MD5", "SHA", "None"])
parser.add_argument("--priv_prot", help="SNMPv3 - privacy (encryption) protocol", type=str, default="AES", choices=["DES", "AES", "None"])
parser.add_argument("-a", dest="auth_key", help="SNMPv3 - authentication key", type=str)
parser.add_argument("-p", dest="priv_key", help="SNMPv3 - privacy key", type=str)
parser.add_argument("-C", dest="community", help="SNMP v1, v2c - community", default="public", type=str)

parser.add_argument("-m", dest="mode", help="Comma-seperated list of modes that should be checked: load,memory,disk,raid,storage,ups,status,update,all", type=str, default='all')
parser.add_argument("-x", dest="exclude_mode", help="Comma-seperated list of modes that should not be checked", type=str)

parser.add_argument("--memory_warn", help="Memory - warning utilization (percent)", type=int, default=80)
parser.add_argument("--memory_crit", help="Memory - critical utilization (percent)", type=int, default=90)
parser.add_argument("--net_warn", help="Network - warning utilization (percent of linkspeed)", type=int, default=80)
parser.add_argument("--net_crit", help="Network - critical utilization (percent of linkspeed)", type=int, default=90)
parser.add_argument("--temp_warn", help="Status - warning NAS temperature", type=int, default=60)
parser.add_argument("--temp_crit", help="Status - critical NAS temperature", type=int, default=80)
parser.add_argument("--disk_temp_warn", help="Disk - warning temperature", type=int, default=50)
parser.add_argument("--disk_temp_crit", help="Disk - critical temperature", type=int, default=70)
parser.add_argument("--storage_used_warn", help="Storage - warning usage (percent)", type=int, default=80)
parser.add_argument("--storage_used_crit", help="Storage - critical usage (percent)", type=int, default=90)
parser.add_argument("--ups_level_warn", help="UPS - warning battery level (percent)", type=int, default=50)
parser.add_argument("--ups_level_crit", help="UPS - critical battery level (percent)", type=int, default=30)
parser.add_argument("--ups_load_warn", help="UPS - warning load (percent)", type=int, default=80)
parser.add_argument("--ups_load_crit", help="UPS - critical load (percent)", type=int, default=90)
args = parser.parse_args()

returnstring = ""
returnperf = " |"
state = "OK"

timeout=5

last_check_file = "/tmp/check_synology_"+args.hostname+"_"+re.sub(r'\W', '', args.mode)+".json"
datetime_format = "%Y-%m-%d %H-%M-%S"

session_kargs=[
    "-O","nq",
    "-v",str(args.version),
]

if args.version == '3':
    if args.auth_prot == "None":
        session_kargs.append("-l")
        session_kargs.append("noAuthNoPriv")
    elif args.priv_prot == "None":
        session_kargs.append("-l")
        session_kargs.append("authNoPriv")

        if args.auth_prot:
            session_kargs.append("-a")
            session_kargs.append(args.auth_prot)

        if args.auth_key:
            session_kargs.append("-A")
            session_kargs.append(args.auth_key)

        if args.username:
            session_kargs.append("-u")
            session_kargs.append(args.username)
    else:
        session_kargs.append("-l")
        session_kargs.append("authPriv")

        if args.auth_prot:
            session_kargs.append("-a")
            session_kargs.append(args.auth_prot)

        if args.auth_key:
            session_kargs.append("-A")
            session_kargs.append(args.auth_key)

        if args.username:
            session_kargs.append("-u")
            session_kargs.append(args.username)

        if args.priv_prot and args.priv_prot != "None":
            session_kargs.append("-x")
            session_kargs.append(args.priv_prot)

        if args.priv_key:
            session_kargs.append("-X")
            session_kargs.append(args.priv_key)
else:
    session_kargs.append("-c")
    session_kargs.append(args.community)

session_kargs.append(args.hostname+":"+str(args.port))

def run_snmp(proc, oids):
    command = [ proc ]
    for a in session_kargs:
        command.append(a)
    if isinstance(oids, list):
        for o in oids:
            command.append(o)
    else:
        command.append(oids)
    result=subprocess.run(command, capture_output=True).stdout.decode('UTF-8')
    lines = result.split("\n")
    results = {}
    for l in lines:
        if l != "":
            key=re.findall(r"(1(\.[0-9]+)+) ", l)[0][0]
            tmp=l.split()
            if len(tmp) > 1:
                value=re.findall("(?<= ).+", re.findall(" .+", l)[0])[0]
                extractval=re.findall('(?<=^").*(?="$)',value)
                if len(extractval)!=0:
                    value=extractval[0]
                results[key]=value
    return results

def count_cores():
    oid="1.3.6.1.2.1.25.3.3.1.2"
    core_stats=run_snmp("snmpwalk", oid)
    return len(core_stats)

if args.mode != 'all':
    mode = re.findall("[a-z]+", args.mode)
else:
    mode = args.mode

if args.exclude_mode != None:
    exclude_mode = re.findall("[a-z]+", args.exclude_mode)
else:
    exclude_mode = []

network_mesurement_time = 5
state = 'OK'
queue = {
    "get": [],
    "walk": []
}
queue_result = [ ]

required_values = {
    "load" : [
        { "oid":"1.3.6.1.2.1.25.3.3.1.2", "type":"walk" },
        { "oid":"1.3.6.1.4.1.2021.10.1.3", "type":"walk" }
    ],
    "memory": [
        { "oid":"1.3.6.1.4.1.2021.4.5.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.2021.4.6.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.2021.4.14.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.2021.4.15.0", "type":"get" }
    ],
    "disk": [
        { "oid":"1.3.6.1.4.1.6574.2.1.1", "type":"walk" }
    ],
    "storage": [
        { "oid":"1.3.6.1.2.1.25.2.3.1", "type":"walk" }
    ],
    "raid": [
        { "oid":"1.3.6.1.4.1.6574.3.1.1", "type":"walk" }
    ],
    "update": [
        { "oid":"1.3.6.1.4.1.6574.1.5.4.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.5.3.0", "type":"get" }
    ],
    "status": [
        { "oid":"1.3.6.1.4.1.6574.1.5.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.5.2.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.2.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.4.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.4.2.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.1.3.0", "type":"get" }
    ],
    "ups": [
        { "oid":"1.3.6.1.4.1.6574.4.1.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.1.2.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.1.3.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.2.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.2.6.2.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.2.12.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.3.1.1.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.3.1.4.0", "type":"get" },
        { "oid":"1.3.6.1.4.1.6574.4.3.12.0", "type":"get" }
    ],
    "network": [
        { "oid":"1.3.6.1.2.1.31.1.1.1", "type":"walk" }
    ],
}

try:
    with open(last_check_file, "r") as f:
        lastcheck_result = json.load(f)
except:
    lastcheck_result = False


def format_bytes(size, unit):
    # 2**10 = 1024
    #power = 2**10
    power = 10**3
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return size, power_labels[n]+unit, str(round(size,2))+' '+power_labels[n]+unit

def snmpwalk(oid):
    result={}
    snmpres = run_snmp("snmpwalk", oid)
    return snmpres

def snmpget(oid):
    oids = []
    if isinstance(oid, list):
        for k in oid:
            oids.append(k)
    else:
        oids = oid
    result={}
    snmpres = run_snmp("snmpget", oids)
    return snmpres

def add_queue(oid, type):
    queue[type].append(oid)

def run_queue():
    global queue
    global queue_result
    local_queue_result = {}
    snmp_result = snmpget(queue["get"])
    local_queue_result = { **local_queue_result,  **snmp_result}
    for to_walk in queue["walk"]:
        snmp_result = snmpwalk(to_walk)
        local_queue_result = { **local_queue_result,  **snmp_result}
    if len(local_queue_result) == 0:
        change_state("UNKNOWN")
        print("UNKNOWN - Error fetching informations from NAS.")
        exitCode()

    queue_result.append( {
            "datetime": time.strftime(datetime_format),
            "data": local_queue_result
        }
    )

def change_state(locstate):
    global state
    if locstate != "OK" and state != "CRITICAL":
        if locstate == "WARNING":
            state = "WARNING"
        elif locstate == "CRITICAL":
            state = "CRITICAL"
        elif locstate == "UNKNOWN" and state != "WARNING":
            state = "UNKNOWN"

def check_standard(value, warn, crit, inv=False):
    value = float(value)
    warn = float(warn)
    crit = float(crit)
    if inv==False:
        if crit > value >= warn:
            locstate = "WARNING"
        elif value >= crit:
            locstate = "CRITICAL"
        else:
            locstate = "OK"
    else:
        if crit < value <= warn:
            locstate = "WARNING"
        elif value <= crit:
            locstate = "CRITICAL"
        else:
            locstate = "OK"

    change_state(locstate)
    return { "value":value, "locstate":locstate, "warn":warn, "crit":crit }

def check_ups_status(value):
    if value == "OL":
        locstate = "OK"
        perfvalue = 1
    elif value == "OL CHRG":
        locstate = "WARNING"
        perfvalue = 2
    elif value == "OB DISCHRG":
        locstate = "CRITICAL"
        perfvalue = 3
    else:
        locstate = "CRITICAL"
        value = "UNKOWN CRITICAL STATE '"+str(value)+"' - PLEASE REPORT ON GITHUB"
        perfvalue = 4

    change_state(locstate)
    return { "value":value, "locstate":locstate, "perfvalue":perfvalue }

def check_failed(value):
    if value == "1":
        locstate = "OK"
        output = "Normal"
    elif value == "2":
        locstate = "CRITICAL"
        output = "Failed"
    else:
        locstate = "CRITICAL"
        output = "Unknown status replied"

    change_state(locstate)
    return { "value":output, "locstate":locstate, "perfvalue":value }

def check_update(value):
    if value == "1":
        locstate = "WARNING"
        output = "Available"
    elif value == "2":
        locstate = "OK"
        output = "Unavailable"
    elif value == "3":
        locstate = "WARNING"
        output = "Connecting"
    elif value == "4":
        locstate = "WARNING"
        output = "Disconnected"
    elif value == "5":
        locstate = "CRITICAL"
        output = "Others"
    else:
        locstate = "CRITICAL"
        output = "Unknown status replied"

    change_state(locstate)
    return { "value":output, "locstate":locstate, "perfvalue":value }

def check_disk_status(value):
    if value == "1":
        locstate = "OK"
        output = "Normal"
    elif value == "2":
        locstate = "WARNING"
        output = "Initialized"
    elif value == "3":
        locstate = "WARNING"
        output = "NotInitialized"
    elif value == "4":
        locstate = "CRITICAL"
        output = "SystemPartitionFailed"
    elif value == "5":
        locstate = "CRITICAL"
        output = "Crashed"
    else:
        locstate = "CRITICAL"
        output = "Unknown status replied"

    change_state(locstate)
    return { "value":output, "locstate":locstate, "perfvalue":value }

def check_raid_status(value):
    if value == "1":
        locstate = "OK"
        output = "Normal"
    elif value == "2":
        locstate = "WARNING"
        output = "Repairing"
    elif value == "3":
        locstate = "WARNING"
        output = "Migrating"
    elif value == "4":
        locstate = "WARNING"
        output = "Expanding"
    elif value == "5":
        locstate = "WARNING"
        output = "Deleting"
    elif value == "6":
        locstate = "WARNING"
        output = "Creating"
    elif value == "7":
        locstate = "OK"
        output = "RaidSyncing"
    elif value == "8":
        locstate = "OK"
        output = "RaidParityChecking"
    elif value == "9":
        locstate = "WARNING"
        output = "RaidAssembling"
    elif value == "10":
        locstate = "WARNING"
        output = "Canceling"
    elif value == "11":
        locstate = "CRITICAL"
        output = "Degrade"
    elif value == "12":
        locstate = "CRITICAL"
        output = "Crashed"
    elif value == "13":
        locstate = "WARNING"
        output = "DataScrubbing"
    elif value == "14":
        locstate = "WARNING"
        output = "RaidDeploying"
    elif value == "15":
        locstate = "WARNING"
        output = "RaidUnDeploying"
    elif value == "16":
        locstate = "WARNING"
        output = "RaidMountCache"
    elif value == "17":
        locstate = "WARNING"
        output = "RaidUnmountCache"
    elif value == "18":
        locstate = "WARNING"
        output = "RaidExpandingUnfinishedSHR"
    elif value == "19":
        locstate = "WARNING"
        output = "RaidConvertSHRToPool"
    elif value == "20":
        locstate = "WARNING"
        output = "RaidMigrateSHR1ToSHR2"
    elif value == "21":
        locstate = "CRITICAL"
        output = "RaidUnknownStatus"
    else:
        locstate = "CRITICAL"
        output = "Unknown status replied"

    change_state(locstate)
    return { "value":output, "locstate":locstate, "perfvalue":value }


def exitCode():
    if state == 'OK':
        sys.exit(0)
    if state == 'WARNING':
        sys.exit(1)
    if state == 'CRITICAL':
        sys.exit(2)
    if state == 'UNKNOWN':
        sys.exit(3)

def count_keys(dict, patterns):
    res = 0
    for key in dict:
        if len(re.findall(patterns, key)):
            res = res + 1
    return res

def regex_keys(dict, patterns):
    res = []
    for key in dict:
        if len(re.findall(patterns, key)):
            res.append(key)
    return res

def render(name, tag, perf, value, locstate=False, perfvalue=False, warn=False, crit=False, unit=""):
    global returnstring
    global returnperf
    loc_returnstring = "\n" + name + ": " + str(value) + " " + unit
    if unit == "B" or unit == "b":
        loc_returnstring = "\n" + name + ": " + str(format_bytes(value, unit)[2])
    if locstate != False:
        loc_returnstring += " - "+str(locstate)

    returnstring += loc_returnstring
    if perf==True:
        if perfvalue == False:
            perfvalue = value
        loc_returnperf = " " + tag + "=" + str(perfvalue).replace(" ", "_") + unit
        if warn != False and crit != False:
            loc_returnperf += ";" + str(warn) + ";" + str(crit)
        returnperf += loc_returnperf

def fetch_required_values():
    for k, v in required_values.items():
        if (k in mode or mode == 'all') and k not in exclude_mode:
            for oids in v:
                add_queue(oids["oid"], oids["type"])
    run_queue()

fetch_required_values()
with open(last_check_file, "w") as f:
    f.write(json.dumps(queue_result))

if ('load' in mode or mode == 'all') and 'load' not in exclude_mode:
    returnstring += "\n\nLoad:"
    core_number = count_keys(queue_result[0]["data"], r"^1\.3\.6\.1\.2\.1\.25\.3\.3\.1\.2\.[0-9]+")
    render("Load - 1", "load-1", True, **check_standard(queue_result[0]["data"]['1.3.6.1.4.1.2021.10.1.3.1'], warn=core_number*2, crit=core_number*4) )
    render("Load - 5", "load-5", True, **check_standard(queue_result[0]["data"]['1.3.6.1.4.1.2021.10.1.3.2'], warn=core_number*1.5, crit=core_number*2) )
    render("Load - 15", "load-15", True, **check_standard(queue_result[0]["data"]['1.3.6.1.4.1.2021.10.1.3.3'], warn=core_number-0.3, crit=core_number) )

if ('memory' in mode or mode == 'all') and 'memory' not in exclude_mode:
    returnstring += "\n\nMemory:"
    render("Memory - Total", "memory-total", True, int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.5.0']))*1000, unit="B")
    render("Memory - Unused", "memory-unused", True, int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.6.0']))*1000, unit="B")
    render("Memory - Buffer", "memory-buffer", True, int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.14.0']))*1000, unit="B")
    render("Memory - Cached", "memory-cached", True, int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.15.0']))*1000, unit="B")
    memoryused = ( int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.5.0'])) - int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.6.0'])) - int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.15.0'])) - int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.14.0'])) )*1000
    render("Memory - Used", "memory-used", True, **check_standard(memoryused, warn=int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.5.0']))*args.memory_warn*10, crit=int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.4.1.2021.4.5.0']))*args.memory_crit*10), unit="B")

if ('disk' in mode or mode == 'all') and 'disk' not in exclude_mode:
    returnstring += "\n\nDisks:"
    disks = regex_keys(queue_result[0]["data"], r"^1\.3\.6\.1\.4\.1\.6574\.2\.1\.1\.2\.[0-9]+")
    for d in disks:
        num = re.findall("[0-9]+$", d)[0]
        render('Disk '+str(num)+' - Name', 'disk-'+str(num)+'-name', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.2.1.1.2.'+str(num)])
        render('Disk '+str(num)+' - Status', 'disk-'+str(num)+'-status', True, **check_disk_status(queue_result[0]["data"]['1.3.6.1.4.1.6574.2.1.1.5.'+str(num)]))
        render('Disk '+str(num)+' - Model', 'disk-'+str(num)+'-model', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.2.1.1.3.'+str(num)])
        render('Disk '+str(num)+' - Temperature', 'disk-'+str(num)+'-temperature', True, **check_standard(int(queue_result[0]["data"]['1.3.6.1.4.1.6574.2.1.1.6.'+str(num)]), crit=args.disk_temp_crit, warn=args.disk_temp_warn), unit="C")

if ('storage' in mode or mode == 'all') and 'storage' not in exclude_mode:
    returnstring += "\n\nStorages:"
    storages = regex_keys(queue_result[0]["data"], r"^1\.3\.6\.1\.2\.1\.25\.2\.3\.1\.3\.[0-9]+")
    for s in storages:
        num = re.findall("[0-9]+$", s)[0]

        x = re.search(r"/volume[0-9]+", queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.3.'+str(num)])
        if x == None:
            continue

        size = int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.4.'+str(num)]))*float(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.5.'+str(num)]))
        used = int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.4.'+str(num)]))*float(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.6.'+str(num)]))
        render('Storage '+str(num)+' - Name', 'storage-'+str(num)+'-name', False, queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.3.'+str(num)])
        render('Storage '+str(num)+' - Allocations Units', 'storage-'+str(num)+'-alloc-units', False, int(re.sub(r'\D', '', queue_result[0]["data"]['1.3.6.1.2.1.25.2.3.1.4.'+str(num)])))
        render('Storage '+str(num)+' - Size', 'storage-'+str(num)+'-size', False, size, unit="B")
        render('Storage '+str(num)+' - Used', 'storage-'+str(num)+'-used', True, **check_standard(used, crit=args.storage_used_crit/100*size, warn=args.storage_used_warn/100*size), unit="B")

if ('raid' in mode or mode == 'all') and 'raid' not in exclude_mode:
    returnstring += "\n\nRaids:"
    raids = regex_keys(queue_result[0]["data"], r"^1\.3\.6\.1\.4\.1\.6574\.3\.1\.1\.2\.[0-9]+")
    for r in raids:
        num = re.findall("[0-9]+$", r)[0]
        render('RAID '+str(num)+' - Name', 'raid-'+str(num)+'-name', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.3.1.1.2.'+str(num)])
        render('RAID '+str(num)+' - Status', 'raid-'+str(num)+'-status', True, **check_raid_status(str(queue_result[0]["data"]['1.3.6.1.4.1.6574.3.1.1.3.'+str(num)])))

if ('update' in mode  or mode == 'all') and 'update' not in exclude_mode:
    returnstring += "\n\nUpdate:"
    render('Update - Status', 'update-status', True, **check_update(queue_result[0]["data"]['1.3.6.1.4.1.6574.1.5.4.0']))
    render('Update - DSM-Version', 'update-version', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.1.5.3.0'])

if ('status' in mode  or mode == 'all') and 'status' not in exclude_mode:
    returnstring += "\n\nStatus:"
    render('Status - Model', 'status-model', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.1.5.1.0'])
    render('Status - S/N', 'status-serial', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.1.5.2.0'])
    render('Status - Temperature', 'status-temp', False, **check_standard(int(queue_result[0]["data"]['1.3.6.1.4.1.6574.1.2.0']), crit=args.temp_crit, warn=args.temp_warn), unit="C")
    render('Status - System', 'status-system', True, **check_failed(queue_result[0]["data"]['1.3.6.1.4.1.6574.1.1.0']))
    render('Status - System Fan', 'status-fan-system', True, **check_failed(queue_result[0]["data"]['1.3.6.1.4.1.6574.1.4.1.0']))
    render('Status - CPU Fan', 'status-fan-cpu', True, **check_failed(queue_result[0]["data"]['1.3.6.1.4.1.6574.1.4.2.0']))
    render('Status - Power', 'status-power', True, **check_failed(queue_result[0]["data"]['1.3.6.1.4.1.6574.1.3.0']))

if ('ups' in mode  or mode == 'all') and 'ups' not in exclude_mode:
    returnstring += "\n\nUPS:"
    if queue_result[0]["data"]['1.3.6.1.4.1.6574.4.1.1.0'] != 'No Such Instance currently exists at this OID':
        render('UPS - Model', 'ups-model', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.4.1.1.0'])
        render('UPS - Manufacturer', 'ups-manufacturer', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.4.1.2.0'])
        render('UPS - S/N', 'ups-serial', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.4.1.3.0'])
        render('UPS - Status', 'ups-status', True, **check_ups_status(queue_result[0]["data"]['1.3.6.1.4.1.6574.4.2.1.0']))
        render('UPS - Manufacturer-Date', 'ups-manufacturer-date', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.4.2.6.2.0'])
        render('UPS - Load', 'ups-load', True, **check_standard(float(queue_result[0]["data"]['1.3.6.1.4.1.6574.4.2.12.1.0']), crit=args.ups_load_crit, warn=args.ups_load_warn))
        render('UPS - Battery Level', 'ups-battery-level', True, **check_standard(float(queue_result[0]["data"]['1.3.6.1.4.1.6574.4.3.1.1.0']), crit=args.ups_level_crit, warn=args.ups_level_warn, inv=True))
        render('UPS - Battery Warning Level', 'ups-warning-battery-level', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.4.3.1.1.0'])
        render('UPS - Battery Battery Type', 'ups-battery-type', False, queue_result[0]["data"]['1.3.6.1.4.1.6574.4.3.12.0'])
    else:
        change_state('UNKNOWN')
        render('UPS - Status', 'ups-status', False, 'Can not find UPS', 'UNKNOWN')

if ('network' in mode  or mode == 'all') and 'network' not in exclude_mode:
    returnstring += "\n\nNetwork:"
    if lastcheck_result != False:
        last_check_timestamp = datetime.strptime(lastcheck_result[0]["datetime"], datetime_format)
        current_check_timestamp = datetime.strptime(queue_result[0]["datetime"], datetime_format)
        timespan=(current_check_timestamp-last_check_timestamp).total_seconds()
        networks = regex_keys(queue_result[0]["data"], r"^1\.3\.6\.1\.2\.1\.31\.1\.1\.1\.1\.[0-9]+")
        for n in networks:
            num = re.findall("[0-9]+$", n)[0]
            linkspeed=int(queue_result[0]["data"]['1.3.6.1.2.1.31.1.1.1.15.'+str(num)])*10**6
            if linkspeed != 0:
                speed_warn=linkspeed*args.net_warn
                speed_crit=linkspeed*args.net_crit

                downlink_octets_old=int(lastcheck_result[0]["data"]['1.3.6.1.2.1.31.1.1.1.6.'+str(num)])
                downlink_octets_new=int(queue_result[0]["data"]['1.3.6.1.2.1.31.1.1.1.6.'+str(num)])
                downlink_octets_diff=downlink_octets_new-downlink_octets_old
                downlink_speed=round(((downlink_octets_diff)*8)/timespan)

                uplink_octets_old=int(lastcheck_result[0]["data"]['1.3.6.1.2.1.31.1.1.1.10.'+str(num)])
                uplink_octets_new=int(queue_result[0]["data"]['1.3.6.1.2.1.31.1.1.1.10.'+str(num)])
                uplink_octets_diff=uplink_octets_new-uplink_octets_old
                uplink_speed=round(((downlink_octets_diff)*8)/timespan)

                render('Network '+str(num)+' - Name', 'net-'+str(num)+'-name', False, queue_result[0]["data"]['1.3.6.1.2.1.31.1.1.1.1.'+str(num)])
                render('Network '+str(num)+' - Linkspeed', 'net-'+str(num)+'-link_speed', True, linkspeed, unit="b")
                render('Network '+str(num)+' - Utilization - Downlink', 'net-'+str(num)+'-util_down', True, **check_standard(downlink_speed, crit=speed_warn, warn=speed_crit), unit="b")
                render('Network '+str(num)+' - Utilization - Uplink', 'net-'+str(num)+'-util_up', True, **check_standard(uplink_speed, crit=speed_warn, warn=speed_crit), unit="b")
                render('Network '+str(num)+' - Octets - Downlink', 'net-'+str(num)+'-octets_down', True, downlink_octets_new, unit="c")
                render('Network '+str(num)+' - Octets - Uplink', 'net-'+str(num)+'-octets_up', True, uplink_octets_new, unit="c")


    else:
        change_state('UNKNOWN')
        render('Network - Status', 'net-status', False, 'temporary network file error', 'UNKNOWN')





print("NAS-Status: "+state+returnstring+returnperf)
exitCode()
