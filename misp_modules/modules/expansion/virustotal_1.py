import json
import requests
from requests import HTTPError
import base64
import time
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import argparse
from collections import OrderedDict
import socket

misperrors = {'error': 'Error'}
mispattributes = {'input': ["md5",'url', 'hostname', 'domain', "ip-src", "ip-dst"],
                  'output': ['md5','url', 'hostname', 'domain', "ip-src", "ip-dst"]
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1.0', 'author': 'SEC21',
              'description': 'Get Scan Results',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin
moduleconfig = ["VTapikey", "MISPurl", "MISPkey"]

def init(url,key):
    return PyMISP(url,key, False, 'json')

def handler(q=False):
    global limit
    if q is False:
        return False
	
    q = json.loads(q)
	
    key = q["config"]["VTapikey"]
    MISPurl = q["config"]["MISPurl"]
    MISPkey = q["config"]["MISPkey"] 

    r = {"results": []}

    print (q)

	# If the attribute is a md5, perform scan and save result as an new attribute
    if 'md5' in q:
        ioc = q["md5"]
        ioc_type = "md5"
        r["results"] += filescan(q['md5'], key)
	
	# If the attribute belongs to any of the following types, perform scan and save result as an new attribute
    if "ip-src" in q:
        ioc = q["ip-src"]
        ioc_type = "ip-src"
        url = cleanURL(q["ip-src"])
        comment = urlscan(ioc, key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
        
		
    if "ip-dst" in q: 
        ioc = q["ip-dst"]
        ioc_type = "ip-dst"
        url = cleanURL(q["ip-dst"])
        comment = urlscan(ioc, key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "domain" in q: 
        ioc = q["domain"]
        ioc_type = "domain"
        url = cleanURL(q["domain"])
        comment = urlscan(ioc, key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "hostname" in q:
        ioc = q["hostname"]
        ioc_type = "hostname"
        url = cleanURL(q["hostname"])
        comment = urlscan(ioc, key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})

    if "url" in q:
        ioc = q["url"]
        ioc_type = "url"
        url = cleanURL(q["url"])
        comment = urlscan(ioc, key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
	
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
  
    # Remove the original attribute
    delete_mispAttribute(q,ioc, MISPurl, MISPkey)

    return r

def filescan(md5, key):

    r = []
    result = []

    params = {'resource': md5, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}

    # Request a rescan of the md5
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)

    # Get the rescanned results
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

    antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

    comment = ""

    # Parse the returned json result
    if response.text:
        res = json.loads(response.text)
        
        for antivirus in antivirusList:
            try:
                s = res["scans"]
                try:
                    d = s[antivirus]

                    if d["detected"] == True:
                        result = d["result"] 
                        update = d["update"]
                    elif d["detected"] == False:
                        result = "Not Detected"
                        update = d["update"]
                except KeyError:
                    result = "File not found"
                    update = "N/A"

            except KeyError:
                result = "File not found"
                update = "N/A"

            comment += antivirus + " Scan Result: " + result + " \nUpdate: " + update +"\n"
            print(comment)
        
    r.append({"types": ["md5"], "values": [md5], "comment": comment})

    return r

def urlscan(ioc, key):
    r = []
    result = []

    params = {'url': ioc, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}

    # Request a rescan of the url
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', params=params)

    # Get the rescanned results
    params = {'resource': ioc, 'apikey': key}
    response = requests.get('http://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)

    # Parse the returned json result
    if response.text:
        try:
            res = json.loads(response.text)
            positives = res['positives']
            total = res['total']
            date_st = res['scan_date'].find(" ")
            update = res['scan_date'][:date_st]
			
            comment = "Virustotal \r\nDetection Ratio: " + str(positives) + ' / ' + str(total) + "Update:" + update
            print(comment)
        except:
            comment = "Virustotal \r\nDetection Ratio: URL not found  Update: N/A"
			
    else:
        vt_ratio = "URL not found"
        vt_update = "N/A"
		
    return comment
			
def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url
			
        
	
def delete_mispAttribute(q, ioc, MISPurl, MISPkey):

    myMISPurl = MISPurl
    myMISPkey = MISPkey
    misp = init(myMISPurl, myMISPkey)

    eid = q["event_id"]
    event = misp.get_event(eid)

    attrib = []

    # Get Dict of Attributes
    for k, v in event.items():
        if isinstance(v, dict):
            for inK, inV in v.items():
                if inK == "Attribute" and isinstance(inV, list):
                    
                    for value in inV:
                        if isinstance(value, dict):
                            attrib.append(value)
                            


    # Delete attribute
    for attribute in attrib:
        if ioc in attribute.values():
            print("Found attribute")
            for k,v in attribute.items():
                if k =="id":
                    
                    misp.delete_attribute(v)

    return ""
	
	
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo