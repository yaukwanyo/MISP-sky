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

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url', 'hostname', 'domain', "ip-src", "ip-dst", "md5"],
                  'output': ['url', 'hostname', 'domain', 'ip-src', 'ip-dst', 'md5']
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

    MISPurl = q["config"]["MISPurl"]
    MISPkey = q["config"]["MISPkey"] 

    r = {"results": []}

    print (q)
	
	# If the attribute is one of the following types, scan port and save the results as an new attribute
    if "ip-src" in q:
        ioc = q["ip-src"]
        ioc_type = "ip-src"
        url = cleanURL(q["ip-src"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
        
		
    if "ip-dst" in q: 
        ioc = q["ip-dst"]
        ioc_type = "ip-dst"
        url = cleanURL(q["ip-dst"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "domain" in q: 
        ioc = q["domain"]
        ioc_type = "domain"
        url = cleanURL(q["domain"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "hostname" in q:
        ioc = q["hostname"]
        ioc_type = "hostname"
        url = cleanURL(q["hostname"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})

    if "url" in q:
        ioc = q["url"]
        ioc_type = "url"
        url = cleanURL(q["url"])
        comment = scanURL(ioc) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
	
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
  
    # Remove the original attribute
    delete_mispAttribute(q,ioc, MISPurl, MISPkey)

    return r


def scanURL(ioc):
    port80 = portScan(ioc, 80)
    port443 = portScan(ioc, 443)

    toReturn = " \r\nPort Status \r\nPort 80: \n" + port80 + " \r\nPort 443: \n" + port443 
 
    return toReturn

	
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

# Remove possible symbols in url
def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url

# Scan ports using yougetsignal's api
def portScan(url, portNo):
    params = {"remoteAddress": url, "portNumber": portNo}
    r=requests.post("https://ports.yougetsignal.com/check-port.php", params)
    page = r.text
    if "/img/flag_green.gif" in page:
        status = "Open"
    elif "/img/flag_red.gif" in page:
        status = "Close"
    else:
        status = "Invalid URL"
    return status	
	
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
