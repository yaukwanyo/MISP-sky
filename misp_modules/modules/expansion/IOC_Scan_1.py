import json
import requests
from requests import HTTPError
import base64
from pyvirtualdisplay import Display
from selenium import webdriver
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import TimeoutException
import time
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import argparse
from collections import OrderedDict
import socket

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url', 'hostname', 'domain', "ip-src", "ip-dst", "md5", 'sha256'],
                  'output': ['url', 'hostname', 'domain', 'ip-src', 'ip-dst', 'md5','sha256']
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
	
	# If the attribute belongs to any of the following types, perform scan and save results as an new attribute
    if "ip-src" in q:
        ioc = q["ip-src"]
        ioc_type = "ip-src"
        url = cleanURL(q["ip-src"])
        comment = scanURL(ioc,key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
        
		
    if "ip-dst" in q: 
        ioc = q["ip-dst"]
        ioc_type = "ip-dst"
        url = cleanURL(q["ip-dst"])
        comment = scanURL(ioc,key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "domain" in q: 
        ioc = q["domain"]
        ioc_type = "domain"
        url = cleanURL(q["domain"])
        comment = scanURL(ioc,key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if "hostname" in q:
        ioc = q["hostname"]
        ioc_type = "hostname"
        url = cleanURL(q["hostname"])
        comment = scanURL(ioc,key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
		
    if 'md5' in q:
        ioc = q["md5"]
        ioc_type = "md5"
        r["results"] += vtAPIscan(q['md5'], key, ioc_type)

    if 'sha256' in q:
        ioc = q['sha256']
        ioc_type = 'sha256'
        r['results'] += vtAPIscan(q['sha256'], key, ioc_type)

    if "url" in q:
        ioc = q["url"]
        ioc_type = "url"
        url = cleanURL(q["url"])
        comment = scanURL(ioc,key) 
        r["results"].append({'types': [ioc_type], "values": [url], "comment": comment})
	
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
  
    # Remove the original attribute 
    delete_mispAttribute(q, ioc, MISPurl, MISPkey)

    return r

# Combine the scanning jobs together
def scanURL(ioc,key):
    vt_ratio, vt_update = vt_urlscan(ioc,key)
    quttera = Quttera(ioc)
    sucuri = Sucuri(ioc)
    port80 = portScan(ioc, 80)
    port443 = portScan(ioc, 443)
	
    toReturn = "Virustotal \r\nDetection Ratio: " + vt_ratio +"  Update: " + vt_update +\
               " \r\nQuttera \r\nResult: \r\n" + quttera +\
               " \r\n" + sucuri +\
               " \r\nPort Status \r\nPort 80: \n" + port80 + " \r\nPort 443: \n" + port443 
    return toReturn

# Setup browser    
def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver

# Scan ports using yougetsignal's api
def portScan(url, portNo):
    params = {"remoteAddress": url, "portNumber": portNo}
    r = requests.post("https://ports.yougetsignal.com/check-port.php", params)
    page = r.text
    if "/img/flag_green.gif" in page:
        status = "Open"
    elif "/img/flag_red.gif" in page:
        status = "Close"
    else:
        status = "Invalid URL"
    return status
	
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

# Scan file hashes using virustotal's API
def vtAPIscan(value, key, ioc_type):

    r = []
    result = []

    params = {'resource': value, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}

    # Request a rescan of the file hash
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)

    # Get the rescanned results
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

    antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

    comment = ""

    # Parse json results
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
                    result= "Not Mentioned"
                    update= "N/A"
                    
            except KeyError:
                result = "File not found"
                update = "N/A"
           
            comment += antivirus + " Scan Result: " + result + " \nUpdate: " + update + "\n"
            print(comment)

    r.append({"types": [ioc_type], "values": [value], "comment": comment})

    return r

# Remove possible symbols in URL
def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url

# Get scan results from Sucuri
def Sucuri(url):

    driver = startBrowsing()
    driver.get("https://sitecheck.sucuri.net/results/" + url)

    print("Scanning " + url + " on Sucuri...")
    results = driver.find_elements_by_tag_name("td")

    try:
        #Get status
        endPos = results[3].text.find('"', 2)
        status = results[3].text[:endPos]

        #Get Web Trust
        endPos = results[5].text.find('"', 2)
        webTrust = results[5].text[:endPos]
        if ":" in webTrust:
            endPos = webTrust.find(":", 2)
            webTrust = webTrust[:endPos]

    except:
        status = "Invalid URL"
        webTrust = "Invalid URL"

    toReturn = ""
    toReturn = "Sucuri \r\n Status: \r\n" + status + " \r\nWeb Trust: " + webTrust + " \r\n"
	
    return toReturn

# Get scan results from Quttera	
def Quttera(url):

    status = "N/A"
    driver = startBrowsing()
    print("Scanning " + url + " on Quttera...")
    try:
        driver.get("http://quttera.com/detailed_report/" + url)
    except TimeoutException:
        print("Scan failed")
        return status
		
    results = driver.find_elements_by_xpath("//div[@class='panel-heading']")
    
    for result in results:
        print(result.text)
        if "Potentially Suspicious" in result.text:
            status = "Potentially Suspicious"
            break
        elif "Malicious" in result.text:
            status = "Malicious"
            break
        elif "No Malware" in result.text:
            status = "Clean"
            break
        else: 
            status = "Unreachable"
    
    print(status)
    return status		

def vt_urlscan(ioc, key):
    r = []
    result = []

    params = {'url': ioc, 'apikey': key}

    # Request a rescan of the url
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', params=params)

    # Get the rescanned results
    params = {'resource': ioc, 'apikey': key}
    response = requests.get('http://www.virustotal.com/vtapi/v2/url/report', params=params)

    # Parse the returned json result
    if response.text:
        try:
            res = json.loads(response.text)
            vt_ratio = str(res['positives']) + " / " + str(res['total'])
            date_st = res['scan_date'].find(" ")
            vt_update = res['scan_date'][:date_st]
			
        except:
            vt_ratio = "URL not found"
            vt_update = "N/A"

    else:
        vt_ratio = "URL not found"
        vt_update = "N/A"
		
    return vt_ratio, vt_update
	
	
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
