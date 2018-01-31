import json
import base64
import re
import requests
import time
import os
from pyvirtualdisplay import Display
from pymisp.tools import stix
from collections import OrderedDict
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
import socket

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '1.0', 'author': 'SEC21',
              'description': 'Import stix and get IOC scan results',
              'module-type': ['import']}

moduleconfig = ["VTapikey"]


def handler(q=False):
    # Just in case we have no data
    if q is False:
        return False
	
    # The return value
    r = OrderedDict()
    r = {'results': []}
    comment = ""
	
    # Load up that JSON
    q = json.loads(q)

    # Get virustotal api key
    key = q["config"]["VTapikey"] 

    # It's b64 encoded, so decode that stuff
    package = base64.b64decode(q.get("data")).decode('utf-8')

    # If something really weird happened
    if not package:
        return json.dumps({"success": 0})

    pkg = stix.load_stix(package)

    for attrib in pkg.attributes:

        #If it's a md5, scan with virustotal API
        if "md5" in attrib.type:
            md5 = attrib.value
            
            VTAPIresult = vtAPIscan(md5,key)
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": VTAPIresult })

        #If it's domain or url, perform webcrawling			    
        elif "url" in attrib.type or "ip-dst" in attrib.type or "domain" in attrib.type:
            url = attrib.value
            # If the url contains directory or filename, remove them and create a new attribute
            if url.find("/", 8) > 0:
                pos = url.find("/", 8)
                print(pos)
                newURL = url[:pos]
                comment = scanURL(newURL,key)
                r["results"].append({"values":[newURL], "types":[attrib.type], "categories": [attrib.category], "comment": comment })
            comment = scanURL(url,key)
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": comment })
			
        else:
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": " "})
    return r

# Web crawling
def scanURL(url,key):
    vt_ratio, vt_update= vt_urlscan(url,key)
    quttera = Quttera(url)
    sucuri = Sucuri(url)
    port80 = portScan(url, 80)
    port443 = portScan(url, 443)
    comment = CombineScans(vt_ratio, vt_update, quttera, sucuri, port80, port443)
    return comment

# Start browser
def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    driver.set_page_load_timeout(40)
    return driver

# Scan ports using yougetsignal's api
def portScan(url, portNo):
    params = {"remoteAddress": url, "portNumber": portNo}
    print("Scanning " + url + "Port " + str(portNo) + "...")
    r = requests.post("https://ports.yougetsignal.com/check-port.php", params)
    page = r.text
    print(page)
    if "/img/flag_green.gif" in page:
        status = "Open"
    elif "/img/flag_red.gif" in page:
        status = "Close"
    else:
        status = "Invalid URL"
    print(str(portNo) + ": " +status)
    return status

#Combine scan results
def CombineScans(vt_ratio, vt_update, quttera, sucuri, port80, port443):
    toReturn = ""
    toReturn = "Virustotal \r\nDetection Ratio: " + vt_ratio +"  Update: " + vt_update +\
               " \r\nQuttera \r\nResult: \r\n" + quttera +\
               " \r\n " + sucuri +\
               " \r\nPort Status \r\nPort 80: \n" + port80 + " \r\nPort 443: \n" + port443 
    return toReturn

#Crawl sucuri	
def Sucuri(url):

    driver = startBrowsing()
    try:
        driver.get("https://sitecheck.sucuri.net/results/" + url)
    except TimeoutException:
        return "Sucuri \r\n Status: N/A \r\n Web Trust: N/A"

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
 
# Crawl Quttera
def Quttera(url):

    status = "N/A"
    driver = startBrowsing()
    print("Scanning " + url + " on Quttera...")

    try:
        driver.get("https://quttera.com/detailed_report/" + url)
    except TimeoutException:
        print("Scan failed")
        return status

    results = driver.find_elements_by_xpath("//div[@class='panel-heading']")
   
    for result in results:
        print(result.text)
        if "No Malware" in result.text:
            status = "Clean"
            break
        elif "Potentially Suspicious" in result.text:
            status = "Potentially Suspicious"
            break
        elif "Malicious" in result.text:
            status = "Malicious"
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
	
    print("Scanning " + ioc + " on virustotal...")
	
    # Get the rescanned results
    params = {'resource': ioc, 'apikey': key}
    response = requests.get('http://www.virustotal.com/vtapi/v2/url/report', params=params)

    countOftry = 1

    while not response.text:
        if countOftry < 20:
            time.sleep(2)
            countOftry += 1
            print("Try virustotal url scan again...")
            response = requests.get('http://www.virustotal.com/vtapi/v2/url/report', params=params)
        else:
            vt_ratio = "URL not found"
            vt_update = "N/A"    
            return vt_ratio, vt_update
			
    # Parse the returned json result

    try:
        res = json.loads(response.text)
        vt_ratio = str(res['positives']) + " / " + str(res['total'])
        date_st = res['scan_date'].find(" ")
        vt_update = res['scan_date'][:date_st]
			
    except:
        vt_ratio = "URL not found"
        vt_update = "N/A"
		
    return vt_ratio, vt_update

# Scan md5 via virustotal api	
def vtAPIscan(md5, key):

    result = OrderedDict()
    params = {'resource': md5, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}

    # Rescan the md5
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)

    # Retrieve the rescanned result
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

    print("Scanning " + md5 + " on virustotal...")
    countOftry = 1
    toReturn = ""
    antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

    while not response.text:
        if countOftry < 20:
            time.sleep(2)
            countOftry += 1
            print("Try virustotal file scan again...")
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        else:
            for antivirus in antivirusList:
                toReturn += " \r\n\r\n" + antivirus + " Scan Result:\r\n File not found" + " \r\nUpdate: N/A"
            return toReturn

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
                    result = "Not Mentioned"
                    update = "N/A"
            except KeyError:
                 result = "File Not Found"
                 update = "N/A"
	
            toReturn += " \r\n\r\n" + antivirus + " Scan Result:\r\n " + result + " \r\nUpdate:\r\n " + update

    print(toReturn)
    return toReturn

def introspection():
    modulesetup = {}
    try:
        userConfig
        modulesetup['userConfig'] = userConfig
    except NameError:
        pass
    try:
        inputSource
        modulesetup['inputSource'] = inputSource
    except NameError:
        pass
    return modulesetup


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo