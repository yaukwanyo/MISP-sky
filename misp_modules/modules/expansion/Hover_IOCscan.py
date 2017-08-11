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
import time
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import argparse

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url', 'hostname', 'domain', "ip-src", "ip-dst", "md5"],
                  'output': ['url', 'hostname', 'domain', 'ip-src', 'ip-dst', 'md5']
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'SSKYAU@OGCIO',
              'description': 'Get Scan Results',
              'module-type': ['hover']}

# config fields that your code expects from the site admin
moduleconfig = ["VTapikey"]

def init(url,key):
    return PyMISP(url,key, False, 'json')

def handler(q=False):
    global limit
    if q is False:
        return False
	
    q = json.loads(q)
	
    key = q["config"]["VTapikey"]

    r = {"results": []}

    print (q)
	
    if "ip-src" in q:
        ioc = q["ip-src"]
        ioc_type = "ip-src"
        url = cleanURL(q["ip-src"])
        r["results"] += virustotal(url, "ip-src")
	#	r["results"] += sucuri(q["ip-src"])
        
		
    if "ip-dst" in q: 
        ioc = q["ip-dst"]
        ioc_type = "ip-dst"
        url = cleanURL(q["ip-dst"])
        r["results"] += virustotal(url, "ip-dst")
	#	r["results"] += sucuri(q["ip-dst"])
		
    if "domain" in q: 
        ioc = q["domain"]
        ioc_type = "domain"
        url = cleanURL(q["domain"])
        r["results"] += virustotal(url, "domain")
	#	r["results"] += sucuri(q["domain"])
		
    if "hostname" in q:
        ioc = q["hostname"]
        ioc_type = "hostname"
        url = cleanURL(q["hostname"])
        r["results"] += virustotal(url, "hostname")
	#	r["results"] += sucuri(q["hostname"])
		
    #if 'md5' in q:
        #ioc = q["md5"]
        #ioc_type = "md5"
    #    r["results"] += vtAPIscan(q['md5'], key)

    if "url" in q:
        ioc = q["url"]
        ioc_type = "url"
        url = cleanURL(q["url"])
        r["results"] += virustotal(url, "url")
	
    uniq = []
    for res in r["results"]:
        if res not in uniq:
            uniq.append(res)
    r["results"] = uniq
  
    print("Done scanning and storing!")

    #myMISPurl = 'http://192.168.56.50'
    #myMISPkey = '2WGtsQVM8ThD72afNgwu8Dd9F2hPUBIcOPuMtJRE'
    #misp = init(myMISPurl, myMISPkey)
    

    return r


def cleanURL(url):
	
    url = str(url)
    url = url.replace("[","")
    url = url.replace("]","")

    return url

def virustotal(url, type):

    r = []

    print(url)

    display = Display(visible=0, size = (800,600))
    display.start()
    driver = webdriver.Chrome()
	
    driver.get("https://www.virustotal.com/en/#url")

    element = WebDriverWait(driver, 60).until(
        EC.visibility_of_element_located((By.XPATH, "//input[@id='url']"))
    )
	
    elem = driver.find_element_by_xpath("//input[@id='url']")
    elem.send_keys(url)
	
    submit = driver.find_element_by_xpath("//button[@id='btn-scan-url']")
    submit.click()
	
    time.sleep(1)
	
    countOftry = 0

    '''
    try:
        reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')
        countOftry += 1
    except: 
        if countOftry < 10 :
            time.sleep(1)
            print("try virustotal again")
            reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')
            countOftry += 1
    '''
    element = WebDriverWait(driver, 6000).until(
        EC.visibility_of_element_located((By.XPATH, "//a[@id='btn-url-reanalyse']"))
    )
	
    reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')

    driver.get(str(reanalyze))
	
    element = WebDriverWait(driver,6000).until(
        EC.visibility_of_element_located((By.TAG_NAME, "td"))
    )
	
    cells = driver.find_elements_by_tag_name("td")
    ratio = cells[3].text
	
    comment = "VT Detection Ratio: " + ratio
	
    r.append({'types': [type], "values": [url], "comment": comment})
	
    return r
	
	
def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo
