import json
import base64
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

misperrors = {'error': 'Error'}
userConfig = {}
inputSource = ['file']

moduleinfo = {'version': '0.2', 'author': 'SK',
              'description': 'Import some stix stuff',
              'module-type': ['import']}

moduleconfig = []


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

    # It's b64 encoded, so decode that stuff
    package = base64.b64decode(q.get("data")).decode('utf-8')

    # If something really weird happened
    if not package:
        return json.dumps({"success": 0})

    pkg = stix.load_stix(package)
    for attrib in pkg.attributes:

        if "md5" in attrib.type:
            md5 = attrib.value
            #print(md5)
            d = OrderedDict()
            responseDict = getFileReport(md5)
            #print("finished getting report! :DD")
            if "scans" in responseDict:
                scanReportDict = responseDict["scans"]
                d["Fortinet"], d["Fortinet Scan Date"] = GetScanResult(scanReportDict, "Fortinet")
                d["Kaspersky"], d["Kaspersky Scan Date"] = GetScanResult(scanReportDict, "Kaspersky")
                d["McAfee"], d["McAfee Scan Date"] = GetScanResult(scanReportDict, "McAfee")
                d["Symantec"], d["Symantec Scan Date"] = GetScanResult(scanReportDict, "Symantec")
                d["TrendMicro"], d["TrendMicro Scan Date"] = GetScanResult(scanReportDict, "TrendMicro")

                d["TrendMicro-Housecall"], d["TrendMicro-Housecall Scan Date"] = GetScanResult(scanReportDict, "TrendMicro-Housecall")
            else:
                d["Fortinet"], d["Fortinet Scan Date"] = "File not found on Virustotal", "N/A"
                d["Kaspersky"], d["Kaspersky Scan Date"] = "File not found on Virustotal", "N/A"
                d["McAfee"], d["McAfee Scan Date"] = "File not found on Virustotal", "N/A"
                d["Symantec"], d["Symantec Scan Date"] = "File not found on Virustotal", "N/A"
                d["TrendMicro"], d["TrendMicro Scan Date"] = "File not found on Virustotal", "N/A"
                d["TrendMicro-Housecall"], d["TrendMicro-Housecall Scan Date"] = "File not found on Virustotal", "N/A"
            
            antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

            for antivirus in antivirusList:
                comment += antivirus + " \n " + "Result: " +  d[antivirus] + " \r\n " + "Update: " + d[antivirus + " Scan Date"]
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": comment })
        
        elif "url" in attrib.type or "ip-dst" in attrib.type or "domain" in attrib.type:
            url = str(attrib.value)
            url = url.replace("[","")
            url = url.replace("]","")
            display = Display(visible=0, size = (800,600))
            display.start()
            driver = webdriver.Chrome()
            ratio = virustotal(url)
            status, webTrust = sucuri(url)
            comment = "\r\n Virustotal Detection ratio: \r\n " + ratio + "\r\n Sucuri \r\n Status: " + status + "\r\n Web Trust: " + webTrust
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category], "comment": comment})

           # p80, p443 = youGetSignal(url)
           # r["results"].append({"values": [p80], "types": ["comment"], "categories": [attrib.category]})
           # r["results"].append({"values": [p443], "types": ["comment"], "categories": [attrib.category]})
        else:
            r["results"].append({"values": [attrib.value], "types": [attrib.type], "categories": [attrib.category]})
    return r
    '''
    #Visit Virustotal
    display = Display(visible=0, size = (800,600))
    display.start()
    driver = webdriver.Chrome()
    #chromedriver = "/usr/local/bin/chromedriver"
    #os.environ["webdriver.chrome.driver"] = chromedriver
    #driver = webdriver.Chrome(chromedriver)
    '''
def youGetSignal(url):
    driver = webdriver.Chrome()
    driver.get("https://yougetsignal.com/tools/open-ports/")
    address = driver.find_element_by_id("remoteAddress")
    address.send_keys(url)
    portNo = driver.find_element_by_id("portNumber")
    portNo.send_keys("80")

    driver.execute_script("checkport(document.getElementbyID('remoteAddress'.value, document.getElementByID('portNumber').value")
    
    element = WebDriverWait(driver, 60).until(
        EC.visibility_of_element_located((By.XPATH, "//a[@href='http://en.wikipedia.org/wiki/Port_80']"))
    )
    
    if "open" in driver.find_element_by_id("statusDescription").text:
        p80_value = url + "\r\n Port 80: Open"
    elif "closed" in driver.find_element_by_id("statusDescription").text:
        p80_value = url + "\r\n Port 80: Close"
    else: p80_value = url + "\r\n Port 80: N/A"

    portNo.send_keys("443")
    driver.execute_script("checkport(document.getElementbyID('remoteAddres'.value, document.getElementByID('portNumber').value")

    #element = WebDriverWait((driver,60).until(
    #    EC.visibility_of_element_located((By.XPATH, "//a[@href='http://en.wikipedia.org/wiki/Port_443']"))
    #)
    
    #if "open" in driver.find_element_by_id("statusDescription").text:
    #    p443_value = url + "\r\n Port 443: Open"
    #    return value
    #elif "closed" in driver.find_element_by_id("statusDescription").text:
    #    p443_value = url + "\r\n Port 443: Close"
    #else: p443_value = url + "\r\n Port 443: N/A"

    return p80_value#, p443_value



def virustotal(url):
    print(url)
    driver = webdriver.Chrome()
    driver.get("https://www.virustotal.com/en/#url")
  
    #Input URL
    elem = driver.find_element_by_xpath("//input[@id='url']")
    elem.send_keys(url)
    #elem.submit()
    submit = driver.find_element_by_xpath("//button[@id='btn-scan-url']")
    submit.click()

    #form = driver.find_element_by_xpath("//form[@id='frm-url']")
    #form.submit()

    #Wait for page to load
    time.sleep(1)
    countOftry = 0
    
    try:
        element = WebDriverWait(driver, 60).until(
            EC.visibility_of_element_located((By.XPATH, "//a[@id='btn-url-reanalyse']"))
        )
    except TimeoutException:
        return ""
        
    #Reanalyze
    try:
        reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')
    except: return ""
    
    while reanalyze == "" and countOftry < 10:
        time.sleep(1)
        print("try virustotal scan again")
        reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')
            #try: 
            #    invalid_id = driver.find_element_by_xpath("//div[@id='dig-url-invalid']")
            #except:
            #    return ""
        countOftry += 1
    return ""
    
    print(str(reanalyze))
    
    driver.get(str(reanalyze))

    element = WebDriverWait(driver,6000).until(
        EC.visibility_of_element_located((By.TAG_NAME, "td"))
    )

    #Get results
    cells = driver.find_elements_by_tag_name("td")
    ratio = cells[3].text
    #date = cells[5].text

    #Epos = date.index("(")
    #date = date[0:Epos-1]
    
    return ratio
   

def sucuri(url):
    driver = webdriver.Chrome()
    driver.get("https://sitecheck.sucuri.net/results/"+url)
    try:
        table = driver.find_element_by_xpath("//table[@class='table main-result']")
    except:
        return "N/A", "N/A"
    
    cells = table.find_elements_by_tag_name("td")
    status = cells[3].text
    webTrust = cells[5].text

    return status, webTrust
    #else: return " ", " "

def GetScanResult(scanReportDict, antivirus):
    if antivirus in scanReportDict:
        scanResultDictOfAntivirus = scanReportDict[antivirus]
        if 'detected' in scanResultDictOfAntivirus:
            scanUpdate = ""
            if 'update' in scanResultDictOfAntivirus:
                scanUpdate = scanResultDictOfAntivirus['update']
            if (scanResultDictOfAntivirus['detected']):
                scanResult = ""
                if 'result' in scanResultDictOfAntivirus:
                    scanResult = scanResultDictOfAntivirus['result']
                return scanResult, scanUpdate
            return "File not detected", scanUpdate
    return "{} not mentioned in Virustotal search result".format(antivirus), "N/A"

def getFileReport(md5):
    params = {'resource': md5, 'apikey': 'c013e4ec7d8bb6264bf62727845a20e93fc8380e2e23c9dbc748dcb542745ff5'}
    headers = {"Accept-Encoding": "gzip, deflate", "User-Agent" : "gzip, My Python requests llibrary example client or username"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    #count_of_try = 1
    #while not response.text:
    #    if count_of_try < 3:
    #        time.sleep(1)
    #        count_of_try = count_of_try + 1
    #        print ("Try Virustotal file scan again {} : {}".format(count_of_try, md5))
    #        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    ##    else: return ""
    if response.text: 
        json_response = response.json()
        return json_response
    return ""

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
