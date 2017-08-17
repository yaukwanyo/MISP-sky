import json
import base64
import datetime
import csv
import io
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException
from pyvirtualdisplay import Display
import time
import socket 

misperrors = {'error': 'Error'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Export domain/ip scan results in csv format',
              'module-type': ['export']}

# config fields that your code expects from the site admin


fieldmap = {
    "domain": "Domains/IPs",
    "hostname": "Domain/IPs",
    "ip-src": "Domain/IPs",
    "ip-dst": "Domain/IPs",
    "url": "Domain/IPs"
}

mispattributes = {'input':list(fieldmap.keys())}
outputFileExtension = "csv"
responseType = "application/txt"

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    print(request)
    response = io.StringIO()
    writer = csv.DictWriter(response, fieldnames=["Type", "Value", "Virustotal Detection Ratio", "Quttera.com", "Sucuri", "Port Status"])

    writer.writeheader()
 
    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                p80 = portScan(attribute["value"],80)
                p443 = portScan(attribute["value"], 443)
                
                writer.writerow({
                    "Type": fieldmap[attribute["type"]],
                    "Value": attribute["value"],
                    "Virustotal Detection Ratio": "'" + virustotal(attribute["value"]),
                    "Quttera.com": Quttera(attribute["value"]),
                    "Sucuri": Sucuri(attribute["value"]),
                    "Port Status": "Port 80:" + "\r\n" + p80 + "\r\n" + "\r\n" + "Port 443:" + "\r\n" + p443
                })
                   
    r = {"response":[], "data":str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}
    return r

def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver

def portScan(url,portNo):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(2)
    print("Scanning " + url + " Port " + str(portNo))
    try:
        result = TCPsock.connect((url, portNo))
        if result == 0:
            status = "Open"
        else: 
            status = "Close"
    except:
        status = "Invalid URL"
    return status

def Sucuri(url):

    driver = startBrowsing()

    driver.get("https://sitecheck.sucuri.net/results/" + url)

    print("Scanning " + url + " on Sucuri...")

    results = driver.find_elements_by_tag_name("td")

    try:
        # Get status
        endPos = results[3].text.find('"', 2)
        status = results[3].text[:endPos]

        # Get Web Trust
        endPos = results[5].text.find('"', 2)
        webTrust = results[5].text[:endPos]
        if ":" in webTrust:
            endPos = webTrust.find(":", 2)
            webTrust = webTrust[:endPos]
    except:
        status = "Invalid URL"
        webTrust = "Invalid URL"

    toReturn = ""
    toReturn = "Sucuri \r\n Status: \r\n" + status + "\r\n\r\nWeb Trust: " + webTrust + " \r\n"

    return toReturn
 
def Quttera(url):
    driver = startBrowsing()
    driver.get("http://quttera.com/sitescan/" + url)

    print("Scanning " + url + " on Quttera...")

    try:
        complete = WebDriverWait(driver, 40).until(
            EC.visibility_of_element_located((By.XPATH, "//div[@id='ResultSummary']"))
        )
    except:
        try:
            malicious = driver.find_element_by_xpath("//div[@class='alert alert-m']").text
        except:
            result = "Unreachable"
            return result

        if "Malicious" in malicious:
            result = malicious
        '''
        else: 
            result = "Unreachable"
        '''
    summary = driver.find_element_by_xpath("//div[@id='ResultSummary']")
    scanResult = summary.find_elements_by_tag_name("h4")

    status = str(scanResult[0].text)

    print (isinstance(status, str))
    print (status)

    if "No Malware Detected" in status:
        result = "Clean"
    elif "Potentially Suspicious" in status:
        result = "Potentially Suspicious"
    elif "Malicious" in status:
        result = "Malicious"
    else: 
        result = ""

    return result
        
def virustotal(url):
    display = Display(visible=0, size = (800,600))
    display.start()
    driver = webdriver.Chrome()
    driver.get("https://www.virustotal.com/en/#url")
    
    url_input = WebDriverWait(driver, 60).until(
        EC.visibility_of_element_located((By.XPATH, "//input[@id='url']"))
    )

    url_input = driver.find_element_by_xpath("//input[@id='url']")
    url_input.send_keys(url)
    submit = driver.find_element_by_xpath("//button[@id='btn-scan-url']")
    submit.click()
    print("Scanning " + url + " on virustotal...")

    try:
        reanalyze = WebDriverWait(driver, 300).until(
            EC.visibility_of_element_located((By.XPATH, "//a[@id='btn-url-reanalyse']"))
        )
    except TimeoutException:
        return ""
    
    reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')

    driver.get(reanalyze)

    print("\tReanalyzing URL")
    element = WebDriverWait(driver, 6000).until(
        EC.visibility_of_element_located((By.TAG_NAME, "td"))
    )
    
    cells = driver.find_elements_by_tag_name("td")
    ratio = cells[3].text
    
    return ratio

def introspection():
  modulesetup = {}
  try:
        responseType
        modulesetup['responseType'] = responseType
  except NameError:
      pass
  try:
      userConfig
      modulesetup['userConfig'] = userConfig
  except NameError:
      pass
  try:
      outputFileExtension
      modulesetup['outputFileExtension'] = outputFileExtension
  except NameError:
      pass
  try:
      inputSource
      modulesetup['inputSource'] = inputSource
  except NameError:
      pass
  return modulesetup

def version():
    #moduleinfo['config'] = moduleconfig
    return moduleinfo

