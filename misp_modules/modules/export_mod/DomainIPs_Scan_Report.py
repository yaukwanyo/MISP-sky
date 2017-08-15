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
from socket import *

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
   # csv.QUOTE_ALL
    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                status, webTrust = Sucuri(attribute["value"])
                p80 = portScan(attribute["value"],80)
                p443 = portScan(attribute["value"], 443)
                
                writer.writerow({
                    "Type": fieldmap[attribute["type"]],
                    "Value": attribute["value"],
                    "Virustotal Detection Ratio": "'" + virustotal(attribute["value"]),
                    "Quttera.com": Quttera(attribute["value"]),
                    "Sucuri": "Status: " + "\r\n" + status + "\r\n" + "\r\n" + "Web Trust: " + "\r\n" + webTrust,
                    "Port Status": "Port 80:" + "\r\n" + p80 + "\r\n" + "\r\n" + "Port 443:" + "\r\n" + p443
                })
    #csv.QUOTE_ALL                   
    r = {"response":[], "data":str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}
    return r

def startBrowsing():
    display = Display(visible=0, size=(800,600))
    display.start()
    driver = webdriver.Chrome()
    return driver

'''
def yougetsignal(url):
    driver = startBrowsing()

    driver.get("https://www.yougetsignal.com/tools/open-ports/")

    add_input = driver.find_element_by_xpath("//input[@id='remoteAddress']")
    add_input.send_keys(url)

    port_input = driver.find_element_by_xpath("//input[@id='portNumber']")
    port_input.send_keys("80")

    submit = driver.find_element_by_xpath("//input[@type='submit']").click()

    print("Checking port status~~")
    
    complete = WebDriverWait(driver,60).until(
        EC.visibility_of_element_located((By.XPATH, "//a[@href='http://'+ url]"))
    )
    

    time.sleep(10)
     

    p80 = driver.find_element_by_xpath("//div[@id='statusDescription']").text
    p80_close = p80.find("closed")
    p80_open = p80.find("open")
    p80_result = ""

    if p80_close > 0:
        p80_result = "Close"
    elif p80_open > 0:
        p80_result = "Open"
    
    return p80_result
            
def portStatus(driver, portNo):
    port_input = driver.find_element_by_xpath("//input[@id='portNumber']")
    port_input.send_keys(portNo)

    print("Checking port status")

    complete = WebDriverWait(driver, 60).until(
        EC.visibility_of_element_located((By.XPATH, "//    
'''

def portScan(url,portNo):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(2)
    result = s.connect_ex((url, portNo))
    if result == 0:
        status = "Open"
    else:
        status = "Close"
        #increase_error_count()
    s.close()
    return status

def increase_error_count():
    with open('/var/www/MISP/app/tmp/logs/ErrorCount.log') as f:
        for line in f:
            error_count = line
    error_count = int(error_count)
    print("Error counter: " + str(error_count))
    file = open('ErrorCount.log', 'w')
    file.write(str(error_count + 1))
    file.close()
    if error_count == 10:
        file = open('/var/www/MISP/app/tmp/logs/ErrorCount.log', 'w')
        file.write('0')
        file.close()


def Sucuri(url):

    driver = startBrowsing()

    driver.get("https://sitecheck.sucuri.net/results/" + url)

    print("SUCURI!!!")

    results = driver.find_elements_by_tag_name("td")

    endPos = results[3].text.find('"', 2)

    status = results[3].text[:endPos]

    endPos = results[5].text.find('"', 2)
    webTrust = results[5].text[:endPos]

    return status, webTrust
 
def Quttera(url):
    driver = startBrowsing()
    driver.get("http://quttera.com/sitescan/" + url)

    try:
        complete = WebDriverWait(driver, 60).until(
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
    
    print("submitted url!")

    try:
        reanalyze = WebDriverWait(driver, 300).until(
            EC.visibility_of_element_located((By.XPATH, "//a[@id='btn-url-reanalyse']"))
        )
    except TimeoutException:
        return ""
    
    reanalyze = driver.find_element_by_xpath("//a[@id='btn-url-reanalyse']").get_attribute('href')

    driver.get(reanalyze)

    print("Now reanalyzingggggg")
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

