import json
import base64
import datetime
import csv
import io
from collections import OrderedDict
import time
import requests
from requests import HTTPError

misperrors = {'error': 'Error'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': 'Hannah Ward',
              'description': 'Export domain/ip scan results in csv format',
              'module-type': ['export']}

# config fields that your code expects from the site admin


fieldmap = {
    "md5": "File"
}
moduleconfig = ["VTapikey"]
mispattributes = {'input':list(fieldmap.keys())}
outputFileExtension = "csv"
responseType = "application/txt"

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    key = request.get("config", {"VTapikey": ""})
    key = key["VTapikey"]    
    response = io.StringIO()
    writer = csv.DictWriter(response, fieldnames=["MD5", "Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"])

    writer.writeheader()
    
    result = OrderedDict()

    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                result = vtAPIscan(attribute["value"], key)
               
                if bool(result) == True:
                    
                    writer.writerow({
                        "MD5": attribute["value"],
                        "Fortinet": result["Fortinet"],
                        "Kaspersky": result["Kaspersky"],
                        "McAfee": result["McAfee"],
                        "Symantec": result["Symantec"],
                        "TrendMicro": result["TrendMicro"],
                        "TrendMicro-Housecall": result["TrendMicro-Housecall"]
                    })    
                else:
                    writer.writerow({
                        "MD5": attribute["value"],
                        "Fortinet": "File not found",
                        "Kaspersky": "File not found",
                        "McAfee": "File not found",
                        "Symantec": "File not found",
                        "TrendMicro": "File not found",
                        "TrendMicro-Housecall": "File not found"
                    }) 
                 
    r = {"response":[], "data":str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}

    return r

def vtAPIscan(md5, key):

    result = OrderedDict()
    print(md5)
    print(key)
    params = {'resource': md5, 'apikey': key}
    headers = {'Accept-Encoding': "gzip, deflate", "User-Agent": "gzip, My Python requests library example client or username"}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan', params=params)
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)

    countOftry = 1
    while not response.text:
        if countOftry<10:
            time.sleep(1)
            countOftry += 1
            print("Try virustotal file scan again")
            response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        else:
            return []

    print(response.text)
    
    antivirusList = ["Fortinet", "Kaspersky", "McAfee", "Symantec", "TrendMicro", "TrendMicro-Housecall"]

    if response.text:
        json_response = response.json()
            
        result = getScanResults(json_response, antivirusList)

    return result

def getResults(scanReportDict, antivirus):
    for k,v in scanReportDict.items():
       if k == antivirus:
            for inK, inV in v.items():
                if inK == "result" and inV != "None":
                    scanResult = inV
                    detected = True
                elif inK == "update":
                    scanUpdate = inV
                elif inK == "detected" and inV == False:
                    detected = False
                    print("No Virus!!!!!")
            if detected == False:
                return "Clean", scanUpdate
            else:
                return scanResult, scanUpdate
    return "Not mentioend", "N/A" 

def getScanResults(json_response, antivirusList):
    d = OrderedDict()

    if "scans" in json_response:
        scanReportDict = json_response["scans"]
        print("got results!!:D")

        for antivirus in antivirusList:
            d[antivirus], d[antivirus + " Scan Date"] = getResults(scanReportDict, antivirus)
    '''       
    else: 
        for antivirus in antivirusList:
            d[antivirus], d[antivirus + " Scan Date"] = "File not found", "N/A"
    '''
    return d

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
    moduleinfo['config'] = moduleconfig
    return moduleinfo
