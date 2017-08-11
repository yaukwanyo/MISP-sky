import json
import base64
import datetime
import csv
import io

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
    writer = csv.DictWriter(response, fieldnames=["Type", "Value", "Virustotal Detection Ratio", "Quttera.com", "Sucuri Status", "Sucuri Web Trust",  "yougetsignal.com"])

    writer.writeheader()
   # csv.QUOTE_ALL
    for event in request["data"]:
        for attribute in event["Attribute"]:
            if attribute["type"] in mispattributes["input"]:
                writer.writerow({
                    "Type": fieldmap[attribute["type"]],
                    "Value": attribute["value"],
                    "Virustotal Detection Ratio": getvtResult(attribute["comment"])
                    #"Quttera.com": getQutteraResult(attribute["comment"]),
                    #"Sucuri Status": getSucuriResult(attribute["comment"]),
                    #"yougetsignal.com": getsignal(attribute["comment"])
                })
    #csv.QUOTE_ALL                   
    r = {"response":[], "data":str(base64.b64encode(bytes(response.getvalue(), 'utf-8')), 'utf-8')}
    return r

def getvtResult(comment):
    stPos = comment.find("tio: ")
    endPos = comment.find(" Sucuri")
    if endPos > 0:
        vt = comment[stPos+5:endPos]
    else:
        vt = comment[stPos+5:]
    return vt

#def getSucuriResult(comment):
    #stPos = comment.find(

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

