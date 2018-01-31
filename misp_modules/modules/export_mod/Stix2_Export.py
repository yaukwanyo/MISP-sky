import json
import base64
import datetime
import io
import pprint
from stix2 import Indicator, Malware, Report, Bundle


misperrors = {'error': 'Error'}

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '1', 'author': '(SEC)21 SSKYAU',
              'description': 'Export in STIX2.0 format',
              'module-type': ['export']}

moduleconfig = ["indent_json_export"]

outputFileExtension = ".json"
responseType = "application/json"

def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)


    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(request)
      
    if "config" in request:
        config = request['config']
    else:
        config = {"indent_json_export": None}

    if config['indent_json_export'] is not None:
        try:
            config['indent_json_export'] = int(config['indent_json_export'])
        except:
            config['indent_json_export'] = None

    if 'data' not in request:
        return False

    iocList = []

    for event in request['data']:
        for attribute in event["Attribute"]:
            ioc_type = attribute["type"]
            ioc_value = attribute["value"]
            scan_results = attribute["comment"]
            ioc = create_indicator(ioc_type, ioc_value, scan_results)
            iocList.append(ioc)

    bundle = Bundle(iocList)

    print(bundle)

    return {'response': [],
            'data': str(base64.b64encode(bytes(str(bundle), 'utf-8')), 'utf-8')}


    return r

def create_indicator(ioc_type, ioc_value, scan_results):
    if (ioc_type == "url") or (ioc_type == "ip-src") or (ioc_type == "ip_dst") or (ioc_type == "domain") or (ioc_type == "hostname"):
        ioc_pattern = "[url:value = '" + ioc_value + "']"
        indicator = Indicator(labels=["malicious-activity"], pattern=ioc_pattern, description=scan_results)

    if (ioc_type == "md5") or (ioc_type == "sha256"):
        ioc_pattern = "[file:hashes." + ioc_type + " = '" + ioc_value + "']"
        indicator = Indicator(labels=["malicious-activity"], pattern=ioc_pattern, description=scan_results)

    return indicator

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
