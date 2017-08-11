import json
import requests
from requests import HTTPError
import base64

misperrors = {'error': 'Error'}
mispattributes = {'input': ['url', 'hostname', 'domain', "ip-src", "ip-dst", "md5"],
                  'output': ['url', 'hostname', 'domain', 'ip-src', 'ip-dst', 'md5']
                  }

# possible module-types: 'expansion', 'hover' or both
moduleinfo = {'version': '2', 'author': 'Hannah Ward',
              'description': 'Get information from virustotal',
              'module-type': ['expansion']}

# config fields that your code expects from the site admin

def handler(q=False):
    global limit
    if q is False:
        return False
	
    q = json.loads(q)
	
    print(q)
    r=[]
    
     	
    return r

def introspection():
    return mispattributes


def version():
    #moduleinfo['config'] = moduleconfig
    return moduleinfo
