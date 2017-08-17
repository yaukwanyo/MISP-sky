import json
from urllib import request
from urllib import error
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import argparse
import datetime
from datetime import date, datetime, timedelta
from collections import OrderedDict
from calendar import timegm
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
#from email.MIMEMultipart import MIMEMultipart
#from email.MIMEBase import MIMEBase
#from email.MIMEText import MIMEText
from email.utils import COMMASPACE,formatdate
#from email.encoders import Encoders
import os

def init(url,key):
    return PyMISP(url, key, False, 'json')

def search_dict_in_list(list):
    for k in list:
        if isinstance(k,dict):
            return k

def search_list_in_dict(d):
    for k, v in d.items():
        if isinstance(v, list):
            return v

def sendMail(to, fro, subject, text, server="localhost"):
    assert type(to) == list

    msg = MIMEMultipart()
    msg["From"] = fro
    msg["To"] = COMMASPACE.join(to)
    msg["Date"] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    smtp = smtplib.SMTP(server)
    smtp.sendmail(fro,to,msg.as_string())
    smtp.close

def getValue(d, key):
    for k, v in d.items():
        if k == key:
            return v

def emailBody(d):
    body = ""
    for i in range(len(d['eventid'])):
        body += "=============================================================== \r\n" + \
                "URL \t: https://192.168.56.50/events/view/" + d['eventid'][i] + \
                "\r\nEventID \t: " + d['eventid'][i] + \
                "\r\nEvent Info \t: " + d['info'][i]+ \
                "\r\nDate: \t: " + d['date'][i] + \
                "\r\n=============================================================== \r\n"
    print(body)
    return body

def emailSubject(d):
    subject = ""
    for info in d['info']:
        subject += "[" + info + "]"
    subject += " MISP Event Update"

    print(subject)

    return subject


myMISPurl = 'http://192.168.56.50/'
myMISPkey = '2WGtsQVM8ThD72afNgwu8Dd9F2hPUBIcOPuMtJRE'
misp = init(myMISPurl, myMISPkey)


today = date.today().strftime("%Y-%m-%d")

update = misp.search(date_from=today, published="0")

events = search_list_in_dict(update)

#event = search_dict_in_list(event)

eventIDs = []
eventInfos = []
attributeCounts = []
dates = []

count = 0
for event in events:
    count +=1
    print("Event" + str(count))
    if isinstance(event,dict):
        for k,v in event.items():
            print(k,v)
            if isinstance(event, dict):
                if timegm(datetime.utcnow().utctimetuple()) - int(v["timestamp"])<=300 and \
                   v["id"] not in eventIDs:
                    eventIDs.append(v["id"])
                    eventInfos.append(v["info"])
                    attributeCounts.append(v["attribute_count"])
                    dates.append(v['date'])                
                    
d = OrderedDict()

d = {"eventid": eventIDs, "info": eventInfos, "attributeCount": attributeCounts, "date": dates}

print (d)
                
print("Users")
users = misp.get_users_list()

to = []

for user in users:

    for k, v in user.items():
        if k == "User":
            if v["role_id"] == "3":
                to.append(v['email'])
           # for inK, inV in v.items():
            #    print(inK, inV)

print(to)

if len(d['eventid']) > 0:
    sendMail(to, "MISP", emailSubject(d), emailBody(d))                

'''
    event = misp.get_event(eid)

    attrib = []

    # Get Dict of Attributes
    for k, v in event.items():
        if isinstance(v, dict):
            for inK, inV in v.items():
                if inK == "Attribute" and isinstance(inV, list):
                    print("Hello", inV)
                    for value in inV:
                        if isinstance(value, dict):
                            attrib.append(value)
                            


    # Delete attribute
    for attribute in attrib:
        if ioc in attribute.values():
            print("Found attribute!")
            for k,v in attribute.items():
                if k =="id":
                    print(k,v)
                    misp.delete_attribute(v)
'''

