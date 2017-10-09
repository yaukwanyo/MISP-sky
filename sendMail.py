import pymysql.cursors
from datetime import datetime
import pymisp as pm
from pymisp import PyMISP
from pymisp import MISPEvent
import json

def ConnectToMySQL():
    connection = pymysql.connect(
        user = "root",
        password = "Password1234",
        database = "misp_json",
        autocommit = True
    )

    cursor = connection.cursor(pymysql.cursors.DictCursor)
    return cursor

def FindUnhandledMail(cursor):
    cursor.execute("Select * from `events` where email_sent=0")

    # Store query results
    rows = cursor.fetchall()

    # Create email content, mailing list for every unhandled events and update corresponding records in database
    for row in rows:
        content = composeEmail(row)
        mailList = getMailingList(row["distribution"], row["org_id"], row["sharing_group_id"])
        sendMail(mailList, content)
        cursor.execute("Update `events` Set email_sent = 1 Where id = %s",(int(row["id"]),))
        print("Database updated!")

# Send mail function (To be completed)
def sendMail(mailList, content):
    print("Sent!")

def composeEmail(r):
    content = "Event info: " + r["info"] + \
              "\nEvent id: " + str(r["event_id"]) + \
              "\nCreate date: " + r["create_date"].strftime("%Y-%m-%d")
    print(content)

# Generate mailing lists according to distribution settings        
def getMailingList(distribution, org, sharing_group):
    print("Generating mailing list...")
    print("Distribution:" + str(distribution))

    misp = ConnectToPyMISP()

    # Distribution: My organisation only(0)
    if distribution == 0:
        mailList = []
        mailList = FindUsersInOrg(misp, org, mailList)

        print(mailList)  

    # Distribution: This community only(1), Connected Communities(2), All communities(3)   
    elif distribution == 1 or 2 or 3:
        mailList = []

        for user in users:
            mailList.append(user["User"]["email"])

        print(mailList)

    # Distribution: Sharing group(4)
    elif distribution == 4:
        mailList = []
        userList = []
        
        orgList = FindSharingGroupMembers(misp, sharing_group)
        
        for org in orgList:
            userList += FindUsersInOrg(misp, org, mailList)

        for user in userList:

            if user not in mailList:
                mailList.appen(user)

        print(mailList)

def FindUsersInOrg(misp, org, mailList):
    users= misp.get_users_list()

    for user in users:

        if user["Organisation"]["id"] == str(org):
            print("Found Organisation member!")
            mailList.append(user["User"]["email"])

    return mailList

def FindSharingGroupMembers(misp, sharing_group_id):
    orgList = []
    SharingGroups = misp.get_sharing_groups()

    for SharingGroup in SharingGroups:
        
        if SharingGroup["SharingGroup"]["id"] == str(sharing_group_id):

            for org in SharingGroup["SharingGroupOrg"]:
                orgList.append(org["org_id"])        

    return orgList

def ConnectToPyMISP():
    myMISPurl = "http://192.168.56.50/"
    myMISPkey = "2WGtsQVM8ThD72afNgwu8Dd9F2hPUBIcOPuMtJRE"

    misp = PyMISP(myMISPurl, myMISPkey)
    return misp


cursor = ConnectToMySQL()
FindUnhandledMail(cursor)
