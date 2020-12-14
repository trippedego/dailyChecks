import requests
import base64
import argparse
import sys
import time
import pytz
import os.path
from os import path
from datetime import datetime

# GO TO MAIN, THERE ARE SOME THINGS TO CHANGE MANUALLY
# Written by Peter Kotsiris in Python 3.7.3
# Grab event data from AMP, returning the last "X" amount of high priority events in AMP
# Grab request data from Umbrella, returning the number of events per hour as well as requests per hour for high priority categories 
# AMP range and Umbrella range are configurable, see help (--help, -h)

parser = argparse.ArgumentParser()
parser.add_argument("-u", "--umbrella", action='store_true', help="Only run checks for Umbrella. Default: Runs both")
parser.add_argument("-a", "--amp", action='store_true', help="Only run checks for AMP. Default: Runs both")
parser.add_argument("-ur", "--umbrellaRange", type=str, help="How far back you want to go in Umbrella, max is 25 hours. Default: 25 (last 25 hours)")
parser.add_argument("-ar", "--ampRange", type=str, help="How many AMP events you want to return. Default: 10")
parser.add_argument("-o", "--outFile", type=str, help="Name of file to save command output to.")
args = parser.parse_args()

def getUmbrellaOAuth(umbrellaApiKey, umbrellaApiSecret):

    message = umbrellaApiKey + ":" + umbrellaApiSecret
    apiToken = (base64.b64encode(message.encode('ascii')))
    apiToken = str(apiToken)
    apiToken = apiToken[2:-1]

    authURL = "https://management.api.umbrella.com/auth/v2/oauth2/token"

    authHeaders = {
        "accept": "application/json",
        "Authorization": "Basic {}".format(apiToken)
    }

    response = requests.request("GET", authURL, headers=authHeaders)
    onlyAuth = ''

    # Split the response by comma, and find the line that starts with access_token. 
    # Grab only the oAuth token, removing any other characters.
    cleanedResponse = response.text.split(",")
    for line in cleanedResponse:
        if (line.find("access_token") != -1):
            tempLine = line[16::]
            onlyAuth = tempLine[:-1]
    
    return onlyAuth


def getUmbrellaLogs(umbrellaClientID, umbrellaOAuthToken, client):

    url = "https://reports.api.umbrella.com/v2/organizations/{}/requests-by-hour".format(umbrellaClientID)
    
    if args.umbrellaRange:
        payload = {"from":"-1days","to":"now","limit":str(args.umbrellaRange)}
    else:
        payload = {"from":"-1days","to":"now","limit":"25"}

    domainHeaders = {
        "accept": "application/json",
        "authorization": "Bearer {}".format(umbrellaOAuthToken)
    }

    response = requests.request("GET", url, headers=domainHeaders, params=payload)

    splitHourResponse = response.text.split(",")

    url = "https://reports.api.umbrella.com/v2/organizations/{}/categories-by-hour".format(umbrellaClientID)

    payload = {"from":"-1days","to":"now","limit":"1"}

    domainHeaders = {
        "accept": "application/json",
        "authorization": "Bearer {}".format(umbrellaOAuthToken)
    }

    response = requests.request("GET", url, headers=domainHeaders, params=payload)

    tempSplitCategoryResponse = response.text.split('"date":')
    splitCategoryResponse = []

    for each in tempSplitCategoryResponse:
        splitCategoryResponse.append(each.split('"id":'))

    categoryList = []
    requestsList = []

    
    tempCategoryDictList = []
    for eachList in splitCategoryResponse:
        categories = {}
        #print (eachList[0])
        for num in range(len(eachList)):
            if eachList[num].find('"Adware"') != -1: 
                categories["Adware"] = eachList[num][eachList[num].find('"requests":')+11:-15]
                #print(eachList[num])
            if eachList[num].find('"Command and Control"') != -1: 
                categories["Command and Control"] = eachList[num][eachList[num].find('"requests":')+11:-15]
                #print(eachList[num])
            if eachList[num].find('"Malware"') != -1: 
                categories["Malware"] = eachList[num][eachList[num].find('"requests":')+11:-15]
                #print(eachList[num])
            if eachList[num].find('"Pornography"') != -1: 
                categories["Pornography"] = eachList[num][eachList[num].find('"requests":')+11:-15]
                #print(eachList[num])
            if eachList[num].find('"Illegal Activities"') != -1:
                categories["Illegal Activities"] = eachList[num][eachList[num].find('"requests":')+11:-15]
                #print(eachList[num])
        #print("\n")
        tempCategoryDictList.append(categories)
    
    
    categoryDictList = tempCategoryDictList[1::]

    dateList = []
    timeList = []
    requestsList = []

    for each in splitHourResponse:
        if each.find("date") != -1:
            temp = each.split(":")
            date = temp[1][1:-1]
            dateList.append(date)
        if each.find('"time"') != -1:
            time = each[each.find('":"')+3:-1]
            if time[-3::] == '"}]':
                time = time[:-3]
            timeList.append(time)
        if each.find('"requests"') != -1:
            numRequests = each[21::]
            requestsList.append(numRequests)
        

    umbrellaProblems = []   

    for num in range(len(dateList) - 1, -1, -1):
        formattedTime = dateList[num]+"T"+timeList[num]+"Z"
        dt = datetime.strptime(formattedTime, "%Y-%m-%dT%H:%M:%S%z")
        tz = pytz.timezone('US/Central')
        dt_cst = dt.astimezone(tz)
        timestamp = str(dt_cst).split(" ")
        line = ("On {} during {} CST, there were {} requests in Umbrella.".format(timestamp[0], timestamp[1][:-6], requestsList[num]))
        print(line)
        #for each in categoryDictList:
        
        this_dict = categoryDictList[num]
        for key, val in this_dict.items():
            #print(num)
            print("\t{} requests this hour: {}".format(key, val))

        print("\n")
        
    
 
def getAMPLogs(ampApiKey, ampClientID, client):
    message = ampClientID + ":" + ampApiKey
    apiToken = (base64.b64encode(message.encode('ascii')))
    apiToken = str(apiToken)
    apiToken = apiToken[2:-1]

    if args.ampRange:
        authURL = "https://api.amp.cisco.com/v1/events?event_type[]=1090519054&event_type[]=1107296272&event_type[]=2164260880&event_type[]=553648147&event_type[]=553648168&event_type[]=1107296273&event_type[]=1107296274&event_type[]=1107296284&event_type[]=1107296283&event_type[]=1090519103&event_type[]=1090519081&event_type[]=1090519112&event_type[]=1107296257&event_type[]=553648222&limit={}".format(str(args.ampRange))
    else:
        authURL = "https://api.amp.cisco.com/v1/events?event_type[]=1090519054&event_type[]=1107296272&event_type[]=2164260880&event_type[]=553648147&event_type[]=553648168&event_type[]=1107296273&event_type[]=1107296274&event_type[]=1107296284&event_type[]=1107296283&event_type[]=1090519103&event_type[]=1090519081&event_type[]=1090519112&event_type[]=1107296257&event_type[]=553648222&limit=10"
    
    authHeaders = {
        "Accept-Encoding": "gzip",
        "authorization": "Basic {}".format(apiToken)
    }

    response = requests.request("GET", authURL, headers=authHeaders)   

    eventList = []    
    tempEventList = response.text.split('"timestamp_nanoseconds"')
    newevent = []

    attackedModuleEP = []

    for eventt in tempEventList:
        if eventt.find('"Exploit Prevention"') != -1: # How to get the attacked_module
            tempModule = eventt[eventt.find("attacked_module")+18:eventt.find("base_address")-3]
            module_path = tempModule.replace('\\\\','\\')
            attackedModuleEP.append(str("Attacked Module: " + module_path))
        newevent.append(eventt.split('"parent"'))

    for event in newevent:
        if event[0].find('"metadata"') != -1:
            continue
        eventList.append(event[0])
        

    dateList = []
    timeList = []
    hostList = []
    eventType = []

    severityListTD = []
    dispositionListTD = []
    detectionListTD = []
    filenameListTD = []
    filepathListTD = []
    shaListTD = []
    trajectoryListTD = []
    userListTD = []
    descriptionListTD = []

    severityListCIOC = []
    dispositionListCIOC = []
    detectionListCIOC = []
    filenameListCIOC = []
    filepathListCIOC = []
    shaListCIOC = []
    trajectoryListCIOC = []
    userListCIOC = []
    descriptionListCIOC = []

    severityListSPP = []
    dispositionListSPP = []
    detectionListSPP = []
    filenameListSPP = []
    filepathListSPP = []
    shaListSPP = []
    trajectoryListSPP = []
    userListSPP = []
    descriptionListSPP = []

    severityListRD = []
    dispositionListRD = []
    detectionListRD = []
    filenameListRD = []
    filepathListRD = []
    shaListRD = []
    trajectoryListRD = []
    userListRD = []
    descriptionListRD = []

    filenameListEP = []
    filepathListEP = []
    trajectoryListEP = []
    userListEP = []

    severityListQF = []
    dispositionListQF= []
    trajectoryListQF = []
    userListQF = []
    descriptionListQF = []

    countTD = 0
    countCIOC = 0
    countSPP = 0
    countRD = 0
    countEP = 0
    countQF = 0

    #for event in eventList:
    for events in eventList:
        #print(line)
        eachEvent = []
        eachEvent = events.split(",")
        for line in eachEvent:
            if line.find('"date":"') != -1:
                tempDate = line[line.find('":"'):-7]
                date = tempDate[3::] + "Z"
                dt = datetime.strptime(date, "%Y-%m-%dT%H:%M:%S%z")
                tz = pytz.timezone('US/Central')
                date_cst = dt.astimezone(tz)
                tempList = str(date_cst).split(" ")
                tempList[1] = tempList[1][0:-6]
                dateList.append(tempList[0])
                timeList.append(tempList[1])

            if line.find('"hostname":"') != -1:
                tempHost = line[line.find('":"'):-1]
                host = tempHost[3::]
                hostList.append(host)

            if line.find('"event_type":"') != -1:
                event = line[line.find('":"')+3:-1]
                eventFormat = str("Event Type: " + event)
                eventType.append(eventFormat)

            try:
                if event == "Threat Detected" and line.find('"severity":"') != -1:
                    severity = line[line.find('":"')+3:-1]
                    severityListTD.append(str("Severity: " + severity))

                if event == "Threat Detected" and line.find('"disposition":"') != -1:
                    disposition = line[line.find('":"')+3:-1]
                    dispositionListTD.append(str("Disposition: " + disposition))

                if event == "Threat Detected" and line.find('"user":"') != -1:
                    user = line[line.find('":"')+3:-1]
                    if user == '':
                        user = "N/A"
                    userListTD.append(str("User: " + user))

                if event == "Threat Detected" and line.find('"detection":"') != -1:
                    detection = line[line.find('":"')+3:-1]
                    detectionListTD.append(str("Detection: " + detection))     

                if event == "Threat Detected" and line.find('"file_name":"') != -1:
                    file_name = line[line.find('":"')+3:-1]
                    filenameListTD.append(str("Filename: " + file_name)) 

                if event == "Threat Detected" and line.find('"file_path":"') != -1:
                    temptempFile_path = str(line[line.find('":"')+3:-1])
                    tempFile_path = temptempFile_path[7::]
                    file_path = tempFile_path.replace('\\\\','\\')
                    filepathListTD.append(str("File Path: " + file_path))

                if event == "Threat Detected" and line.find('"sha256":"') != -1:
                    sha = line[line.find('":"')+3:-1]
                    if sha[-3::] == '"}}':
                        sha = sha[:-3]
                    if sha[-1] == '"':
                        sha = sha[:-1]
                    shaListTD.append(str("SHA256 Hash: " + sha))
                
                if event == "Threat Detected" and line.find('"trajectory":"') != -1:
                    tempTrajectory = line[line.find('":"')+3:-1]
                    uuid = tempTrajectory[tempTrajectory.find("computers")+10:-11]
                    trajectory = "https://console.amp.cisco.com/computers/{}/trajectory2".format(str(uuid))
                    trajectoryListTD.append(str("Device Trajectory Link: " + trajectory))
                
                if event == "Cloud IOC" and line.find('"severity":"') != -1:
                    severity = line[line.find('":"')+3:-1]
                    severityListCIOC.append(str("Severity: " + severity))

                if event == "Cloud IOC" and line.find('"disposition":"') != -1:
                    disposition = line[line.find('":"')+3:-1]
                    dispositionListCIOC.append(str("Disposition: " + disposition))

                if event == "Cloud IOC" and line.find('"user":"') != -1:
                    user = line[line.find('":"')+3:-1]
                    userListCIOC.append(str("User: " + user))

                if event == "Cloud IOC" and line.find('"short_description":"') != -1:
                    detection = line[line.find('":"')+3:-2]
                    detectionListCIOC.append(str("Detection: " + detection))     

                if event == "Cloud IOC" and line.find('"file_name":"') != -1:
                    file_name = line[line.find('":"')+3:-1]
                    filenameListCIOC.append(str("Filename: " + file_name)) 

                if event == "Cloud IOC" and line.find('"file_path":"') != -1:
                    temptempFile_path = str(line[line.find('":"')+3:-1])
                    tempFile_path = temptempFile_path[7::]
                    file_path = tempFile_path.replace('\\\\','\\')
                    filepathListCIOC.append(str("File Path: " + file_path))

                if event == "Cloud IOC" and line.find('"sha256":"') != -1:
                    sha = line[line.find('":"')+3:-1]
                    if sha[-3::] == '"}}':
                        sha = sha[:-3]
                    if sha[-1] == '"':
                        sha = sha[:-1]
                    shaListCIOC.append(str("SHA256 Hash: " + sha))

                if event == "Cloud IOC" and line.find('"trajectory":"') != -1:
                    tempTrajectory = line[line.find('":"')+3:-1]
                    uuid = tempTrajectory[tempTrajectory.find("computers")+10:-11]
                    trajectory = "https://console.amp.cisco.com/computers/{}/trajectory2".format(str(uuid))
                    trajectoryListCIOC.append(str("Device Trajectory Link: " + trajectory))
                
                if event == "System Process Protection" and line.find('"severity":"') != -1:
                    severity = line[line.find('":"')+3:-1]
                    severityListSPP.append(str("Severity: " + severity))

                if event == "System Process Protection" and line.find('"disposition":"') != -1:
                    disposition = line[line.find('":"')+3:-1]
                    dispositionListSPP.append(str("Disposition: " + disposition))

                if event == "System Process Protection" and line.find('"user":"') != -1:
                    user = line[line.find('":"')+3:-1]
                    userListSPP.append(str("User: " + user))

                if event == "System Process Protection" and line.find('"detection":"') != -1:
                    detection = line[line.find('":"')+3:-1]
                    detectionListSPP.append(str("Detection: " + detection))     

                if event == "System Process Protection" and line.find('"file_name":"') != -1:
                    file_name = line[line.find('":"')+3:-1]
                    filenameListSPP.append(str("Filename: " + file_name)) 

                if event == "System Process Protection" and line.find('"file_path":"') != -1:
                    temptempFile_path = str(line[line.find('":"')+3:-1])
                    tempFile_path = temptempFile_path[7::]
                    file_path = tempFile_path.replace('\\\\','\\')
                    filepathListSPP.append(str("File Path: " + file_path))

                if event == "System Process Protection" and line.find('"sha256":"') != -1:
                    sha = line[line.find('":"')+3:-1]
                    if sha[-3::] == '"}}':
                        sha = sha[:-3]
                    if sha[-1] == '"':
                        sha = sha[:-1]
                    shaListSPP.append(str("SHA256 Hash: " + sha))

                if event == "System Process Protection" and line.find('"trajectory":"') != -1:
                    tempTrajectory = line[line.find('":"')+3:-1]
                    uuid = tempTrajectory[tempTrajectory.find("computers")+10:-11]
                    trajectory = "https://console.amp.cisco.com/computers/{}/trajectory2".format(str(uuid))
                    trajectoryListSPP.append(str("Device Trajectory Link: " + trajectory))

                if event == "Retrospective Detection" and line.find('"severity":"') != -1:
                    severity = line[line.find('":"')+3:-1]
                    severityListRD.append(str("Severity: " + severity))

                if event == "Retrospective Detection" and line.find('"disposition":"') != -1:
                    disposition = line[line.find('":"')+3:-1]
                    dispositionListRD.append(str("Disposition: " + disposition))

                if event == "Retrospective Detection" and line.find('"user":"') != -1:
                    user = line[line.find('":"')+3:-1]
                    if user == '':
                        user = "N/A"
                    userListRD.append(str("User: " + user))

                if event == "Retrospective Detection" and line.find('"detection":"') != -1:
                    detection = line[line.find('":"')+3:-1]
                    detectionListRD.append(str("Detection: " + detection))     

                if event == "Retrospective Detection" and line.find('"file_name":"') != -1:
                    file_name = line[line.find('":"')+3:-1]
                    filenameListRD.append(str("Filename: " + file_name)) 

                if event == "Retrospective Detection" and line.find('"file_path":"') != -1:
                    temptempFile_path = str(line[line.find('":"')+3:-1])
                    tempFile_path = temptempFile_path[7::]
                    file_path = tempFile_path.replace('\\\\','\\')
                    filepathListRD.append(str("File Path: " + file_path))

                if event == "Retrospective Detection" and line.find('"sha256":"') != -1:
                    sha = line[line.find('":"')+3:-1]
                    if sha[-5::] == '"}}}]':
                        sha = sha[:-5]
                    elif sha[-3::] == '"}}':
                        sha = sha[:-3]
                    elif sha[-1] == '"':
                        sha = sha[:-1]
                    shaListRD.append(str("SHA256 Hash: " + sha))
                
                if event == "Retrospective Detection" and line.find('"trajectory":"') != -1:
                    tempTrajectory = line[line.find('":"')+3:-1]
                    uuid = tempTrajectory[tempTrajectory.find("computers")+10:-11]
                    trajectory = "https://console.amp.cisco.com/computers/{}/trajectory2".format(str(uuid))
                    trajectoryListRD.append(str("Device Trajectory Link: " + trajectory))

                if event == "Exploit Prevention" and line.find('"user":"') != -1:
                    user = line[line.find('":"')+3:-1]
                    if user == '':
                        user = "N/A"
                    userListEP.append(str("User: " + user))
                
                if event == "Exploit Prevention" and line.find('"file_name":"') != -1:
                    file_name = line[line.find('":"')+3:-1]
                    filenameListEP.append(str("Filename: " + file_name)) 

                if event == "Exploit Prevention" and line.find('"file_path":"') != -1:
                    temptempFile_path = str(line[line.find('":"')+3:-1])
                    tempFile_path = temptempFile_path
                    file_path = tempFile_path.replace('\\\\','\\')
                    filepathListEP.append(str("File Path: " + file_path))

                if event == "Exploit Prevention" and line.find('"trajectory":"') != -1:
                    tempTrajectory = line[line.find('":"')+3:-1]
                    uuid = tempTrajectory[tempTrajectory.find("computers")+10:-11]
                    trajectory = "https://console.amp.cisco.com/computers/{}/trajectory2".format(str(uuid))
                    trajectoryListEP.append(str("Device Trajectory Link: " + trajectory))
                
                if event == "Quarantine Failure" and line.find('"severity":"') != -1:
                    severity = line[line.find('":"')+3:-1]
                    severityListQF.append(str("Severity: " + severity))

                if event == "Quarantine Failure" and line.find('"disposition":"') != -1:
                    disposition = line[line.find('":"')+3:-1]
                    dispositionListQF.append(str("Disposition: " + disposition))

                if event == "Quarantine Failure" and line.find('"user":"') != -1:
                    user = line[line.find('":"')+3:-1]
                    if user == '':
                        user = "N/A"
                    userListQF.append(str("User: " + user))

                if event == "Quarantine Failure" and line.find('"trajectory":"') != -1:
                    tempTrajectory = line[line.find('":"')+3:-1]
                    uuid = tempTrajectory[tempTrajectory.find("computers")+10:-11]
                    trajectory = "https://console.amp.cisco.com/computers/{}/trajectory2".format(str(uuid))
                    trajectoryListQF.append(str("Device Trajectory Link: " + trajectory))

                if event == "Quarantine Failure" and line.find('"description":') != -1:
                    description = line[line.find('":"')+3:-2]
                    descriptionListQF.append(str("Quarantine Description: " + description))

                
            except:
                continue
    
    for num in range(len(hostList)):
        
        if eventType[num][12::] == "Threat Detected":
            #print(len(severityListTD), len(dispositionListTD), len(detectionListTD), len(filenameListTD), len(filepathListTD), len(shaListTD), len(trajectoryListTD), len(userListTD), len(descriptionListTD))
            try: 
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListTD[countTD], dispositionListTD[countTD], userListTD[countTD], detectionListTD[countTD], filenameListTD[countTD], filepathListTD[countTD], shaListTD[countTD], trajectoryListTD[countTD])
                print(line)
            except:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListTD[countTD], dispositionListTD[countTD], "User: N/A", detectionListTD[countTD], filenameListTD[countTD], filepathListTD[countTD], shaListTD[countTD], trajectoryListTD[countTD])
                print(line)
            countTD += 1

        elif eventType[num][12::] == "Cloud IOC":
            #print(len(severityListCIOC), len(dispositionListCIOC), len(detectionListCIOC), len(filenameListCIOC), len(filepathListCIOC), len(shaListCIOC), len(trajectoryListCIOC), len(userListCIOC), len(descriptionListCIOC))
            try: 
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListCIOC[countCIOC], dispositionListCIOC[countCIOC], userListCIOC[countCIOC], detectionListCIOC[countCIOC], filenameListCIOC[countCIOC], filepathListCIOC[countCIOC], shaListCIOC[countCIOC], trajectoryListCIOC[countCIOC])
                print(line)
            except:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListCIOC[countCIOC], dispositionListCIOC[countCIOC], "User: N/A", detectionListCIOC[countCIOC], filenameListCIOC[countCIOC], filepathListCIOC[countCIOC], shaListCIOC[countCIOC], trajectoryListCIOC[countCIOC])
                print(line)
            countCIOC += 1

        elif eventType[num][12::] == "System Process Protection":
            try:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListSPP[countSPP], dispositionListSPP[countSPP], userListSPP[countSPP], detectionListSPP[countSPP], filenameListSPP[countSPP], filepathListSPP[countSPP], shaListSPP[countSPP], trajectoryListSPP[countSPP])
                print(line)
                countSPP += 1
            except:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListSPP[countSPP], dispositionListSPP[countSPP], "User: N/A", detectionListSPP[countSPP], filenameListSPP[countSPP], filepathListSPP[countSPP], shaListSPP[countSPP], trajectoryListSPP[countSPP])
                print(line)
                countSPP += 1
        
        elif eventType[num][12::] == "Retrospective Detection":
            #print(len(severityListRD), len(dispositionListRD), len(detectionListRD), len(filenameListRD), len(filepathListRD), len(shaListRD), len(trajectoryListRD), len(userListRD), len(descriptionListRD))
            try: 
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListRD[countRD], dispositionListRD[countRD], userListRD[countRD], detectionListRD[countRD], filenameListRD[countRD], filepathListRD[countRD], shaListRD[countRD], trajectoryListRD[countRD])
                print(line)
            except:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListRD[countRD], dispositionListRD[countRD], "User: N/A", detectionListRD[countRD], filenameListRD[countRD], filepathListRD[countRD], shaListRD[countRD], trajectoryListRD[countRD])
                print(line)
            countRD += 1

        elif eventType[num][12::] == "Exploit Prevention":
            #print(len(filenameListEP), len(filepathListEP), len(trajectoryListEP), len(userListEP), len(attackedModuleEP))
            try: 
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], userListEP[countEP], filenameListEP[countEP], filepathListEP[countEP], attackedModuleEP[countEP], trajectoryListEP[countEP])
                print(line)
            except:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], "User: N/A", filenameListEP[countEP], filepathListEP[countEP], attackedModuleEP[countEP], trajectoryListEP[countEP])
                print(line)
            countEP += 1

        elif eventType[num][12::] == "Quarantine Failure":
            #print(len(severityListQF), len(dispositionListQF), len(trajectoryListQF), len(userListQF), len(descriptionListQF))
            try: 
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListQF[countQF], userListQF[countQF], dispositionListQF[countQF], descriptionListQF[countQF], trajectoryListQF[countQF])
                print(line)
            except:
                line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num], severityListQF[countQF], "User: N/A", dispositionListQF[countQF], descriptionListQF[countQF], trajectoryListQF[countQF])
                print(line)
            countQF += 1

        else:
            line = "On {} at {} CST, the computer, {}, had an event.\n\t{}\n".format(dateList[num], timeList[num], hostList[num], eventType[num])
            print(line)


class Logger(object):

    # Logger class used to log all stdout output to a file if the user decides to do so.
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(str(args.outFile), "a")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)  

    def flush(self):
        pass 

def main():

    if args.outFile:
        sys.stdout = Logger()

    # CHANGE ME
    umbrellaAPI = [] # List of strings: API Key, API Secret, Client ID 
                     # Could be a list of lists for multiple tenants

    # CHANGE ME
    ampAPI = [] # List of strings: API Key, Client ID 
                # Could be a list of lists for multiple tenants

    #CHANGE ME
    umbrellaClients = [] # List of client names in order, coinciding with the order of umbrellaAPI

    #CHANGE ME
    ampClients = [] # List of client names in order, coinciding with the order of ampAPI

    ampCount = 0
    print("\nStarting Script ...")
    start_time = time.time()

    if args.amp:
        for apiCreds in ampAPI:
            print("\n\nChecking AMP for {} ...\n".format(ampClients[ampCount]))
            currTime = str(datetime.now(pytz.timezone('US/Central'))).split(".")[0].split(" ")
            print("The current CST time is: {} on {}\n".format(currTime[1], currTime[0]))

            getAMPLogs(apiCreds[0], apiCreds[1], ampClients[ampCount])
            ampCount += 1
        
        
    elif args.umbrella:
        umbrellaCount = 0
        for apiCreds in umbrellaAPI:
            print("\n\nChecking Umbrella for {} ...\n".format(umbrellaClients[umbrellaCount]))
            currTime = str(datetime.now(pytz.timezone('US/Central'))).split(".")[0].split(" ")
            print("The current CST time is: {} on {}\n".format(currTime[1], currTime[0]))

            oauth = getUmbrellaOAuth(apiCreds[0], apiCreds[1])
            getUmbrellaLogs(apiCreds[2], oauth, umbrellaClients[umbrellaCount])
            umbrellaCount += 1

    else:
        for apiCreds in ampAPI:
            print("\n\nChecking AMP for {} ...\n".format(ampClients[ampCount]))
            currTime = str(datetime.now(pytz.timezone('US/Central'))).split(".")[0].split(" ")
            print("The current CST time is: {} on {}\n".format(currTime[1], currTime[0]))

            getAMPLogs(apiCreds[0], apiCreds[1], ampClients[ampCount])
            ampCount += 1
        
        print("\n\n\n")
        umbrellaCount = 0
        for apiCreds in umbrellaAPI:
            print("\n\nChecking Umbrella for {} ...\n".format(umbrellaClients[umbrellaCount]))
            currTime = str(datetime.now(pytz.timezone('US/Central'))).split(".")[0].split(" ")
            print("The current CST time is: {} on {}\n".format(currTime[1], currTime[0]))

            oauth = getUmbrellaOAuth(apiCreds[0], apiCreds[1])
            getUmbrellaLogs(apiCreds[2], oauth, umbrellaClients[umbrellaCount])
            umbrellaCount += 1

    totalTime = str(time.time() - start_time)
    print("\n\n\n\nFinished all Daily Checks in {} seconds ...\n".format(totalTime[:totalTime.find(".")+3]))

if __name__ == "__main__":
    main()
