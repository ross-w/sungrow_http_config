import requests_retry_on_exceptions as requests
import json
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

inverter = '172.24.100.131'
proto = 'https'



token = ""
productVersion = {}
lang = "_en_US"

#def callAPI(path, )

def isSupportedDongleVersion(version):
    return version == 'WiNet-S/9'

def isSupportedProductVersion(version):
    return version.get("dev_id")==1 and \
       version.get("dev_code")==9734 and \
       version.get("dev_type")==21 and \
       version.get("dev_procotol")==2

def getDongleVersion():
    url = "{proto}://{inverter}/product/list".format(proto=proto,inverter=inverter)
    resp = requests.get(url, verify=False, exceptions=(requests.exceptions.ConnectionError,),backoff_factor=0.1,retries=3)
    rjson = resp.json().get('result_data')
    return "{name}/{code}".format(name=rjson.get('product_name'),code=rjson.get('product_code'))

def callAPI(path, reqJson):
    url = "{proto}://{inverter}{path}".format(proto=proto,inverter=inverter,path=path)
    resp = requests.post(url, json=reqJson, verify=False, exceptions=(requests.exceptions.ConnectionError,),backoff_factor=0.1,retries=3)
    return resp.json()

def obtainToken():
    resp = callAPI("/user/connect", {"lang": lang, "service": "connect","token": ""})
    return resp.get("result_data").get("token")

def getProductVersion():
    resp = callAPI("/device/list", {"is_check_token": "0", "lang": lang, "service": "devicelist","token": token, "type": "0"})
    return resp.get("result_data").get("list")[0]

def upgradeToken():
    resp = callAPI("/upgrade/upgradeStatus", {"lang": lang, "token": token})
    return resp.get("result_data").get("nextProcess")=="0"

def sendHexMessageToDevice(msgValue, msgType="0"):
    req = {
        "dev_code": productVersion.get("dev_code"),
        "dev_id": productVersion.get("dev_id"),
        "dev_type": productVersion.get("dev_type"),
        "lang": lang,
        "msgLength": (len(msgValue) // 2),
        "msgType": msgType,
        "msgValue": msgValue,
        "token": token
    }
    resp = callAPI("/device/passthroughway", req)
    return resp.get("result_data")

invVersion = getDongleVersion()
print("Detected inverter dongle version: {ver}".format(ver=invVersion))

if not isSupportedDongleVersion(invVersion):
    print("Unsupported dongle version")
    exit(1)

token = obtainToken()
print("Obtained token {token}".format(token=token))

productVersion = getProductVersion()
print("Product ID={id} Code={code} Type={type} Proto={proto} Model={model}".format(id=productVersion.get("dev_id"),code=productVersion.get("dev_code"),type=productVersion.get("dev_type"),proto=productVersion.get("dev_procotol"),model=productVersion.get("dev_model")))
if not isSupportedProductVersion(productVersion):
    print("Unsupported product version")
    exit(1)

if upgradeToken():
    print("Upgraded token")
else:
    print("Failed to upgrade token")
    exit(1)

def setZeroExportLimit():
    msg1 = sendHexMessageToDevice("010679F400AA511B") # Turn on feedin limitation
    msg1resp = msg1.get("data")
    if msg1resp == "010679F400AA511B":
        print("Feed-in limitation enabled")
    else:
        print("Problem enabling feed-in limitation")
        exit(1)

    msg2 = sendHexMessageToDevice("011079F5000306000003E80000F77E") # Set limit to 0kW
    msg2resp = msg2.get("data")
    if msg2resp == "011079F500038966":
        print("Feed-in limitation set at 0kW")
    else:
        print("Problem setting feed-in limitation to 0kW")
        exit(1)

def setNoExportLimit():
    msg1 = sendHexMessageToDevice("010679F40055115B") # Turn off feedin limitation
    msg1resp = msg1.get("data")
    if msg1resp == "010679F40055115B":
        print("Feed-in limitation disabled")
    else:
        print("Problem disabling feed-in limitation")
        exit(1)

setNoExportLimit()
