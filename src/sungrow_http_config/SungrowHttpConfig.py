from urllib3.exceptions import TimeoutStateError
import requests_retry_on_exceptions as requests
import json
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SungrowHttpConfig():
    """ Implementation of the Sungrow Local Access HTTP API
    """

    def __init__(self, host):
        """ Initialise the http client
        :param host: The hostname or IP adddress of the WiNet-S dongle connected to the inverter
        """

        self.host = host
        self.proto = "https"
        self.lang = "_en_US"
        self.token = ""
        self.dongleVersion = ""
        self.productVersion = {}


    def connect(self):
        """ Connect to the dongle, verify it's supported, obtain and upgrade token
        :returns: True if successful
        """

        self.dongleVersion = self._getDongleVersion()

        if not self._isSupportedDongleVersion(self.dongleVersion):
            raise Exception("Unsupported dongle version {ver}".format(ver=self.dongleVersion))

        self.token = self._obtainToken()

        self.productVersion = self._getProductVersion()

        if not self._isSupportedProductVersion(self.productVersion):
            raise Exception("Unsupported product version {ver}".format(ver=self.productVersion))

        if not self._upgradeToken():
            raise Exception("Failed to upgrade token")

        return True

    def _isSupportedDongleVersion(self, version):
        """ Determine if the supplied dongle version is supported
        :param version: The version string produced by getDongleVersion to test
        :returns: True if the dongle version is supported by this package
        """
        return version == 'WiNet-S/9'

    def _isSupportedProductVersion(self, version):
        """ Determine if the supplied product version is supported
        :param version: The version string produced by getProductVersion to test
        :returns: True if the product version is supported by this package
        """
        return version.get("dev_id")==1 and \
        version.get("dev_code")==9734 and \
        version.get("dev_type")==21 and \
        version.get("dev_procotol")==2

    def _getDongleVersion(self):
        """ Connect to the API using GET and retrieve the dongle version info
        :returns: String of product_name/product_code
        """
        url = "{proto}://{host}/product/list".format(proto=self.proto,host=self.host)
        resp = requests.get(url, verify=False, exceptions=(requests.exceptions.ConnectionError,),backoff_factor=0.1,retries=3)
        rjson = resp.json().get('result_data')
        dongleString = "{name}/{code}".format(name=rjson.get('product_name'),code=rjson.get('product_code'))
        logging.debug("Detected dongle version as {ver}".format(ver=dongleString))
        return dongleString

    def _callAPI(self, path, reqJson):
        """ Calls the API with POST (most methods) with the supplied JSON payload
        :param path: The API endpoint to use
        :param reqJson: A JSON object containing the payload to send
        :returns: Dict containing the response
        """
        url = "{proto}://{host}{path}".format(proto=self.proto,host=self.host,path=path)
        # Sungrow inverters use a self-signed certificate, so verification is impossible
        # The dongles can get overwhelmed with requests and occasionally refuse connections, so retry
        resp = requests.post(url, json=reqJson, verify=False, exceptions=(requests.exceptions.ConnectionError,),backoff_factor=0.1,retries=3)
        return resp.json()

    def _obtainToken(self):
        """ Ask the API for a token to be used for subsequent requests
        :returns: Token provided by API
        """
        resp = self._callAPI("/user/connect", {"lang": self.lang, "service": "connect","token": ""})
        token = resp.get("result_data").get("token")
        logging.debug("Obtained token {token}".format(token=token))
        return token

    def _getProductVersion(self):
        """ Ask for the devices (products) connected to the dongle and return details of the first one (inverter)
        :returns: Dict of product information
        """
        resp = self._callAPI("/device/list", {"is_check_token": "0", "lang": self.lang, "service": "devicelist","token": self.token, "type": "0"})
        productVersion = resp.get("result_data").get("list")[0]
        logging.debug("Product ID={id} Code={code} Type={type} Proto={proto} Model={model}".format(id=productVersion.get("dev_id"),code=productVersion.get("dev_code"),type=productVersion.get("dev_type"),proto=productVersion.get("dev_procotol"),model=productVersion.get("dev_model")))
        return productVersion

    def _upgradeToken(self):
        """ Ask the API to upgrade the privileges of the token
        :returns: True if successful
        """
        resp = self._callAPI("/upgrade/upgradeStatus", {"lang": self.lang, "token": self.token})
        return resp.get("result_data").get("nextProcess")=="0"

    def _sendHexMessageToDevice(self, msgValue, msgType="0"):
        """ Sends the supplied hex string to the API and returns the result
        :param msgValue: The hex string to send
        :param msgType: The type of message to send, default is "0"
        :returns: Dict containing the response
        """

        if not self.token:
            self.connect()

        req = {
            "dev_code": self.productVersion.get("dev_code"),
            "dev_id": self.productVersion.get("dev_id"),
            "dev_type": self.productVersion.get("dev_type"),
            "lang": self.lang,
            "msgLength": (len(msgValue) // 2),
            "msgType": msgType,
            "msgValue": msgValue,
            "token": self.token
        }
        resp = self._callAPI("/device/passthroughway", req)
        return resp.get("result_data")

    def setZeroExportLimit(self):
        """ Enable export limit and set to 0kW (zero export limit)
        :returns: True if successful
        """

        msg1 = self._sendHexMessageToDevice("010679F400AA511B") # Turn on feed-in limitation
        msg1resp = msg1.get("data")
        if msg1resp == "010679F400AA511B":
            logging.debug("Feed-in limitation enabled")
        else:
            logging.warning("Problem enabling feed-in limitation")
            return False

        msg2 = self._sendHexMessageToDevice("011079F5000306000003E80000F77E") # Set limit to 0kW
        msg2resp = msg2.get("data")
        if msg2resp == "011079F500038966":
            logging.debug("Feed-in limitation set at 0kW")
        else:
            logging.warning("Problem setting feed-in limitation to 0kW")
            return False
        return True

    def unsetExportLimit(self):
        """ Turns off any export limit in place (no limit)
        :returns: True if successful
        """
        msg1 = self._sendHexMessageToDevice("010679F40055115B") # Turn off feedin limitation
        msg1resp = msg1.get("data")
        if msg1resp == "010679F40055115B":
            logging.debug("Feed-in limitation disabled")
        else:
            logging.warning("Problem disabling feed-in limitation")
            return False
        return True
