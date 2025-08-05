import codecs as c
import logging

import pymodbus.register_write_message as modbus_register_write
import requests
import urllib3
from pymodbus.exceptions import ConnectionException, ModbusIOException
from pymodbus.transaction import ModbusRtuFramer
from requests.exceptions import ConnectionError, RequestException, Timeout
from SungrowModbusTcpClient import SungrowModbusTcpClient
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_fixed
from urllib3.exceptions import TimeoutError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SungrowHttpConfig():
    """ Implementation of the Sungrow Local Access API
    Supports both HTTP and direct Modbus communication
    """

    # Default timeout in seconds for requests
    DEFAULT_TIMEOUT = 10
    # Default number of retry attempts
    MAX_RETRIES = 4
    # Wait time between retries in seconds
    RETRY_WAIT = 2
    # Default Modbus port
    DEFAULT_MODBUS_PORT = 502
    # Default Modbus unit ID
    DEFAULT_MODBUS_UNIT_ID = 1

    def __init__(self, host, timeout=DEFAULT_TIMEOUT, mode="http", port=DEFAULT_MODBUS_PORT, unit_id=DEFAULT_MODBUS_UNIT_ID):
        """ Initialise the client
        :param host: The hostname or IP address of the inverter or WiNet-S dongle
        :param timeout: Timeout in seconds for requests
        :param mode: Communication mode, either "http" or "modbus"
        :param port: Modbus TCP port (only used in modbus mode)
        :param unit_id: Modbus unit ID (only used in modbus mode)
        """
        self.host = host
        self.timeout = timeout
        self.mode = mode.lower()
        self.port = port
        self.unit_id = unit_id
        
        # Initialise mode-specific attributes
        if self.mode == "http":
            self.proto = "https"
            self.lang = "_en_US"
            self.token = ""
            self.dongleVersion = ""
            self.productVersion = {}
            self.session = requests.Session()
        elif self.mode == "modbus":
            self.client = None
        else:
            raise ValueError(f"Unsupported mode: {self.mode}. Use 'http' or 'modbus'.")

    def connect(self):
        """ Connect to the inverter
        :returns: True if successful
        """
        if self.mode == "http":
            return self._http_connect()
        else:  # modbus mode
            return self._modbus_connect()

    def getDeviceSerialNumber(self):
        """ Retrieve the device serial number to uniquely identify it
        :returns: String containing the serial number of the inverter
        """
        if self.mode == "http":
            if self.productVersion == {}:
                self.connect()
            return self.productVersion["dev_sn"]
        else:  # modbus mode
            # Register 4990 contains the device serial number (use 4989 with read_input_registers)
            # Use read_input_registers with address-1 and read 10 registers
            result = self._execute_modbus_operation(
                'read_input_registers',
                4989, 10, unit=self.unit_id
            )
            
            # Use the UTF-8 decoding approach from the other project
            try:
                # Take first register and then the next 4 registers (total 10 bytes)
                utf_value = result.registers[0].to_bytes(2, 'big')
                for x in range(1, 5):
                    utf_value += result.registers[x].to_bytes(2, 'big')
                
                # Decode as UTF-8 and remove null bytes
                return utf_value.decode('utf-8').rstrip('\x00')
            except UnicodeDecodeError:
                try:
                    # Try ASCII as fallback
                    return utf_value.decode('ascii').rstrip('\x00')
                except UnicodeDecodeError:
                    # If both decodings fail, return as hex string
                    logging.warning("Could not decode serial number as UTF-8 or ASCII, returning hex representation")
                    return utf_value.hex().upper()

    def setExportLimit(self, dekawattLimit):
        """ Enable export limit and set to specified value
        :param dekawattLimit: Limit to set, in dekawatts (kW * 100). Note 0 == unlimited, so set 1 for 0.01kW
        :returns: True if successful
        """
        try:
            if self.mode == "http":
                return self._http_set_export_limit(dekawattLimit)
            else:  # modbus mode
                return self._modbus_set_export_limit(dekawattLimit)
        except Exception as e:
            logging.error(f"Error setting export limit: {str(e)}")
            raise

    def unsetExportLimit(self):
        """ Turns off any export limit in place (no limit)
        :returns: True if successful
        """
        if self.mode == "http":
            return self._http_unset_export_limit()
        else:  # modbus mode
            return self._modbus_unset_export_limit()

    def getCurrentExportLimit(self):
        """ Obtains the current export limit setting
        :returns: The current export limit in dekawatts, or 0 if no limit set
        """
        if self.mode == "http":
            return self._http_get_current_export_limit()
        else:  # modbus mode
            return self._modbus_get_current_export_limit()

    # HTTP mode implementation
    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_fixed(RETRY_WAIT),
        retry=retry_if_exception_type((Timeout, ConnectionError, TimeoutError))
    )
    def _make_request(self, method, url, **kwargs):
        """Make an HTTP request with timeout and retry handling

        :param method: HTTP method ('GET' or 'POST')
        :param url: URL to request
        :param kwargs: Additional arguments to pass to requests
        :returns: Response from the server
        :raises: RequestException if all retries fail
        """
        try:
            kwargs['timeout'] = self.timeout
            kwargs['verify'] = False  # Due to self-signed cert

            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()

            return response

        except Timeout:
            logging.warning(f"Request timeout reached ({self.timeout}s) for URL: {url}")
            raise
        except ConnectionError as e:
            logging.warning(f"Connection error for URL {url}: {str(e)}")
            raise
        except RequestException as e:
            logging.error(f"Request failed for URL {url}: {str(e)}")
            raise

    def _http_connect(self):
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
        url = f"{self.proto}://{self.host}/product/list"
        resp = self._make_request('GET', url)
        rjson = resp.json().get('result_data')
        dongleString = f"{rjson.get('product_name')}/{rjson.get('product_code')}"
        logging.debug(f"Detected dongle version as {dongleString}")
        return dongleString

    def _callAPI(self, path, reqJson):
        """ Calls the API with POST (most methods) with the supplied JSON payload
        :param path: The API endpoint to use
        :param reqJson: A JSON object containing the payload to send
        :returns: Dict containing the response
        """
        url = f"{self.proto}://{self.host}{path}"
        resp = self._make_request('POST', url, json=reqJson)
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
        np = resp.get("result_data").get("nextProcess")
        return (np=="0" or np=="1")

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
        if resp.get("result_code")==1:
            return resp.get("result_data")
        elif resp.get("result_code")==106: # Token expired
            self.token=""
            return self._sendHexMessageToDevice(msgValue, msgType)
        else:
            raise Exception("Got unsuccessful message back from device: {resp}".format(resp=resp))

    def _generateExportLimitCommand(self, dekawattLimit):
        """ Generates the appropriate modbus command to send for the given limit
        :param dekawattLimit: Limit to set, in dekawatts (kW * 100)
        :returns: String containing modbus command string
        """
        framer = ModbusRtuFramer(None)
        arguments = {
            "address": 31221,
            "value": dekawattLimit,
            "write_address": 31221,
            "transaction": 1,
            "slave": 1,
            "protocol": 0x00,
        }
        message = modbus_register_write.WriteSingleRegisterRequest(**arguments)
        raw_packet = framer.buildPacket(message)
        packet = c.encode(raw_packet, "hex_codec").decode("utf-8").upper()
        return packet

    def _decodeModbusExportLimitPayload(self, modbusMsg):
        """ Decodes the supplied modbus message into individual registers
        :param modbusMsg: The hex string representing the modbus response
        :returns Array of register values
        """
        response_data = bytes.fromhex(modbusMsg)
        data_section = response_data[3:-2]
        registers = [int.from_bytes(data_section[i:i+2], byteorder='big', signed=False) for i in range(0, len(data_section), 2)]
        return registers

    def _http_set_export_limit(self, dekawattLimit):
        """ Enable export limit and set to specified value using HTTP mode
        :param dekawattLimit: Limit to set, in dekawatts (kW * 100)
        :returns: True if successful
        """
        msg1 = self._sendHexMessageToDevice("010679F400AA511B")  # Turn on feed-in limitation
        msg1resp = msg1.get("data")
        if msg1resp == "010679F400AA511B":
            logging.debug("Feed-in limitation enabled")
        else:
            logging.warning("Problem enabling feed-in limitation")
            return False

        exportLimitCommand = self._generateExportLimitCommand(dekawattLimit)
        logging.debug(f"Generated modbus export limit command as {exportLimitCommand}")
        msg2 = self._sendHexMessageToDevice(exportLimitCommand)  # Set limit
        msg2resp = msg2.get("data")
        if msg2resp == exportLimitCommand:
            logging.debug(f"Feed-in limitation set at {dekawattLimit/100}kW")
        else:
            logging.warning(f"Problem setting feed-in limitation to {dekawattLimit/100}kW, modbus response was {msg2resp}")
            return False
        return True

    def _http_unset_export_limit(self):
        """ Turns off any export limit in place (no limit) using HTTP mode
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

    def _http_get_current_export_limit(self):
        """ Obtains the current export limit setting using HTTP mode
        :returns: The current export limit in dekawatts, or 0 if no limit set
        """
        registers = []
        while (len(registers) == 0) and (0 not in dict(enumerate(registers))):
            msg1 = self._sendHexMessageToDevice("010379F400081CA2")  # Is feed-in limitation on?
            msg1resp = msg1.get("data")
            registers = self._decodeModbusExportLimitPayload(msg1resp)
            if len(registers) == 0:
                logging.warning("No registers received in modbus reply, calling connect")
                self.connect()

        if (registers[0] == 341 or registers[0] == 85):  # Feed-in limitation is disabled
            return 0
        elif (registers[0] == 170):
            return registers[1]
        else:
            raise Exception(f"Unknown response to query for current export limit: {msg1resp}, decoded register value {registers[0]}")

    # Modbus mode implementation
    @retry(
        stop=stop_after_attempt(MAX_RETRIES),
        wait=wait_fixed(RETRY_WAIT),
        retry=retry_if_exception_type((ConnectionException, ModbusIOException, ConnectionError, OSError, AttributeError))
    )
    def _execute_modbus_operation(self, operation_name, *args, **kwargs):
        """Execute a Modbus operation with retry handling
        
        :param operation_name: The name of the Modbus client method to call (e.g., 'read_holding_registers')
        :param args: Arguments to pass to the operation function
        :param kwargs: Keyword arguments to pass to the operation function
        :returns: Result from the Modbus operation
        :raises: Exception if all retries fail
        """
        try:
            # Ensure we have a connection
            if not self.client or not self.client.is_socket_open():
                logging.debug("Modbus connection not open, reconnecting...")
                self._modbus_connect()
                
            if not self.client:
                raise ConnectionException("Failed to establish Modbus connection")
                
            # Get the operation function from the client
            if not hasattr(self.client, operation_name):
                raise AttributeError(f"Modbus client has no method named '{operation_name}'")
                
            operation_func = getattr(self.client, operation_name)
                
            # Execute the operation
            result = operation_func(*args, **kwargs)
            
            # Check if the result indicates an error
            if hasattr(result, 'isError') and result.isError():
                error_msg = f"Modbus operation failed: {result}"
                logging.warning(error_msg)
                # Reconnect and retry
                self._modbus_connect()
                if not self.client:
                    raise ConnectionException("Failed to re-establish Modbus connection")
                operation_func = getattr(self.client, operation_name)
                result = operation_func(*args, **kwargs)
                if result.isError():
                    raise Exception(error_msg)
                    
            return result
            
        except ConnectionException as e:
            logging.warning(f"Modbus connection exception: {str(e)}")
            # Force reconnection on next attempt
            if self.client:
                self.client.close()
                self.client = None
            raise
        except ModbusIOException as e:
            logging.warning(f"Modbus I/O exception: {str(e)}")
            # Force reconnection on next attempt
            if self.client:
                self.client.close()
                self.client = None
            raise
        except OSError as e:
            logging.warning(f"OS error during Modbus operation: {str(e)}")
            # Force reconnection on next attempt
            if self.client:
                self.client.close()
                self.client = None
            raise
        except AttributeError as e:
            logging.error(f"Attribute error during Modbus operation: {str(e)}")
            # Force reconnection on next attempt
            if self.client:
                self.client.close()
                self.client = None
            raise
        except Exception as e:
            logging.error(f"Unexpected error during Modbus operation: {str(e)}")
            raise
            
    def _modbus_connect(self):
        """ Connect to the inverter using direct Modbus TCP
        :returns: True if successful
        """
        client_config = {
            "host":     self.host,
            "port":     self.port,
            "timeout":  self.timeout,
            "retries":  self.MAX_RETRIES,
            "RetryOnEmpty": False,
            "unit":     self.unit_id,
        }
        try:
            if self.client is None:
                self.client = SungrowModbusTcpClient.SungrowModbusTcpClient(**client_config)
            
            self.client.connect()
            
            # Wait 3 seconds after connecting to fix timing issues
            import time
            time.sleep(3)

            return True
        except Exception as e:
            logging.error(f"Error connecting to Modbus server: {str(e)}")
            raise

    def _modbus_set_export_limit(self, dekawattLimit):
        """ Enable export limit and set to specified value using direct Modbus
        :param dekawattLimit: Limit to set, in dekawatts (kW * 100)
        :returns: True if successful
        """
        try:
            # Register 31220 (0x79F4) - Enable feed-in limitation (value 0xAA)
            self._execute_modbus_operation(
                'write_register',
                31220, 0xAA, unit=self.unit_id
            )
            
            # Register 31221 (0x79F5) - Set export limit value
            self._execute_modbus_operation(
                'write_register',
                31221, dekawattLimit, unit=self.unit_id
            )
                
            logging.debug(f"Feed-in limitation set at {dekawattLimit/100}kW")
            return True
        except Exception as e:
            logging.warning(f"Problem setting feed-in limitation: {str(e)}")
            return False

    def _modbus_unset_export_limit(self):
        """ Turns off any export limit in place (no limit) using direct Modbus
        :returns: True if successful
        """
        try:
            # Register 31220 (0x79F4) - Disable feed-in limitation (value 0x55)
            self._execute_modbus_operation(
                'write_register',
                31220, 0x55, unit=self.unit_id
            )
                
            logging.debug("Feed-in limitation disabled")
            return True
        except Exception as e:
            logging.warning(f"Problem disabling feed-in limitation: {str(e)}")
            return False

    def _modbus_get_current_export_limit(self):
        """ Obtains the current export limit setting using direct Modbus
        :returns: The current export limit in dekawatts, or 0 if no limit set
        """
        try:
            # Register 31220 (0x79F4) - Check if feed-in limitation is enabled
            result = self._execute_modbus_operation(
                'read_holding_registers',
                31220, 8, unit=self.unit_id
            )
                
            if result.registers[0] == 0x55 or result.registers[0] == 341:  # Feed-in limitation is disabled
                return 0
            elif result.registers[0] == 0xAA:  # Feed-in limitation is enabled
                return result.registers[1]  # The second register contains the limit value
            else:
                raise Exception(f"Unknown response to query for current export limit: register value {result.registers[0]}")
        except Exception as e:
            logging.error(f"Failed to read export limit status: {str(e)}")
            raise
