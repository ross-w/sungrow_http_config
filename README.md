# Sungrow HTTP Config

This is a package to configure parameters on Sungrow inverters that are not typically available over standard interfaces. It supports both the Sungrow Local Access HTTP API and direct Modbus TCP communication.

It currently supports setting or unsetting an export limit, which is useful if on a variable-rate tariff that can go negative (i.e., charging you for exports at times there's oversupply in the grid), such as [Amber Electric](http://amber.com.au/) in Australia.

## Usage

```python
from sungrow_http_config import SungrowHttpConfig

# Using HTTP mode (default)
config = SungrowHttpConfig(host="192.168.1.100")

# Using direct Modbus TCP mode
config_modbus = SungrowHttpConfig(host="192.168.1.100", mode="modbus")

# Connect to the inverter
config.connect()

# Set export limit to 1kW (100 dekawatts)
config.setExportLimit(100)

# Get current export limit
limit = config.getCurrentExportLimit()
print(f"Current export limit: {limit/100}kW")

# Remove export limit
config.unsetExportLimit()
```

## Notes

- Please note that a 0kW export limit is equivalent to unlimited. To set as close to zero as possible, use 0.01kW (1 dekawatt).
- The reaction time of the inverter to changes in loads can be a little slow, which could result in more use of grid power than anticipated if a new load is switched on. Depending on your differential in price between imports and exports, you may want to configure a bigger export "buffer" to mitigate this.
- When using Modbus mode, the default port is 502 and the default unit ID is 1. These can be configured when initialising the class.

## Communication Modes

### HTTP Mode
Uses the Sungrow Local Access HTTP API via a WiNet-S dongle connected to the inverter. This is the default mode and requires the inverter to be connected to a WiNet-S dongle.

### Modbus Mode
Communicates directly with the inverter using Modbus TCP on port 502. This mode doesn't require a WiNet-S dongle but requires the inverter to be accessible via TCP/IP.

**WARNING**
This package has only been tested on a limited number of inverters, and the protocol is not well understood. Using it with anything else could damage your equipment, void your warranty, cause physical damage, or violate your agreement with your network operator.

Do not use this package if you have an export limit normally configured.
