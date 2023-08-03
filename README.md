# Sungrow HTTP Config

This is a package to use the Sungrow Local Access HTTP API to configure parameters that are not available over Modbus

It currently only supports settting or unsetting an export limit, which is useful if on a variable-rate tariff that can go negative (ie charging you for exports at times there's oversupply in the grid), such as [Amber Electric](http://amber.com.au/) in Australia.

Please note that a 0kW export limit is equivalent to unlimited, to set as close to zero as possible, use 0.01kW (1 dekawatt.)

Additionally, note that the reaction time of the inverter to changes in loads can be a little slow, which could result in more use of grid power than anticipated if a new load is switched on. Depending on your differential in price between imports and exports, you may want to configure a bigger export "buffer" to mitigate this.

**WARNING**
This package has only been tested on a single inverter, and the protocol is not well understood. Using it with anything else could damage your equipment, void your warranty, cause physical damage, or violate your agreement with your network operator.

Do not use this package if you have an export limit normally configured.
