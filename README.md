# Sungrow HTTP Config

This is a package to use the Sungrow Local Access HTTP API to configure parameters that are not available over Modbus

It currently only supports settting or unsetting a zero export limit, which is useful if on a variable-rate tariff that can go negative (ie charging you for exports at times there's oversupply in the grid), such as [Amber Electric](http://amber.com.au/) in Australia

**WARNING**
This package has only been tested on a single inverter, and the protocol is not well understood. Using it with anything else could damage your equipment, void your warranty, cause physical damage, or violate your agreement with your network operator.

Do not use this package if you have an export limit normally configured.
