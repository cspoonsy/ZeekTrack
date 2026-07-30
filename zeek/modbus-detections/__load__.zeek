# Modbus security detection suite — top-level loader.
# Load this directory with:  zeek scripts/
# Or reference the package: @load modbus-detections

@load ./modbus_detect
@load ./modbus_writes
@load ./modbus_exceptions
@load ./modbus_summary
@load ./modbus_recon
@load ./modbus_masters
@load ./modbus_protocol_violations
@load ./modbus_register_tracking
@load ./modbus_register_values
@load ./modbus_read_modify_write
