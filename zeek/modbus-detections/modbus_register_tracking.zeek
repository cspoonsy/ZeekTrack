# modbus_register_tracking.zeek — Shared TID-based request→response correlation
# for holding and input registers.
#
# Maintains per-connection state that maps an in-flight read request (by TID)
# to its start address, so the response handler can store (address → value).
# Coils and discrete inputs are excluded — boolean values break percentage-based
# alerting used by DET-020.
#
# This module extends the connection record with two optional tables used by
# modbus_register_values.zeek (DET-020) and modbus_read_modify_write.zeek (DET-021).

@load base/protocols/modbus
@load ./modbus_detect

module Modbus;

export {
	## Per-register value snapshot: last observed raw value.
	type RegSnapshot: record {
		## Register address (0-based, as in the Modbus PDU).
		address: count;
		## Last value observed from a successful read response.
		value: count;
		## Timestamp of the last read response.
		ts: time;
	};

	## Per-connection pending-read state — keyed by TID.
	type PendingRead: record {
		## FC string ("READ_HOLDING_REGISTERS" or "READ_INPUT_REGISTERS").
		func: string;
		## Start address from the request PDU.
		start_address: count;
		## Number of registers requested.
		quantity: count;
		## Unit ID from the MBAP header.
		unit: count;
		## Request timestamp.
		ts: time;
	};

	## Connection record extension — populated by this module,
	## consumed by modbus_register_values.zeek and modbus_read_modify_write.zeek.
	redef record connection += {
		## Pending read requests keyed by TID (worker-local).
		modbus_pending_reads: table[count] of PendingRead &optional;
		## Last confirmed read value per (unit, address) on this connection.
		## key = cat(unit, "/", address)
		modbus_last_read: table[string] of RegSnapshot &optional;
	};
}

# ---------------------------------------------------------------------------
# Request handlers — record TID → (func, start_address, quantity, unit)
# ---------------------------------------------------------------------------

event modbus_read_holding_registers_request(c: connection,
    headers: ModbusHeaders, start_address: count, quantity: count)
	{
	if ( ! c?$modbus_pending_reads )
		c$modbus_pending_reads = table();
	c$modbus_pending_reads[headers$tid] = PendingRead(
	    $func="READ_HOLDING_REGISTERS", $start_address=start_address,
	    $quantity=quantity, $unit=headers$uid, $ts=network_time());
	}

event modbus_read_input_registers_request(c: connection, headers: ModbusHeaders,
    start_address: count, quantity: count)
	{
	if ( ! c?$modbus_pending_reads )
		c$modbus_pending_reads = table();
	c$modbus_pending_reads[headers$tid] = PendingRead($func="READ_INPUT_REGISTERS",
	    $start_address=start_address, $quantity=quantity, $unit=headers$uid,
	    $ts=network_time());
	}

# ---------------------------------------------------------------------------
# Response handlers — correlate TID, store (unit, address) → value
# ---------------------------------------------------------------------------

# Response handlers run at priority -1 so that other scripts (modbus_register_values,
# modbus_read_modify_write) can read c$modbus_pending_reads at default priority (0)
# before this handler deletes the entry.
event modbus_read_holding_registers_response(c: connection,
    headers: ModbusHeaders, registers: ModbusRegisters) &priority=-1
	{
	if ( ! c?$modbus_pending_reads )
		return;
	if ( headers$tid !in c$modbus_pending_reads )
		return;

	local req = c$modbus_pending_reads[headers$tid];
	delete c$modbus_pending_reads[headers$tid];

	if ( ! c?$modbus_last_read )
		c$modbus_last_read = table();
	local now = network_time();
	for ( idx in registers )
		{
		local reg_addr = req$start_address + idx;
		c$modbus_last_read[cat(req$unit, "/", reg_addr)] = RegSnapshot(
		    $address=reg_addr, $value=registers[idx], $ts=now);
		}
	}

event modbus_read_input_registers_response(c: connection,
    headers: ModbusHeaders, registers: ModbusRegisters) &priority=-1
	{
	if ( ! c?$modbus_pending_reads )
		return;
	if ( headers$tid !in c$modbus_pending_reads )
		return;

	local req = c$modbus_pending_reads[headers$tid];
	delete c$modbus_pending_reads[headers$tid];

	if ( ! c?$modbus_last_read )
		c$modbus_last_read = table();
	local now = network_time();
	for ( idx in registers )
		{
		local reg_addr = req$start_address + idx;
		c$modbus_last_read[cat(req$unit, "/", reg_addr)] = RegSnapshot(
		    $address=reg_addr, $value=registers[idx], $ts=now);
		}
	}
