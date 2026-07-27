# modbus_read_modify_write.zeek — DET-021: Read-modify-write detection.
#
# Fires Modbus::ReadModifyWrite when a master reads a holding or input register
# and then writes a different value to the same register on the same connection.
# This is the core behavioral signature of ZionSiphon-class OT malware that
# reads a register to select a target, then overwrites it with a dangerous value.
#
# Notice behavior:
#   - Fires once per unique (master, slave, unit, register) tuple per session.
#   - Subsequent read-modify-writes on the same tuple are suppressed for the
#     remainder of the Zeek session (not just a time window) to avoid noise
#     from legitimate PLC control logic that uses this pattern.
#   - read_modify_write_allowed set bypasses detection entirely for confirmed
#     legitimate masters; deliberately separate from authorized_masters.
#
# Cluster notes: the suppress set (_rmw_suppressed) is worker-local by default.
# In a cluster, connections are sticky to workers, so the read and the
# subsequent write on the same connection are always processed by the same
# worker — no cross-worker coordination is needed for per-connection detection.
# The suppress set is also relayed to other workers via Broker so that if a
# master opens a new connection on a different worker the notice does not
# re-fire for already-suppressed tuples.
#
# Depends on modbus_register_tracking.zeek for last-read state.

@load base/frameworks/notice
@load base/protocols/modbus
@load ./modbus_detect
@load ./modbus_register_tracking

module Modbus;

export {
	## Broker event: workers relay newly suppressed (master, slave, unit,
	## register) tuples to all other nodes so the suppress set stays in sync
	## across a cluster.  Standalone Zeek ignores this.
	global rmw_suppressed: event(master: addr, slave: addr, unit: count,
	    register: count);
}

# Set of (master, slave, unit, register) tuples that have already triggered a
# ReadModifyWrite notice this session.  Manager-authoritative in cluster.
global _rmw_suppressed: set[addr, addr, count, count] &create_expire=1day;

# ---------------------------------------------------------------------------
# Cluster: Broker relay for suppress set
# ---------------------------------------------------------------------------

@if ( Cluster::is_enabled() )

event Modbus::rmw_suppressed(master: addr, slave: addr, unit: count,
    register: count)
	{
	add _rmw_suppressed[master, slave, unit, register];
	}

@endif

# ---------------------------------------------------------------------------
# Core detection helper
# ---------------------------------------------------------------------------

function _check_rmw(c: connection, unit: count, address: count, value: count)
	{
	local master = c$id$orig_h;
	local slave = c$id$resp_h;

	if ( master in modbus_detect::read_modify_write_allowed )
		return;

	if ( ! c?$modbus_last_read )
		return;

	local k = cat(unit, "/", address);
	if ( k !in c$modbus_last_read )
		return;

	local snap = c$modbus_last_read[k];
	if ( snap$value == value )
		return; # wrote the same value — not an RMW

	if ( [master, slave, unit, address] in _rmw_suppressed )
		return;

	add _rmw_suppressed[master, slave, unit, address];

@if ( Cluster::is_enabled() )
	event Modbus::rmw_suppressed(master, slave, unit, address);
@endif

	NOTICE([$note=Modbus::ReadModifyWrite, $msg=fmt("%s read register %d (value 0x%04x) then wrote 0x%04x to slave %s unit=%d (read-modify-write sequence)",
	    master, address, snap$value, value, slave, unit), $conn=c,
	    $identifier=cat(master, slave, unit, address), $suppress_for=0sec]);
	}

# ---------------------------------------------------------------------------
# Write event handlers
# ---------------------------------------------------------------------------

event modbus_write_single_register_request(c: connection,
    headers: ModbusHeaders, address: count, value: count)
	{
	_check_rmw(c, headers$uid, address, value);
	}

event modbus_write_multiple_registers_request(c: connection,
    headers: ModbusHeaders, start_address: count, registers: ModbusRegisters)
	{
	for ( idx in registers )
		_check_rmw(c, headers$uid, start_address + idx, registers[idx]);
	}

event modbus_read_write_multiple_registers_request(c: connection,
    headers: ModbusHeaders, read_start_address: count, read_quantity: count,
    write_start_address: count, write_registers: ModbusRegisters)
	{
	for ( idx in write_registers )
		_check_rmw(c, headers$uid, write_start_address + idx, write_registers[idx]);
	}
