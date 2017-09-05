-- Usage: tshark -q -Xlua_script:snmp2john.lua -r snmp_usm.pcap
--
-- https://wiki.wireshark.org/Lua/Taps
-- https://wiki.wireshark.org/LuaAPI/Tvb
-- https://wiki.wireshark.org/LuaAPI/Tvb#TvbRange
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
--
-- Special thanks goes to Peter Wu for making this script work!
--
-- Wireshark in Fedora 24 doesn't have Lua enabled. Use Ubuntu or use something
-- else which has Wireshark with Lua support or compile Wireshark with Lua
-- support.

require "socket"

function sleep(sec)
	socket.select(nil, nil, sec)
end

if not Listener then
	print("Usage: tshark -q -Xlua_script:snmp2john.lua -r example.pcap")
	os.exit(0)
end
tap_snmp = Listener.new(nil, "snmp")

local f_msgVersion = Field.new("snmp.msgVersion")
local f_msgSecurityModel = Field.new("snmp.msgSecurityModel")
local f_msgAuthoritativeEngineID = Field.new("snmp.msgAuthoritativeEngineID")
local f_msgAuthenticationParameters = Field.new("snmp.msgAuthenticationParameters")
local f_msgUserName = Field.new("snmp.msgUserName")
local f_snmp = Field.new("snmp")

print("Set the SNMP_ALGORITHM environment variable for a speed boost, if you already know the algorithm being used. Read this script to know more.")
sleep(1)

function tap_snmp.packet(pinfo,tvb,tapdata)
	local msgVersion = f_msgVersion()
	local msgSecurityModel = f_msgSecurityModel()
	local msgAuthoritativeEngineID = f_msgAuthoritativeEngineID()
	local msgAuthenticationParameters = f_msgAuthenticationParameters()
	local msgUserName = f_msgUserName()

	local snmp_algorithm = os.getenv("SNMP_ALGORITHM")
	local algorithm = 0 -- try both HMAC-MD5-96 and HMAC-SHA-96 (authProtocol)
	if snmp_algorithm == "MD5" then
		algorithm = 1
	elseif snmp_algorithm == "SHA1" then
		algorithm = 2
	end

	if msgSecurityModel then
		if msgVersion.value ~= 3 then
			return
		end
		if msgSecurityModel.value ~= 3 then
			return
		end
		if msgAuthoritativeEngineID.len == 0 then
			return
		end
		if msgAuthenticationParameters.len == 0 then
			return
		end
		if msgAuthenticationParameters.len ~= 12 then -- this is known to be 96-bits
			return
		end
		if msgUserName.len == 0 then
			return
		end

		local snmp_field = f_snmp()
		local snmp_payload = snmp_field.range()
		local wholeMsg = snmp_payload:bytes():tohex():lower()
		local AuthoritativeEngineID = tostring(msgAuthoritativeEngineID.value):lower()
		local AuthenticationParameters = tostring(msgAuthenticationParameters.value):lower()
		local UserName = tostring(msgUserName)
		-- zero out the hash (is there a safer/better way to do this?)
		local wholeMsgProper = wholeMsg:gsub(AuthenticationParameters, "000000000000000000000000")
		local hash = string.format("%s:$SNMPv3$%s$%s$%s$%s$%s", UserName, algorithm, pinfo.number,
			wholeMsgProper, AuthoritativeEngineID, AuthenticationParameters)
		print(hash)
	end
end

function tap_snmp.draw()
end
