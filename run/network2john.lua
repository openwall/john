-- #!/usr/bin/env lua -> shebang line seems to be breaking tshark :-(

-- Usage: tshark -q -Xlua_script:network2john.lua -r selected.pcap
--
-- Wireshark in Fedora 25 doesn't have Lua enabled. Use Fedora 27 / Ubuntu or
-- something else which has Wireshark with Lua support or compile Wireshark
-- with Lua support.
--
-- tshark -r selected.pcap -T pdml > data.pdml # use this for development!


-- Extract RADIUS CHAP hashes from .pcap files.
-- https://tools.ietf.org/html/rfc2865 -> The CHAP challenge value is found in
-- the CHAP-Challenge Attribute (60) if present in the packet, otherwise in the
-- Request Authenticator field. NOTE: We don't handle the former case yet.

if not Listener then
	print("Usage: tshark -q -Xlua_script:network2john.lua -r target.pcap")
	os.exit(0)
end
tap_radius = Listener.new(nil, "radius")

-- Extract RADIUS CHAP hashes from .pcap files.
-- We can also parse the "radius.avp" entries for more flexibility?
local f_code = Field.new("radius.code")
local f_authenticator = Field.new("radius.authenticator")
local f_username = Field.new("radius.User_Name")
local f_ident = Field.new("radius.CHAP_Ident")
local f_hash = Field.new("radius.CHAP_String")

function tap_radius.packet(pinfo,tvb,tapdata)
	local code = f_code()

	if code.value == 1 then  -- Access-Request
		local canary = f_ident()
		if canary then
			local challenge = tostring(f_authenticator().value):lower()
			local id = tostring(f_ident().value):lower()
			local response =  tostring(f_hash().value):lower()
			local username = tostring(f_username().value)
			local hash = string.format("%s:$chap$%s*%s*%s", username, id, challenge, response)
			print(hash)
			canary = nil
		end
	end
end

function tap_radius.draw()
end

-- Extract RADIUS authentication hashes from .pcap files.
-- http://www.untruth.org/~josh/security/radius/radius-auth.html
-- (An Analysis of the RADIUS Authentication Protocol)
local f_code = Field.new("radius.code")
local f_authenticator = Field.new("radius.authenticator")
local f_username = Field.new("radius.User_Name")
local f_upe = Field.new("radius.User_Password_encrypted")

-- put the passed-in args into a table
local args = {...}
count = 0
for i,v in ipairs(args) do
	count = count + 1
end

function tap_radius.packet(pinfo,tvb,tapdata)
	local code = f_code()

	if count < 2 then
		print("Usage: tshark -q -Xlua_script:network2john.lua -X lua_script1:<secret-or-password-value-here> -X lua_script1:0 -r target.pcap\n")
		print("Note: -X lua_script1:<secret-or-password-value-here> -> this is used as either the user password or the shared secrert\n")
		print("Note: Use -X lua_script1:0 to attack RADIUS shared secret\n")
		print("Note: Use -X lua_script1:1 to attack user password")
		os.exit(0)
	end

	-- print them out
	if code.value == 1 then  -- Access-Request
		local canary = f_upe()
		if canary then
			local challenge = tostring(f_authenticator().value):lower()
			local upe =  tostring(f_upe().value):lower()
			local username = tostring(f_username().value)
			local secret = args[1]
			local mode = args[2]
			local hash = string.format("%s:$radius$1*%s*%s*%s*%s", username, mode, secret, challenge, upe)
			print(hash)
			canary = nil
		end
	end
end

function tap_radius.draw()
end


-- Extract EAP-MD5 hashes from .pcap files.
tap_eap = Listener.new(nil, "eap")

local f_code = Field.new("eap.code")
local f_id = Field.new("eap.id")
local f_etype = Field.new("eap.type")
local f_identity = Field.new("eap.identity")
local f_challenge = Field.new("eap.md5.value")
local f_response = Field.new("eap.md5.value")

local username = nil
local challenge = nil
local response = nil
local id = nil

function tap_eap.packet(pinfo,tvb,tapdata)
	local code = f_code()
	local etype = f_etype()

	if code.value == 2 and etype.value == 1 then -- Response, Identity (extract username)
		username = tostring(f_identity())
	end

	if code.value == 1 and etype.value == 4 then -- Request, MD5-Challenge EAP
		challenge = tostring(f_challenge().value):lower()
	end

	if code.value == 2 and etype.value == 4 then -- Response, MD5-Challenge EAP
		response = tostring(f_response().value):lower()
		id = tostring(f_id().value)
	end

	if username and challenge and response then
		local hash = string.format("%s:$chap$%s*%s*%s", username, id, challenge, response)
		print(hash)
		username = nil
		challenge = nil
		response = nil
		id = nil
	end
end

function tap_eap.draw()
end


-- Extract SNMPv3 USM hashes from .pcap files.
--
-- Special thanks goes to Peter Wu for making this script work!
-- require "socket"

-- function sleep(sec)
-- 	socket.select(nil, nil, sec)
-- end

tap_snmp = Listener.new(nil, "snmp")

local f_msgVersion = Field.new("snmp.msgVersion")
local f_msgSecurityModel = Field.new("snmp.msgSecurityModel")
local f_msgAuthoritativeEngineID = Field.new("snmp.msgAuthoritativeEngineID")
local f_msgAuthenticationParameters = Field.new("snmp.msgAuthenticationParameters")
local f_msgUserName = Field.new("snmp.msgUserName")
local f_snmp = Field.new("snmp")
local snmp_tip_printed = false


function tap_snmp.packet(pinfo,tvb,tapdata)
	if not snmp_tip_printed then
		print("Set the SNMP_ALGORITHM environment variable for a speed boost, if you already know the algorithm being used. Read this script to know more.")
		-- sleep(1)  -- doesn't work reliably across distributions
		snmp_tip_printed = true
	end
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



-- Extract DHCPv6 authentication hashes from .pcap files.
-- NOTE: This requires Wireshark 2.9.0 (from git master) as of June, 2018.

tap_dhcpv6 = Listener.new(nil, "dhcpv6")

local f_algorithm = Field.new("dhcpv6.auth.algorithm")
local f_hash= Field.new("dhcpv6.auth.md5_data")
local f_dhcpv6 = Field.new("dhcpv6")

function tap_dhcpv6.packet(pinfo,tvb,tapdata)
	local canary = f_hash()
	if not canary then
		return
	end

	local algorithm = f_algorithm()
	if algorithm.value ~= 1 then
		return
	end

	local hash = tostring(canary.value):lower()
	local dhcpv6_field = f_dhcpv6()
	local dhcpv6_payload= dhcpv6_field.range()
	local wholeMsg = dhcpv6_payload:bytes():tohex():lower()
	local wholeMsgProper = wholeMsg:gsub(hash, "00000000000000000000000000000000")
	local hash = string.format("%s:$rsvp$1$%s$%s", pinfo.number, wholeMsgProper, hash)
	print(hash)
end

function tap_dhcpv6.draw()
end



-- Extract DHCPv4 authentication hashes from .pcap files.
-- NOTE: This requires Wireshark 2.9.0 (from git master) as of June, 2018.

tap_dhcpv4 = Listener.new(nil, "bootp")

local f_algorithm = Field.new("bootp.option.dhcp_authentication.alg_delay")
local f_hash= Field.new("bootp.option.dhcp_authentication.hmac_md5_hash")
local f_dhcpv4 = Field.new("bootp")

function tap_dhcpv4.packet(pinfo,tvb,tapdata)
	local canary = f_hash()
	if not canary then
		return
	end

	local algorithm = f_algorithm()
	if algorithm.value ~= 1 then
		return
	end

	local hash = tostring(canary.value):lower()
	local dhcpv4_field = f_dhcpv4()
	local dhcpv4_payload= dhcpv4_field.range()
	local wholeMsg = dhcpv4_payload:bytes():tohex():lower()
	wholeMsg = string.sub(wholeMsg, 1, 6) .. "00" .. string.sub(wholeMsg, 9, 48) .. "00000000" .. string.sub(wholeMsg, 57)  -- zero'ize hops and giaddr
	local wholeMsgProper = wholeMsg:gsub(hash, "00000000000000000000000000000000")  -- zero'ize the mac
	local hash = string.format("%s:$rsvp$1$%s$%s", pinfo.number, wholeMsgProper, hash)
	print(hash)
end

function tap_dhcpv4.draw()
end



-- Extract iSCSI CHAP hashes from .pcap files.
--
-- WARNING: This code is unlikely to handle parallel login sessions well!

tap_iscsi = Listener.new(nil, "iscsi")

local f_opcode = Field.new("iscsi.opcode")
local f_kv = Field.new("iscsi.keyvalue")

local username = nil
local challenge = nil
local response = nil
local id = nil

function tap_iscsi.packet(pinfo,tvb,tapdata)
	local opcode = f_opcode()

	if opcode.value == 0x23 then  -- extract CHAP_C, and CHAP_I
		items = {f_kv()}
		for index in pairs(items) do
			item = tostring(items[index])
			if string.find(item, 'CHAP_C') then
				challenge = item:gsub("CHAP_C=0x", "")  -- robust?
			end
			if string.find(item, 'CHAP_I') then
				id = item:gsub("CHAP_I=", "")  -- robust?
			end
		end
	end

	if opcode.value == 0x3 then  -- extract CHAP_N, and CHAP_R
		items = {f_kv()}
		for index in pairs(items) do
			item = tostring(items[index])
			if string.find(item, 'CHAP_R') then
				response = item:gsub("CHAP_R=0x", "")
			end
			if string.find(item, 'CHAP_N') then
				username = item:gsub("CHAP_N=", "")
			end
		end
	end

	if username and challenge and response then
		local hash = string.format("%s:$chap$%s*%s*%s", username, id, challenge, response)
		print(hash)
		username = nil
		challenge = nil
		response = nil
		id = nil
	end
end

function tap_iscsi.draw()
end


-- Extract DHCP OMAPI hashes from .pcap files. Tested with omshell, and pypureomapi.
tap_omapi = Listener.new(nil, "omapi")

local f_authid = Field.new("omapi.authid")
local f_authlen = Field.new("omapi.authlength")
local f_omapi = Field.new("omapi")
local omapi_tip_printed = false

function tap_omapi.packet(pinfo,tvb,tapdata)
	if not omapi_tip_printed then
		print("[WARNING] The DHCP OMAPI secret value is likely to be uncrackable under normal circumstances!")
		omapi_tip_printed = true
	end

	local authid = f_authid()
	if not authid then
		return
	end
	if authid.value ~= 1 then
		return
	end

	local authlen = f_authlen()
	if authlen.value ~= 16 then
		print("[DEBUG] omapi.authlength is not 16, please report this to us!")
		return
	end

	local omapi_field = f_omapi()
	local omapi_payload = omapi_field.range()
	local wholeMsg = tostring(omapi_payload:bytes():tohex():lower())
	local payload = string.sub(wholeMsg, 8+1, -32-1)
	local signature = string.sub(wholeMsg, -32)
	local hash = string.format("%s:$rsvp$1$%s$%s", pinfo.number, payload, signature)
	print(hash)
end

function tap_omapi.draw()
end
