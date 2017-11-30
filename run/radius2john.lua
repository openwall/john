-- Extract RADIUS CHAP hashes from .pcap files.
--
-- Usage: tshark -q -Xlua_script:radius2john.lua -r selected.pcap
--
-- Wireshark in Fedora 25 doesn't have Lua enabled. Use Fedora 27 / Ubuntu or
-- something else which has Wireshark with Lua support or compile Wireshark
-- with Lua support.
--
-- tshark -r selected.pcap -T pdml > data.pdml # use this for development!
--
-- https://tools.ietf.org/html/rfc2865 -> The CHAP challenge value is found in
-- the CHAP-Challenge Attribute (60) if present in the packet, otherwise in the
-- Request Authenticator field. NOTE: We don't handle the former case yet.

if not Listener then
	print("Usage: tshark -q -Xlua_script:radius2john.lua -r target.pcap")
	os.exit(0)
end
tap_radius = Listener.new(nil, "radius")

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
		end
	end
end

function tap_radius.draw()
end
