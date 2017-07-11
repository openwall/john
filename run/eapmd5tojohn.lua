-- Usage: tshark -q -Xlua_script:eapmd5tojohn.lua -r selected.pcap
--
-- https://wiki.wireshark.org/Lua/Taps
-- https://wiki.wireshark.org/LuaAPI/Tvb
-- https://wiki.wireshark.org/LuaAPI/Tvb#TvbRange
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
--
-- Wireshark in Fedora 24 doesn't have Lua enabled. Use Ubuntu or use something
-- else which has Wireshark with Lua support or compile Wireshark with Lua
-- support.
--
-- tshark -r selected.pcap -T pdml > data.pdml # use this for development!

if not Listener then
	print("Usage: tshark -q -Xlua_script:eapmd5tojohn.lua -r example.pcap")
	os.exit(0)
end
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
