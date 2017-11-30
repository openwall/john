-- Usage: tshark -q -Xlua_script:iscsi2john.lua -r selected.pcap
--
-- https://wiki.wireshark.org/Lua/Taps
-- https://wiki.wireshark.org/LuaAPI/Tvb
-- https://wiki.wireshark.org/LuaAPI/Tvb#TvbRange
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html
-- https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html
--
-- Wireshark in Fedora 25 doesn't have Lua enabled. Use Fedora 27 / Ubuntu or
-- something else which has Wireshark with Lua support or compile Wireshark
-- with Lua support.
--
-- tshark -r selected.pcap -T pdml > data.pdml # use this for development!
--
-- WARNING: This code is unlikely to handle parallel login sessions well!

if not Listener then
	print("Usage: tshark -q -Xlua_script:iscsi2john.lua -r target.pcap")
	os.exit(0)
end
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
