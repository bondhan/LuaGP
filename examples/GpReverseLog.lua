-- Compatible with Lua 5.3.
--
-- Author       : Bondhan Novandy
-- License      : The MIT License (MIT)
-- Information  : Reverse the GP log by matching the MAC/Cryptogram
--

--load all the module from the dll
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_card")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_sam")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_log")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_bytes")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_asn1")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_crypto")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_luasql_odbc")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_socket_core")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_mime_core")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_lxp")()

--package to our lua files library
package.path = ".\\LuaGP\\?.lua;" .. package.path 

-- the library where the gp functions are
local gp = require("lualib.gp_v1_4")

-- Here where we keep the log
log.open_logfile(".\\log\\GpReverseLog.log")

--////////////////////////////////////////////////////////////////////
--Put the required data here
--////////////////////////////////////////////////////////////////////
local input_file = ".\\examples\\gp_data\\card1.txt"

--////////////////////////////////////////////////////////////////////
--//MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN 
--////////////////////////////////////////////////////////////////////
local key, value, index
local property = {}
local diversification_mode = gp.KEY_DIVERSIFY_MODE.NONE
local session_key
local mac_result

--harvest the input file
local file_handle = io.open(input_file)
assert(file_handle)

local line = file_handle:read("l")
while (line ~= nil) do
  line = string.gsub(line, "%s+", "")
  local test = string.match(line, "%-%-")
  local test2 = string.match(line, "^%s*%-%-")
  if (line ~= "" and test2 == nil) then
    key, value = string.match(line,"(.-)=(.-)$"); 
    property[key] = value
  end

  line = file_handle:read("l")
end

io.close(file_handle)

-------------------------------------------------------------------------------
-- Process the properties
-------------------------------------------------------------------------------
local hostChallenge = string.sub(property["InitUpdateCmd"], 11, 11+8*2)

index = 1
local diversificationData = string.sub(property["InitUpdateResp"], index, -1+index+10*2)
index = index+10*2

local keyVersion = string.sub(property["InitUpdateResp"], index, -1+index+1*2)
index = index+1*2

local scpMode = string.sub(property["InitUpdateResp"], index, -1+index+1*2)
index = index+1*2

local sequence = string.sub(property["InitUpdateResp"], index, -1+index+2*2)
index = index+2*2

local cardChallenge6Bytes = string.sub(property["InitUpdateResp"], index, -1+index+6*2)
index = index+6*2

local cardCryptogram = string.sub(property["InitUpdateResp"], index, -1+index+8*2)
index = index+8*2

log.print(log.INFO, "Host Challenge = " .. hostChallenge)
log.print(log.INFO, "Key Version = " .. keyVersion)
log.print(log.INFO, "SCP Mode = " .. scpMode)
log.print(log.INFO, "Sequence = " .. sequence)
log.print(log.INFO, "cardChallenge6Bytes = " .. cardChallenge6Bytes)
log.print(log.INFO, "Card Cryptogram = " .. cardCryptogram) 
log.print(log.INFO, "Diversification mode = " .. property["Diversification"]) 

if (string.match(property["Diversification"], "NONE")) then
  diversification_mode = gp.KEY_DIVERSIFY_MODE.NONE
elseif (string.match(property["Diversification"], "CPS")) or (string.match(property["Diversification"], "EMV")) then --dirty EMV and CPS is the same?
  diversification_mode = gp.KEY_DIVERSIFY_MODE.EMV
elseif (string.match(property["Diversification"], "VISA2")) then
  diversification_mode = gp.KEY_DIVERSIFY_MODE.VISA2
else
  error("Wrong diversification option")
end

local normal_key = gp.set_kmc(property["KMC_ENC"], property["KMC_MAC"], property["KMC_KEK"], 0x00, 0x00)

local diversified_keyset = gp.diversify_key(diversification_mode, property["InitUpdateResp"], normal_key)

if (tonumber(scpMode,16) == 0x02) then
  session_key = gp.deriveSessionKeysSCP02(diversified_keyset, sequence, false)
elseif (tonumber(scpMode,16) == 0x01) then
  session_key = gp.deriveSessionKeysSCP01(diversified_keyset, hostChallenge, (sequence..cardChallenge6Bytes))
else
  error("SCP mode not implemented yet")
end


local cntx = bytes.new(8, sequence .. cardChallenge6Bytes .. hostChallenge)

local host_cryptogram = gp.compute_mac(session_key.KEY_ENC, cntx, true)

local reference_host_cryptogram = string.sub(property["ExtAuthCmd"], 11, 11+8*2)

log.print(log.INFO, "Computed host cryptogram = " .. tostring(host_cryptogram))

-- if not match
if (string.match(reference_host_cryptogram,tostring(host_cryptogram)) == nil) then
  log.print(log.INFO, "Reference host cryptogram = " .. reference_host_cryptogram)

  error("computed host cryptogram is not equal")
end

local apdu_cmd = bytes.new(8, string.sub(property["ExtAuthCmd"], 1, 10+8*2))
local C_MAC = bytes.new(8,"00 00 00 00 00 00 00 00")		
if (tonumber(scpMode,16) == 0x02) then	

  local CBC_MAC = crypto.create_context(crypto.ALG_ISO9797_M3 + crypto.PAD_ISO9797_P2, session_key.KEY_MAC);	

  C_MAC = crypto.mac_iv(CBC_MAC, apdu_cmd, C_MAC)

  log.print(log.DEBUG, "apdu_cmd =  " .. tostring(apdu_cmd))
  log.print(log.DEBUG, "C_MAC =  " .. tostring(C_MAC))

  secure_apdu = bytes.concat(apdu_cmd, C_MAC)

elseif (tonumber(scpMode,16) == 0x01)  then
  log.print(log.ERROR, "SCP01 session key derivation not yet implemented")
  error("SCP01 session key derivation not yet implemented")
else
  error("SCPX Not implemented yet")
end

local reference_cmac = string.sub(property["ExtAuthCmd"], 27, 27+8*2)
log.print(log.INFO, "Computed C_MAC = " .. tostring(C_MAC))

if (string.match(reference_cmac, tostring(C_MAC)) == nil) then
  log.print(log.INFO, "Reference C_MAC = " .. reference_cmac)

  error("C_MAC not equal")
end

  log.print(log.INFO, "KEY & DERIVATION METHOD IS CORRECT")

-------------------------------------------------------------------------------
log.close_logfile()