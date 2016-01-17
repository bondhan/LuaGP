--------------------------------------------------------------------------------
--  Author  : Bondhan Novandy (bondhan.novandy@gmail.com)
--  Date    : January 2016 
--  INFO    : A demo script to authenticate with card without (NONE) key derivation
--	License	:	MIT License
--------------------------------------------------------------------------------

--load all the module from the dll
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_card")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_sam")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_log")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_bytes")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_asn1")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_crypto")()
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_luasql_odbc")()

package.path = "lualib\\?.lua;" .. package.path 
--log.print(log.INFO, "path = " .. package.path)

require "lualib.gp"

--the place to save or log
local msg = log.open_logfile("log\\02_NONE_AUTHENTICATE.txt", 5)
print("msg = " .. msg)


--//////////////////////////////////////////////////////////////////////////////////////////
-- CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG 
--//////////////////////////////////////////////////////////////////////////////////////////

local CM_AID
local VISA_AID = "A0000000031010"

CM_AID = nil

--Set Key Set
local KMC_ENC = "404142434445464748494A4B4C4D4E4F"
local KMC_MAC = "404142434445464748494A4B4C4D4E4F"
local KMC_DEK = "404142434445464748494A4B4C4D4E4F"

--Set secure messaging type
local apdu_mode = APDU_MODE["CLR"]

--Set key diversification
local key_div = KEY_DIVERSIFY_MODE["NONE"]

--the SCP mode
local scp_mode = SCP_MODE["SCP_02_15"]

--random challenge (nil) if you want it random override with a string of number e.g. "1122334455667788"
local  host_random = nil 

-- the library that we use and assign it to a readable object
card  = pcsc_card 

--///////////////////////////////////////////////////////////////////////////////
--MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN 
--///////////////////////////////////////////////////////////////////////////////

local reader_name = "O2Micro CCID SC Reader 0"
--local reader_name=card_reader

--connect to reader name
local isconnected = card.connect_reader(reader_name)
if (isconnected == false) then
	error("Cannot connect to reader")
	return
end

--get the atr
local atr = card.get_atr()
log.print(log.INFO,"Card ATR = " .. atr)

--Select CM/AID
select_applet(CM_AID, card)

local kmc_key_set = set_kmc(KMC_ENC, KMC_MAC, KMC_DEK)

log.print(log.DEBUG, "key_derivation_type = " .. tostring(key_div))

-- do inital update
init_update(kmc_key_set, host_random, apdu_mode, key_div, scp_mode, card)

-- do external authenticate
external_authenticate()

--print all the session keys
log.print(log.DEBUG, "SCP02 Session Key ENC = " ..  tostring(GP_SESSION_KEYS["ENC"]))
log.print(log.DEBUG, "SCP02 Session Key MAC = " ..  tostring(GP_SESSION_KEYS["MAC"]))
log.print(log.DEBUG, "SCP02 Session Key KEK = " ..  tostring(GP_SESSION_KEYS["KEK"]))

--close log file
log.close_logfile()

