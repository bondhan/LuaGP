-- Compatible with Lua 5.3.
--
-- Author       : Bondhan Novandy
-- License      : The MIT License (MIT)
-- Information  : 1st Authenticate with the CM
--                2nd Compute the new diversified key (CPS method)
--                3rd Put keyset to the card
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
log.open_logfile(".\\log\\GpChangeKeyCPSDerivation.log")

--////////////////////////////////////////////////////////////////////
--//MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN 
--////////////////////////////////////////////////////////////////////
local card = pcsc_card
--local  card = mlb_card

local readers = card.list_readers()
log.print(log.DEBUG, "Available readers = " .. readers)

local isInitialized = card.init_reader()
if (isInitialized) then
  log.print(log.DEBUG, "Reader Initialized")
else
  error("Fail to initialize the reader/encoding station")
end

local reader_name = "O2Micro CCID SC Reader 0"
--local reader_name=card_reader

local isconnected = card.connect_reader(reader_name)
if (isconnected == false) then
  error("Cannot connect to reader")
end

local atr = card.get_atr()
log.print(log.INFO,"Card ATR = " .. atr)

local sw
local response

-------------------------------------------------------------
---AUTHENTICATE WITH CM
------------------------------------------------------------
--Set secure messaging type
local apdu_mode = gp.APDU_MODE.CLR

--Set key diversification
local key_div = gp.KEY_DIVERSIFY_MODE.NONE

--the SCP mode
local scp_mode = gp.SCP_MODE.SCP_02_15

--ISD
local  CM_AID = "A000000003000000"

--The GP/KMC/MICK key
local normal_key = gp.set_kmc("404142434445464748494A4B4C4D4E4F", "404142434445464748494A4B4C4D4E4F", "404142434445464748494A4B4C4D4E4F", 0x00, 0x00)

------------------------------------------------------------
--- Compute key diversification
------------------------------------------------------------
-- select CM
gp.select_applet(CM_AID, card)
-- initialize update
sw, response = gp.init_update(normal_key, host_random, apdu_mode, key_div, scp_mode, card)
-- get key diversification using CPS/EMV
local diversified_keyset = gp.diversify_key(gp.KEY_DIVERSIFY_MODE.EMV, response, normal_key)

-- the key version and id
diversified_keyset.KEY_VERSION =  0x01
diversified_keyset.KEY_ID =  0x01

------------------------------------------------------------
--- Authenticate with default GP key 
------------------------------------------------------------
-- select CM
gp.select_applet(CM_AID, card)
-- initialize update
gp.init_update(normal_key, host_random, apdu_mode, key_div, scp_mode, card)
-- external authenticate
gp.external_authenticate(card)
-- put the new key set
gp.put_keyset(diversified_keyset, card)

-- run the GPAuthenticate_CPS.lua to verify the put key result

------------------------------------------------------------
--- Disconnect reader and close the log file
------------------------------------------------------------
card.disconnect_reader();

log.close_logfile()