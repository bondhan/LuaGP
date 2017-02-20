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

package.path = ".\\LuaGP\\?.lua;" .. package.path 

local gp = require("lualib.gp_v1_4")

log.open_logfile(".\\log\\GpAuthenticate_None.log")

--////////////////////////////////////////////////////////////////////
--//MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN 
--////////////////////////////////////////////////////////////////////
card = pcsc_card
--card = mlb_card

-- 0 not permanent
-- 1 is permanent
-- V could be 1800, 3300, 5000
local stat = card.set_voltage(1,3300)
if (stat) then
  log.print(log.DEBUG, "Changed the voltage")
else
  log.print(log.ERROR, "Fail to change voltage")
  error("Fail to change the voltage")
  return
end

local timeout = 150000
local rc = card.set_timeout(timeout)
if rc == false then
  error("Fail setting time out")
else
  log.print(log.DEBUG, "Timeout was set")
end

local readers = card.list_readers()
log.print(log.DEBUG, "Available readers = " .. readers)

local isInitialized = card.init_reader()
if (isInitialized) then
  log.print(log.DEBUG, "Reader Initialized")
else
  log.print(log.ERROR, "Reader Not Initialized")
  error("Fail to initialize the reader/encoding station")
  return
end

local reader_name = "O2Micro CCID SC Reader 0"
--local reader_name=card_reader

local isconnected = card.connect_reader(reader_name)
if (isconnected == false) then
  error("Cannot connect to reader")
  return
end

atr = card.get_atr()
log.print(log.INFO,"Card ATR = " .. atr)


--local pps = card.do_pps(0x32, 4910000) 
local pps = card.do_pps(0x11, 4910000) 
  if (pps == false) then
    card.disconnect_reader()
    error("PPS Failed")
    return
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

  local normal_key = gp.set_kmc("404142434445464748494A4B4C4D4E4F", "404142434445464748494A4B4C4D4E4F", "404142434445464748494A4B4C4D4E4F", 0x00, 0x00)
  
  ------------------------------------------------------------
  --- Authenticate with GP 
  ------------------------------------------------------------
  gp.select_applet(CM_AID, card)
  gp.init_update(normal_key, host_random, apdu_mode, key_div, scp_mode, cardobj)
  gp.external_authenticate()
  gp.getStatus()

  ------------------------------------------------------------
  --- Disconnect reader and close the log file
  ------------------------------------------------------------
  card.disconnect_reader();

  log.close_logfile()