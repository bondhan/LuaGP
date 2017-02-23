-- Compatible with Lua 5.3.
--
-- Author       : Bondhan Novandy
-- License      : The MIT License (MIT)
-- Information  : Loading cap file into the GP card
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
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_zip")()

package.path = ".\\LuaGP\\?.lua;" .. package.path 

local gp = require("lualib.gp_v1_4")
local cap = require("lualib.CapFile")

log.open_logfile(".\\log\\GpLoadCap.log")

local filename = "D:/tmp/CslNSICC_ALLv2_2013.cap"

cap.CapFile(filename)
