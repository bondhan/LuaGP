----------------------------------------------------------------------------------------------
-- Description  : Global platform implementation based on LUA
-- Author       : Bondhan Novandy
-- Date         : 5 February 2016
-- Features     : - Select applet
--                - Initialize update
--                - External Authenticate
--                - Diversify Key (None, EMV, VISA2)
--                - Put key
--                - Modular design
-- Note         : It is mostly porting/implementation of GlobalPlatform Master by Martin Paljak
----------------------------------------------------------------------------------------------

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

local util = require("lualib.util")

-----------------------------------------------------------------------------
-- Please assign either to choose pcsc or muehlbauer
-----------------------------------------------------------------------------
local _card = {}

-----------------------------------------------------------------------------
-- Declare module and import dependencies
-----------------------------------------------------------------------------
local base = _G

_card.CapFile = {}
local _M = _card.CapFile

-----------------------------------------------------------------------------
-- Declare module and import dependencies
-----------------------------------------------------------------------------

_M.PackageName = ""
_M.PackageAID = ""
_M.AppletAIDs = {}
_M.DapBlocks = {}
_M.LoadTokens = {}
_M.InstallTokens = {}
_M.componentNames = { "Header", "Directory", "Import", "Applet", "Class", "Method", "StaticField", "Export",
  "ConstantPool", "RefLocation", "Descriptor", "Debug" }
_M.CapComponents = {}

-----------------------------------------------------------------------------------------------------------
-- LOCAL FUNCTION, THE SCOPE IS ONLY INSIDE THIS FILE
-----------------------------------------------------------------------------------------------------------

function _M.CapFile(file)
  local internalFile, content, tmp, index
  local dir_name = string.match(file, "(.-)([^\\/]-%.?([^%.\\/]*))$")

  local capFile, err = zip.open(file)
  assert(capFile, err)

  local lookFor = "/javacard/Header.cap"
  local packageName = nil
  for file in capFile:files() do
--    log.print(log.DEBUG, "filename " .. file.filename) 
    for i=1, #_M.componentNames do
      --look for "Header.cap" first and makesure it is javacard archive
      if string.match(file.filename, lookFor) then
        packageName = string.match(file.filename, "(.-)([^\\/]-%.?([^%.\\/]*))$")
        assert(packageName)
        log.print(log.DEBUG, "match " .. file.filename .. " with " .. lookFor) 
        break
      end
    end
  end

  log.print(log.DEBUG, "package name = " .. packageName)

  -- read the file and make a table list: "name" <-> content
  for i=1, #_M.componentNames do
    -- read the file
    internalFile, err = capFile:open(packageName .. _M.componentNames[i] .. ".cap")

    if internalFile == nil then
      goto endloop
    end

    -- read the file and put the content inside the list
    content = internalFile:read("*a")    
    _M.CapComponents[_M.componentNames[i]] = util.string_tohex(content)

    ::endloop::
  end

  local header = _M.CapComponents["Header"]

  index = 1;  -- starts from one in lua
--		header[0] should be 1;
  index = index + 1*2
--  header[1] should be 0;
  index = index + 1*2
  -- header[2] should be remaining length
  index = index + 1*2
--   header[3, 4, 5, 6] should be magic
  index = index + 4*2
--   header[7, 8] should be cap file version
  index = index + 2*2
--   header[9] should be flags
  index = index + 1*2
--   header[10,11] should be package version
  index = index + 2*2
--   header[12] should be the length of AID
  local len = tonumber(string.sub(header, index, index+1), 16)

  index = index + 1*2

  local _PackageAID = string.sub(header, index, -1 + index + len*2);

  log.print(log.DEBUG, "package AID = " .. _PackageAID )

--  index = index + len*2 
--  len = tonumber(string.sub(header, index, index+1), 16)
--  index = index + 1*2 
--  local _PackageAIDString = util.string_fromhex(string.sub(header, index, -1 + index + len*2));
--  log.print(log.DEBUG, "package AID Name = " .. _PackageAIDString)  

end

return _M