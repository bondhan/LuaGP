----------------------------------------------------------------------------------------------
-- Description  : Global platform implementation based on LUA
-- Author       : Bondhan Novandy
-- Date         : 5 February 2016
-- Features     : - CAP File
-- Note         : It is mostly porting/implementation of GlobalPlatform Master by Martin Paljak
----------------------------------------------------------------------------------------------

--load all the module from the dll
package.loadlib("LuaSmartCardLibrary.dll", "luaopen_zip")()

package.path = ".\\LuaGP\\?.lua;" .. package.path 
-----------------------------------------------------------------------------
-- Declare module and import dependencies
-----------------------------------------------------------------------------
local util = require("lualib.util")
local AID = require("lualib.AID")

-----------------------------------------------------------------------------
-- Please assign either to choose pcsc or muehlbauer
-----------------------------------------------------------------------------
local _card = {}

local base = _G

_card.CapFile = {}
local _M = _card.CapFile

-----------------------------------------------------------------------------
-- Declare the variables on the scope of this module
-----------------------------------------------------------------------------

_M.PackageAID = ""
_M.AppletAIDs = {}
_M.DapBlocks = {}
_M.LoadTokens = {}
_M.InstallTokens = {}
_M.componentNames = { "Header", "Directory", "Import", "Applet", "Class", "Method", "StaticField", "Export",
  "ConstantPool", "RefLocation", "Descriptor", "Debug" }
_M.CapComponents = {}

-----------------------------------------------------------------------------------------------------------
-- Functions in the scope of this module
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

  -- get the package AID
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

  --getting the ascii name
  index = index + len*2
  len = tonumber(string.sub(header, index, index+1), 16)
  index = index + 1*2

  local name = util.string_fromhex(string.sub(header, index, -1 + index + len*2));

  _M.PackageAID = AIDClass(_PackageAID, name)

  log.print(log.DEBUG, "Package AID = " .. _M.PackageAID.aid .. " Name = " .. _M.PackageAID.readable_name)
  header = nil

  -- get Applets inside
  local applet = _M.CapComponents["Applet"]
  index = 1;  -- starts from one in lua
  -- applet[0] should be 3;
  index = index + 1*2
  -- applet[1] should be 0;
  index = index + 1*2
  -- applet[2] should be remaining length
  index = index + 1*2
  -- header[3] should be number of applets
  -- get numbers of applet
  local num = tonumber(string.sub(applet, index, index+1), 16)

  index = index + 1*2

  for j = 1, num do
    len = tonumber(string.sub(applet, index, index+1), 16) -- aid length
    index = index + 1*2

    tmp = string.sub(applet, index, -1 + index + len*2);
    _M.AppletAIDs[j] = AIDClass(tmp)

    index = index + len*2
    index = index + 2*2

  end

  log.print(log.DEBUG, "Found " .. #_M.AppletAIDs .. " Applets: ")
  for i=1,#_M.AppletAIDs do
      log.print(log.DEBUG, tostring(i) .. " = " .. _M.AppletAIDs[i].aid)
  end


end -- end of function


return _M