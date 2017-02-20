
package.path = ".\\LuaGP\\?.lua;" .. package.path

-----------------------------------------------------------------------------
-- Declare module and import dependencies
-----------------------------------------------------------------------------

require("lualib.class")
local util = require("lualib.util")

-- create a new class, named `BaseClass`
AIDRegistryClass = Class()

-- constructor function must be named `construct`
function AIDRegistryClass:construct(aid_str)
--  print('Constructing BaseClass:', self)
  self.aid = string.upper(aid_str)
end

-- constructor function must be named `construct`
function AIDRegistryClass:construct(aid_str, name)
--  print('Constructing BaseClass:', self)
  self.aid = string.upper(aid_str)
  self.readable_name = name 
end


-- if this instance is being garbage collected, this is called
function AIDRegistryClass:destruct()
--  print('Destructing BaseClass:', self)
end

function AIDRegistryClass:equals(aid_text)
  if (self.aid == string.upper(aid_text)) then
    return true
  end

  return false
end

function AIDRegistryClass:equals(aid_text)
  return string.len(self.aid)/2
end