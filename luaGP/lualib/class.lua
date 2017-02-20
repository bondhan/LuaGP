--[[
The MIT License (MIT)
Copyright (c) 2016 Simon "Tenry" Burchert
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
]]

-- Compatible with Lua 5.3.

Class =
{
  instanceOf = function(self, class)
    if type(self) == 'table' then
      local myClass = getmetatable(self).__class
      
      while myClass ~= class do
        if myClass.super then
          myClass = myClass.super
        else
          return false
        end
      end
      
      return true
    else
      return false
    end
  end
}
local mt = {}

function mt.__call(func, base)
  local class = {}
  local mt
  -- local mt = { __index = class }
  class.metatable =
  {
    -- __index = class
    construct = function() return setmetatable({}, mt) end,
    -- getters = {},
    -- setters = {},
    __index = function(self, prop)
      local getter
      -- foobar => getFoobar
      if type(prop) == 'string' then
        getter = 'get' .. prop:upper():sub(1, 1) .. prop:sub(2)
      end
      
      -- check for getter (e.g. getFoobar) in class + base classes
      if getter and type(class[getter]) == 'function' then
        return class[getter](self)
      -- otherwise just get the attribute (e.g. foobar),
      -- possibly from a base class
      else
        return class[prop]
      end
    end,
    __newindex = function(self, prop, value)
      local setter
      -- foobar => setFoobar
      if type(prop) == 'string' then
        setter = 'set' .. prop:upper():sub(1, 1) .. prop:sub(2)
      end
      
      -- check for getter (e.g. setFoobar) in class + base classes
      if setter and type(class[setter]) == 'function' then
        return class[setter](self, value)
      -- otherwise rawset the attribute (e.g. foobar) in this instance
      else
        -- class[prop] = value
        rawset(self, prop, value)
      end
    end,
    __class = class
  }
  mt = class.metatable -- shorthand
  
  local function construct(func, ...)
    -- local self = setmetatable(mt.construct(), mt)
    local self = mt.construct(class, ...)
    
    if class.construct then
      class.construct(self, ...)
    end
    
    return self
  end
  
  local function destruct(self)
    local base = self
    while base do
      if type(base) == 'table' and rawget(base, 'destruct') then
        base.destruct(self)
      end
      
      if base == self then base = class
      else base = base.super end
      -- local mt = getmetatable(base)
      -- if (not mt) or (not mt.__index) then break end
      -- base = mt.__index
    end
  end
  mt.__gc = destruct
  
  setmetatable(class, { __call = construct, __index = base })
  
  class.super = base
  class.instanceOf = Class.instanceOf
  
  -- if base then
  --   setmetatable(class, { __index = base })
  -- end
  
  return class
end

setmetatable(Class, mt)