package.path = ".\\LuaGP\\?.lua;" .. package.path 

local _util = {}

-- The RPC server location which handles the safenet
RPC_SERVER = "http://172.16.1.180:9999/xmlrpc"

-----------------------------------------------------------------------------
-- Declare module and import dependencies
-----------------------------------------------------------------------------
local base = _G

_util.util = {}
local _M = _util.util

-----------------------------------------------------------------------------
-- Functions
-----------------------------------------------------------------------------
function _M.deepcopy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in next, orig, nil do
            copy[_M.deepcopy(orig_key)] = _M.deepcopy(orig_value)
        end
        setmetatable(copy, _M.deepcopy(getmetatable(orig)))
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end

return _M