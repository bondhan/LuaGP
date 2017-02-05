--package.path = "C:\\SCPComLib8.14\\MCES_8.14\\ChipCoding\\Scripts\\LuaGP\\?.lua;" .. package.path 
package.path = "..\\LuaGP\\?.lua;" .. package.path 


---------------------------------------------------------------------
-- XML-RPC over HTTP.
-- See Copyright Notice in license.html
---------------------------------------------------------------------

local error, tonumber, tostring, unpack = error, tonumber, tostring, unpack

require "socket.http"

local ltn12   = require"socket.ltn12"
local request = socket.http.request
local string  = require"string"
local table   = require"table"

require"xmlrpc.init"


--module("xmlrpc.http")

---------------------------------------------------------------------
-- Call a remote method.
-- @param url String with the location of the server.
-- @param method String with the name of the method to be called.
-- @return Table with the response (could be a `fault' or a `params'
--	XML-RPC element).
---------------------------------------------------------------------
function call (url, method, ...)
	local request_sink, tbody = ltn12.sink.table()
	local request_body = clEncode(method, ...)
	local err, code, headers, status = request {
		url = url,
		method = "POST",
		source = ltn12.source.string (request_body),
		sink = request_sink,
		headers = {
			["User-agent"] = _PKGNAME .. " " .. _VERSION,
			["Content-type"] = "text/xml",
			["content-length"] = tostring (string.len (request_body)),
		},
	}
	local body = table.concat (tbody)
	if tonumber (code) == 200 then
		return clDecode (body)
	else
		error (tostring (err or code).."\n\n"..tostring(body))
	end
end
