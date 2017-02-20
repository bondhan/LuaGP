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

package.path = ".\\LuaGP\\?.lua;" .. package.path 

local xlmrpc_lua = require("xmlrpc.http")
local util = require("lualib.util")

-----------------------------------------------------------------------------
-- Please assign either to choose pcsc or muehlbauer
-----------------------------------------------------------------------------
local _card = {}

-- The RPC server location which handles the safenet
RPC_SERVER = "http://172.16.1.180:9999/xmlrpc"

-----------------------------------------------------------------------------
-- Declare module and import dependencies
-----------------------------------------------------------------------------
local base = _G

_card.gp_v1_4 = {}
local _M = _card.gp_v1_4

-----------------------------------
-- GLOBAL VARIABLES
-----------------------------------

_M.GP_SESSION_KEYS = {}
_M.GP_SCP_MODE = 0
_M.GP_APDU_MODE = 0
_M.GP_SCP_VERSION = 0x02
_M.GP_CARD_CHALLENGE = ""
_M.GP_HOST_CHALLENGE = ""
_M.CARD_KEY_VERSION = 0x00
_M.C_MAC = bytes.new(8,"0000000000000000")

local show_key_not_found = setmetatable({}, {__index = function (t, k)  -- {} an empty table, and after the comma, a custom function failsafe
      error("Key doesn't exist in the metatable list")
    end})


--The apdu mode for secure messaging
_M.APDU_MODE = setmetatable({CLR = 0x00, MAC = 0x01, RMAC = 0x10}, {__index = show_key_not_found})

--Key diversification mode
_M.KEY_DIVERSIFY_MODE = setmetatable({NONE = 0x00, VISA2 = 0x01, EMV= 0x02}, {__index = show_key_not_found})

--Key type
_M.KEY_TYPE = setmetatable({ENC = 1, MAC = 2, KEK= 3}, {__index = show_key_not_found})

--Put key mode
_M.PUT_KEY_MODE = setmetatable({MODIF = 1, REPLACE = 2, ADD = 4}, {__index = show_key_not_found})

--SCP Mode
_M.SCP_MODE = setmetatable({SCP_ANY = 0, SCP_01_05 = 1, SCP_01_15 = 2, SCP_02_04 = 3, SCP_02_05 = 4,SCP_02_0A = 5, SCP_02_0B = 6, SCP_02_14 = 7, SCP_02_15 = 8, SCP_02_1A = 9, SCP_02_1B = 10}, {__index = show_key_not_found})


local CLA_GP = 0x80
local CLA_MAC = 0x84
local INS_INITIALIZE_UPDATE = 0x50
local INS_INSTALL = 0xE6
local INS_LOAD = 0xE8
local INS_DELETE = 0xE4
local INS_GET_STATUS = 0xF2
local INS_PUT_KEY = 0xD8

-----------------------------------------------------------------------------------------------------------
-- LOCAL FUNCTION, THE SCOPE IS ONLY INSIDE THIS FILE
-----------------------------------------------------------------------------------------------------------

-- verify SW1 and SW2
local function verify_sw(recv_sw, ref_sw) 
  if (recv_sw ~= ref_sw) then
    error("Received " .. string.format("sw = %x", recv_sw) .. " Expect " .. string.format("sw = %x", ref_sw))
  end

  return true
end


-- ternary operation just like in C
local function ternary ( cond , T , F )
  if cond then return T else return F end
end

-- Get the value of the data by its tag
-- parameter: 
--		tag 
--		resp
local function get_value_by_tag(tag, resp)
  local tlv_tag, tlv_value, tlv_tail = asn1.split(resp)

  if tlv_tag ~= nill then
    if tlv_tag == tag then
      return tlv_value, tlv_tail
    else
      return get_value_by_tag(tag, tlv_value)
    end
  end

end

--a simple verify if the key is valid
local function verify_key(key, length)
  if (#key/2 ~= length) then
    error("Wrong key length")
  end

  if (string.find(key, "%x") == nil) then
    error("key is not hex value")
  end	

  return true
end


-- key diversification of VISA2 method
local function fillVisaStr(update_response, key_type)
  local data = ""
  data = data .. string.sub(update_response, 1, 4) .. string.sub(update_response, 9, 16) .. "F0" .. string.format("%02x", key_type)
  data = data .. string.sub(update_response, 1, 4) .. string.sub(update_response, 9, 16) .. "0F" .. string.format("%02x", key_type)

  log.print(log.DEBUG, "diversification data visa = " .. data)
  return data
end

-- key diversification of EMV method
local function fillEmvStr(update_response, key_type)
  local data = ""
  data = data .. string.sub(update_response, 9, 20) .. "F0" .. string.format("%02x", key_type)
  data = data .. string.sub(update_response, 9, 20) .. "0F" .. string.format("%02x", key_type)

  log.print(log.DEBUG, "diversification data EMV = " .. data)
  return data
end


-- Create/compose APDU command
local function create_cmd_apdu(cla, ins, p1, p2, data)
  local apdu = string.format("%02x", cla) .. string.format("%02x", ins) .. string.format("%02x", p1) .. string.format("%02x", p2) 

  if (data == nil) then
    apdu = apdu .. "00"
  else
    apdu = apdu .. string.format("%02x", #data/2) .. data
  end

  return string.upper(apdu)
end

local function compute_mac(key, text, doPad)
  local TDES_CBC
  local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	

  if (doPad == true) then	
    TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC +  crypto.PAD_ISO9797_P2, key)	
  end

  local result = crypto.encrypt(TDES_CBC, text, iv)

  log.print(log.DEBUG, "Computed MAC = " .. tostring(result))

  return bytes.sub(result, result:format("%l")-8)
end

--session key derivation based on SCP01
local function deriveSessionKeysSCP01(diversified_derived_key, rnd_challenge, card_challenge)
  local session_key = {}

  local cardChallenge = bytes.new(8, card_challenge)
  local hostChallenge = bytes.new(8, rnd_challenge)
  local derivationData = bytes.new(8, "00000000000000000000000000000000")
  local i
  for i=0,3 do
    --log.print(log.DEBUG, " cc = " .. bytes.get(cardChallenge,i)) 
    bytes.set(derivationData, i, bytes.get(cardChallenge,i+4))
    bytes.set(derivationData, i+4, bytes.get(hostChallenge,i))
    bytes.set(derivationData, i+8, bytes.get(cardChallenge,i)) 
    bytes.set(derivationData, i+12, bytes.get(hostChallenge,i+4))
  end
  log.print(log.DEBUG, "SCP01 SKU derivation data = " .. tostring(derivationData))

  local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
  local TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, diversified_derived_key.KEY_ENC)
  local key = crypto.encrypt(TDES_ECB, derivationData, iv)
  session_key.KEY_ENC = key

  iv = bytes.new(8,"00 00 00 00 00 00 00 00")
  TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, diversified_derived_key.KEY_MAC)
  key = crypto.encrypt(TDES_ECB, derivationData, iv)
  session_key.KEY_MAC = key

  iv = bytes.new(8,"00 00 00 00 00 00 00 00")
  TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, diversified_derived_key.KEY_KEK)
  key = crypto.encrypt(TDES_ECB, derivationData, iv)
  session_key.KEY_KEK = key

  log.print(log.DEBUG, "SCP01 Session Key ENC = " ..  tostring(session_key.KEY_ENC))
  log.print(log.DEBUG, "SCP01 Session Key MAC = " ..  tostring(session_key.KEY_MAC))
  log.print(log.DEBUG, "SCP01 Session Key KEK = " ..  tostring(session_key.KEY_KEK))

  return  session_key	
end


--session key derivation based on SCP02
local function deriveSessionKeysSCP02(diversified_derived_key, seq, implicit_channel)
  local session_key = {}

  local enc_sku_derivation = bytes.new(8,"0182" .. seq .. "000000000000000000000000")
  local kek_sku_derivation = bytes.new(8,"0181" .. seq .. "000000000000000000000000")
  local mac_sku_derivation = bytes.new(8,"0101" .. seq .. "000000000000000000000000")

  local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
  local TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, diversified_derived_key.KEY_ENC)
  local key = crypto.encrypt(TDES_CBC, enc_sku_derivation, iv)
  session_key.KEY_ENC = key

  iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
  TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, diversified_derived_key.KEY_MAC)
  key = crypto.encrypt(TDES_CBC, mac_sku_derivation, iv)
  session_key.KEY_MAC = key

  iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
  TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, diversified_derived_key.KEY_KEK)
  key = crypto.encrypt(TDES_CBC, kek_sku_derivation, iv)
  session_key.KEY_KEK = key

  log.print(log.DEBUG, "SCP02 dersification data ENC = " ..  tostring(enc_sku_derivation))
  log.print(log.DEBUG, "SCP02 dersification data MAC = " ..  tostring(mac_sku_derivation))
  log.print(log.DEBUG, "SCP02 dersification data KEK = " ..  tostring(kek_sku_derivation))

  log.print(log.DEBUG, "SCP02 Session Key ENC = " ..  tostring(session_key.KEY_ENC))
  log.print(log.DEBUG, "SCP02 Session Key MAC = " ..  tostring(session_key.KEY_MAC))
  log.print(log.DEBUG, "SCP02 Session Key KEK = " ..  tostring(session_key.KEY_KEK))

  return session_key			
end

--Compute the mac of apdu based on scp02
local function generateMAC_SCP02(apdu_cmd)

  local CBC_MAC = crypto.create_context(crypto.ALG_ISO9797_M3 + crypto.PAD_ISO9797_P2, GP_SESSION_KEYS.KEY_MAC);	
  local total = bytes.get(apdu_cmd, 4) + 0x08
  bytes.set(apdu_cmd, 4, total)

  C_MAC = crypto.mac_iv(CBC_MAC, apdu_cmd, C_MAC)

  log.print(log.DEBUG, "apdu =  " .. tostring(apdu_cmd))
  log.print(log.DEBUG, "C_MAC =  " .. tostring(C_MAC))

  return bytes.concat(apdu_cmd, C_MAC)
end


-- compute Key Check Value
local function computeKCV(keyDes2)
  local iv = bytes.new(8,"00 00 00 00 00 00 00 00")
  local zero8 = bytes.new(8,"00 00 00 00 00 00 00 00")
  log.print(log.DEBUG, "keyDes2 " .. tostring(keyDes2))
  local TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, keyDes2)
  local computed_kcv = crypto.encrypt(TDES_CBC, zero8, iv)

  return bytes.sub(computed_kcv, 0, 2)
end

-- Prepare new key and compute it
local function encodeNewKey(new_key_set)
  local TDES_ECB
  local encoded_keys = string.format("%02x", new_key_set.KEY_VERSION)
  local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
  local key 
  local new_key
  local kcv

  if  CARD_SCP_VERSION == 1 then
    log.print(log.ERROR, "SCP 01 not implemented")
    error("SCP 01 not implemented")
  elseif  CARD_SCP_VERSION == 2 then                

    key = bytes.new(8, GP_SESSION_KEYS.KEY_KEK)

    for i = _M.KEY_TYPE.ENC, _M.KEY_TYPE.KEK do

      if  i == _M.KEY_TYPE.ENC then       
        new_key = bytes.new(8, new_key_set.KEY_ENC)               
      elseif i == _M.KEY_TYPE.MAC then
        new_key = bytes.new(8, new_key_set.KEY_MAC)
      elseif i == _M.KEY_TYPE.KEK then
        new_key = bytes.new(8, new_key_set.KEY_KEK)
      end

      TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, key)
      encoded_keys = encoded_keys .. "80" .. "10"
      encoded_keys = encoded_keys .. tostring(crypto.encrypt(TDES_ECB, new_key, iv))
      encoded_keys = encoded_keys .. "03"
      encoded_keys = encoded_keys .. tostring(computeKCV(new_key))
    end
  end

  return encoded_keys

end

-----------------------------------------------------------------------------------------------------------
-- GLOBAL FUNCTION, ACCESSIBLE OUTSIDE THE SCOPE
-----------------------------------------------------------------------------------------------------------
function _M.verify_kcv(key1, key2, kcv, Msg)
  local iv = bytes.new(8,"00 00 00 00 00 00 00 00")
  local zero8 = bytes.new(8,"00 00 00 00 00 00 00 00")
  local TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, bytes.concat(key1, key2))
  local computed_kcv = crypto.encrypt(TDES_CBC, zero8, iv)

  if ( bytes.sub(computed_kcv, 0, 2) ==  kcv) then
    log.print(log.DEBUG,"KCV is verified for " .. Msg)
    return true
  end

  return false	--not verified
end

function _M.verify_kcv_rpc(keyname_str, kcv_str)
  local zero8 = "0000000000000000"
  local status, cipherText = call(RPC_SERVER, "SafenetService.encrypt3DesEcb", keyname_str, zero8)
  assert(status, string.format("XML-RPC call failed on client: %s", tostring(cipherText)))

  if ( string.sub(string.upper(cipherText), 1, 6) ==  string.upper(kcv_str)) then
    log.print(log.DEBUG,"KCV is verified for " .. keyname_str)
    return true
  end

  return false	--not verified
end

-- Select the applet
-- parameter: 
--		aid is applet AID
--		cardobj is the reference to terminal
function _M.select_applet(aid, cardobj)
  local sw, resp	
  local cm =  nil
  local val, tail

  if (aid == nil) then
    sw, resp = cardobj.send_auto("00A4040000")

    verify_sw(sw, 0x9000)

    val, tail = get_value_by_tag(0x84, resp)

    if val == nil then		
      log.print(log.WARNING,  "AID Not found using default A000000003000000!")
      cm  = "A000000003000000"
    else
      cm = tostring(val)
      log.print(log.INFO,  "CM AID is " .. cm .. " selected!")
    end

  else		
    sw, resp = cardobj.send_auto("00A40400" .. string.format("%02x", #aid/2) .. aid)

    if (verify_sw(sw, 0x9000) == true) then
      cm = aid		
    end

    if cm ~= nill then		
      log.print(log.INFO,  "CM AID is " .. cm .. " selected!")
    else
      error("AID not found!")			
    end
  end		

  return cm
end




-- Description  : Compose the keys with name of the KEYS in the HSM and return the key set
-- Parameter    : - key_enc
--                - key_mac
--                - key_dek
--                - key_version
--                - key_id
function _M.set_kmc_rpc(kmc_enc_name, kmc_mac_name, kmc_dek_name, key_version, key_id)
  --set the key version (should be match the SCP major version)
  local key_set_table = {KEY_VERSION = 0x00, KEY_ID = 0x00, KEY_ENC = "", KEY_MAC = "", KEY_KEK = ""}


  if (key_version ~= nil) then
    key_set_table.KEY_VERSION = key_version
  end

  if (key_id ~= nil) then
    key_set_table.KEY_ID = key_id
  end

  if (kmc_enc_name == nil) then
    log.print(log.ERROR, "Please set the key ENC name which is stored in the HSM")
    error("kmc enc name is empty")
  else      
    key_set_table.KEY_ENC = kmc_enc_name      
  end

  if (kmc_mac_name == nil) then
    log.print(log.ERROR, "Please set the key MAC name which is stored in the HSM")
    error("kmc mac name is empty")
  else
    key_set_table.KEY_MAC = kmc_mac_name
  end

  if (kmc_dek_name == nil) then
    log.print(log.ERROR, "Please set the key DEK name which is stored in the HSM")
    error("kmc dek name is empty")
  else
    key_set_table.KEY_KEK = kmc_dek_name
  end

  log.print(log.DEBUG, "KMC ENC key name = " .. tostring(key_set_table.KEY_ENC))
  log.print(log.DEBUG, "KMC MAC key name = " .. tostring(key_set_table.KEY_MAC))
  log.print(log.DEBUG, "KMC KEK key name = " .. tostring(key_set_table.KEY_KEK))

  return key_set_table
end


function _M.set_kmc(key_enc, key_mac, key_kek, key_version, key_id)

  local key_set_table = {KEY_VERSION = 0x00, KEY_ID = 0x00, KEY_ENC = bytes.new(8,"404142434445464748494A4B4C4D4E4F"), KEY_MAC = bytes.new(8,"404142434445464748494A4B4C4D4E4F"), KEY_KEK = bytes.new(8,"404142434445464748494A4B4C4D4E4F")}

  if (key_version ~= nil) then
    key_set_table.KEY_VERSION = key_version
  end

  if (key_id ~= nil) then
    key_set_table.KEY_ID = key_id
  end

  if (key_enc ~= nil) then
    if verify_key(key_enc, 16) == true then
      key_set_table.KEY_ENC = bytes.new(8,key_enc)
    end
  end

  if (key_mac ~= nil) then
    if verify_key(key_mac, 16) == true then
      key_set_table.KEY_MAC = bytes.new(8,key_mac)
    end
  end

  if (key_dek ~= nil) then
    if verify_key(key_dek, 16) == true then
      key_set_table.KEY_KEK = bytes.new(8,key_kek)
    end
  end

  log.print(log.DEBUG, "KMC ENC = " .. tostring(key_set_table.KEY_ENC))
  log.print(log.DEBUG, "KMC MAC = " .. tostring(key_set_table.KEY_MAC))
  log.print(log.DEBUG, "KMC KEK = " .. tostring(key_set_table.KEY_KEK))

  return key_set_table
end

-- Get the clear key from HSM, might not work if the key is sensitive
function _M.getClearKey(keyName)
  status, temp_key = call(RPC_SERVER, "SafenetService.wrapDecryptKey",keyName)
  assert(status, string.format("XML-RPC call failed on client: %s", tostring(temp_key)))

  return temp_key
end


-- Description  : 
-- Parameter    : - key_enc
--                - key_mac
--                - key_dek
--                - key_version
--                - key_id
function _M.diversify_key_rpc(divers_mode, update_response, key_set)
  local diversified_key = {}
  local divers_string = ""  
  local status, wrappedKeyVal
  local hKey, cipherText

  --copy the properties on the new object derived key
  diversified_key.KEY_VERSION = key_set.KEY_VERSION
  diversified_key.KEY_ID = key_set.KEY_ID

  if divers_mode == _M.KEY_DIVERSIFY_MODE.NONE then

    local status, hWrapperKey, wrappedKeyVal 
    local theKey, temp_key    

    for i=_M.KEY_TYPE.ENC,_M.KEY_TYPE.KEK do
      if (i == _M.KEY_TYPE.ENC) then

        status, temp_key = call(RPC_SERVER, "SafenetService.wrapDecryptKey",key_set.KEY_ENC)
        assert(status, string.format("XML-RPC call failed on client: %s", tostring(temp_key)))

        diversified_key.KEY_ENC = bytes.new(8, temp_key)
      elseif (i == _M.KEY_TYPE.MAC) then

        status, temp_key = call(RPC_SERVER, "SafenetService.wrapDecryptKey",key_set.KEY_MAC)
        assert(status, string.format("XML-RPC call failed on client: %s", tostring(temp_key)))

        diversified_key.KEY_MAC = bytes.new(8, temp_key)
      elseif (i == _M.KEY_TYPE.KEK) then

        status, temp_key = call(RPC_SERVER, "SafenetService.wrapDecryptKey",key_set.KEY_KEK)
        assert(status, string.format("XML-RPC call failed on client: %s", tostring(temp_key)))

        diversified_key.KEY_KEK = bytes.new(8, temp_key)
      end
    end

  else

    for i=_M.KEY_TYPE.ENC,_M.KEY_TYPE.KEK do

      if divers_mode == _M.KEY_DIVERSIFY_MODE.VISA2 then
        log.print(log.DEBUG,"Diversify using VISA 2 method")
        divers_string = fillVisaStr(update_response, i)
      elseif divers_mode == _M.KEY_DIVERSIFY_MODE.EMV then
        log.print(log.DEBUG,"Diversify using CPS/EMV method")
        divers_string = fillEmvStr(update_response, i)	
      end	

      if (i == _M.KEY_TYPE.ENC) then

        status, cipherText = call(RPC_SERVER, "SafenetService.encrypt3DesEcb",key_set.KEY_ENC, divers_string)
        assert(status, string.format("XML-RPC call failed on client: %s", tostring(cipherText)))

        diversified_key.KEY_ENC = bytes.new(8,cipherText)
        log.print(log.DEBUG, "Using key_set['ENC'] = " .. key_set.KEY_ENC .. " Derived key ENC = " .. tostring(diversified_key.KEY_ENC))
      elseif (i == _M.KEY_TYPE.MAC) then

        status, cipherText = call(RPC_SERVER, "SafenetService.encrypt3DesEcb",key_set.KEY_MAC, divers_string)
        assert(status, string.format("XML-RPC call failed on client: %s", tostring(cipherText)))

        diversified_key.KEY_MAC = bytes.new(8,cipherText)
        log.print(log.DEBUG, "Using key_set['MAC'] = " .. key_set.KEY_MAC .. " Derived key MAC = " .. tostring(diversified_key.KEY_MAC))
      elseif (i == _M.KEY_TYPE.KEK) then

        status, cipherText = call(RPC_SERVER, "SafenetService.encrypt3DesEcb",key_set.KEY_KEK, divers_string)
        assert(status, string.format("XML-RPC call failed on client: %s", tostring(cipherText)))

        diversified_key.KEY_KEK = bytes.new(8,cipherText)
        log.print(log.DEBUG, "Using key_set['KEK'] = " .. key_set.KEY_KEK .. " Derived key KEK = " .. tostring(diversified_key.KEY_KEK))
      end	
    end	
  end

  return diversified_key
end


function _M.diversify_key(divers_mode, update_response, key_set)
  local diversified_key = util.deepcopy(key_set)
  local divers_string = ""
  local update_response_str = tostring(update_response)

  if divers_mode == _M.KEY_DIVERSIFY_MODE.NONE then
    log.print(log.DEBUG, "Not doing key diversification")
    return diversified_key
  end

  for i=_M.KEY_TYPE.ENC,_M.KEY_TYPE.KEK do

    if divers_mode == _M.KEY_DIVERSIFY_MODE.VISA2 then
      divers_string = fillVisaStr(update_response_str, i)
      --log.print(log.DEBUG, "i = " .. i)
    elseif divers_mode == _M.KEY_DIVERSIFY_MODE.EMV then
      divers_string = fillEmvStr(update_response_str, i)	
      --log.print(log.DEBUG, "i = " .. i)
    end	

    local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
    local divers_bytes = bytes.new(8, divers_string)	

    local key
    if (i == _M.KEY_TYPE.ENC) then
      key = key_set.KEY_ENC
    elseif (i == _M.KEY_TYPE.MAC) then
      key = key_set.KEY_MAC
    elseif (i == _M.KEY_TYPE.KEK) then
      key = key_set.KEY_KEK
    end

    local TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, key)

    if (i == _M.KEY_TYPE.ENC) then
      diversified_key.KEY_ENC = crypto.encrypt(TDES_ECB, divers_bytes, iv)			
      log.print(log.DEBUG, "Derived key ENC = " .. tostring(diversified_key.KEY_ENC))
    elseif (i == _M.KEY_TYPE.MAC) then
      diversified_key.KEY_MAC = crypto.encrypt(TDES_ECB, divers_bytes, iv)			
      log.print(log.DEBUG, "Derived key MAC = " .. tostring(diversified_key.KEY_MAC))
    elseif (i == _M.KEY_TYPE.KEK) then
      diversified_key.KEY_KEK = crypto.encrypt(TDES_ECB, divers_bytes, iv)
      log.print(log.DEBUG, "Derived key KEK = " .. tostring(diversified_key.KEY_KEK))			
    end	

    iv = bytes.new(8,"00 00 00 00 00 00 00 00")			
  end	

--  -- make it the same with the current one
  diversified_key.KEY_VERSION =  CARD_KEY_VERSION
  diversified_key.KEY_ID =  CARD_KEY_VERSION

  return diversified_key
end

function _M.doDiversifyKeys(key_set, host_challenge, apdu_mode, key_derivation_type, scp_mode, cardobj)  
  local sw, response
  local random_challenge = ""

  --log.print(log.DEBUG, "key_derivation_type = " .. tostring(key_derivation_type))

  if (host_challenge == nil) then
    math.randomseed(os.time())
    math.random() -- remove the 1st random
    for i=0,7 do		
      random_challenge = random_challenge .. string.format("%02x", math.random(255))
    end
    --log.print(log.DEBUG, "Random = " .. random_challenge)
  else
    random_challenge = host_challenge
  end	

  sw, response = card.send_auto(create_cmd_apdu(0x80, 0x50, 0x00, 0x00, random_challenge))

  if sw == 0x6982 or sw == 0x6983 then
    long.print(log.ERROR, "INITIALIZE UPDATE failed, card LOCKED?")
  end

  verify_sw(sw, 0x9000)

  local update_response = tostring(response)

  if (#update_response/2 ~= 28 and #update_response/2 ~= 29 and #update_response/2 ~= 32) then
    error("Response length %d is wrong (see length)?", #response/2)
  end

  --Parse the response
  local offset = 0	
  local diversification_data = string.sub(update_response, 1, 20)
  offset = offset + #diversification_data;

  --log.print("abcd" .. bytes.sub(response, offset, offset+1))
  --log.print(log.INFO, "offset " .. offset .. " diversification_data " .. tostring(diversification_data))

  --Get used key version from response
  --log.print(log.INFO, "offset  " .. tostring(offset))
  local keyVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  CARD_KEY_VERSION = keyVersion;

  --Get major SCP version from Key Information field in response
  local scpMajorVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  CARD_SCP_VERSION = scpMajorVersion

  -- set the selected scp mode	
  if  (scp_mode == SCP_MODE.SCP_ANY) then
    if (scpMajorVersion == 1) then		
      GP_SCP_MODE = SCP_MODE.SCP_01_05
    elseif (scpMajorVersion == 2) then
      GP_SCP_MODE = SCP_MODE.SCP_02_15
    elseif (scpMajorVersion == 3) then
      log.print(log.ERROR, "SCP03 is not supported");
    end
  else
    log.print(log.WARNING, "Overriding SCP version: card reports " .. scpMajorVersion .. " but user requested " .. scp_mode)		
    if (scp_mode >= 1 or scp_mode <= 2) then
      GP_SCP_MODE = SCP_MODE.SCP_01_05
    elseif (scp_mode > 2 or scp_mode <=  10) then
      GP_SCP_MODE = SCP_MODE.SCP_02_15
    else
      error("error: " .. scp_mode .. " not supported yet")
    end
  end	

  --FIXME: SCP02 has 2 byte sequence + 6 bytes card challenge but the challenge is discarded.
  --get card challenge
  local card_challenge = string.sub(update_response, offset+1, offset + 16);
  offset = offset + #card_challenge

  -- get card cryptogram
  local card_cryptogram  = string.sub(update_response, offset+1, offset + 16);
  offset = offset + #card_cryptogram

  log.print(log.DEBUG, "Card Challenge = " .. card_challenge)
  log.print(log.DEBUG, "Card Cryptogram = " .. card_cryptogram)	

  if (key_set.KEY_VERSION > 0 and keyVersion ~= key_set.KEY_VERSION) then
    error("Key version did not match")
  end	

  local diversified_derived_key = diversify_key_rpc(key_derivation_type, update_response, key_set)

  return diversified_derived_key
end

-------------------------------------------------
-------------------------------------------------
-------------------------------------------------
-- initial update
function _M.init_update_rpc(key_set, host_challenge, apdu_mode, key_derivation_type, scp_mode, cardobj)
  local sw, response
  local random_challenge = ""

  GP_APDU_MODE = apdu_mode

  --log.print(log.DEBUG, "key_derivation_type = " .. tostring(key_derivation_type))

  if (host_challenge == nil) then
    math.randomseed(os.time())
    math.random() -- remove the 1st random
    for i=0,7 do		
      random_challenge = random_challenge .. string.format("%02x", math.random(255))
    end
    --log.print(log.DEBUG, "Random = " .. random_challenge)
  else
    random_challenge = host_challenge
  end	

  sw, response = card.send_auto(create_cmd_apdu(0x80, 0x50, key_set.KEY_VERSION, key_set.KEY_ID, random_challenge))

  if sw == 0x6982 or sw == 0x6983 then
    long.print(log.ERROR, "INITIALIZE UPDATE failed, card LOCKED?")
  end

  verify_sw(sw, 0x9000)

  local update_response = tostring(response)

  if (#update_response/2 ~= 28 and #update_response/2 ~= 29 and #update_response/2 ~= 32) then
    error("Response length %d is wrong (see length)?", #response/2)
  end

  --Parse the response
  local offset = 0	
  local diversification_data = string.sub(update_response, 1, 20)
  offset = offset + #diversification_data;

  --log.print("abcd" .. bytes.sub(response, offset, offset+1))
  --log.print(log.INFO, "offset " .. offset .. " diversification_data " .. tostring(diversification_data))

  --Get used key version from response
  --log.print(log.INFO, "offset  " .. tostring(offset))
  local keyVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  CARD_KEY_VERSION = keyVersion;

  --Get major SCP version from Key Information field in response
  local scpMajorVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  log.print(log.DEBUG, "Key Version (Hex) = " .. string.format("%02x", keyVersion))
  log.print(log.DEBUG, "SCP Major Version (Hex) = " .. string.format("%02x", scpMajorVersion))

  CARD_SCP_VERSION = scpMajorVersion

  -- set the selected scp mode	
  if  (scp_mode == _M.SCP_MODE.SCP_ANY) then
    if (scpMajorVersion == 1) then		
      GP_SCP_MODE = _M.SCP_MODE.SCP_01_05;
    elseif (scpMajorVersion == 2) then
      GP_SCP_MODE = _M.SCP_MODE.SCP_02_15;
    elseif (scpMajorVersion == 3) then
      log.print(log.ERROR, "SCP03 is not supported");
    end
  else
    log.print(log.WARNING, "Overriding SCP version: card reports " .. scpMajorVersion .. " but user requested " .. scp_mode)		
    if (scp_mode >= 1 or scp_mode <= 2) then
      GP_SCP_MODE = _M.SCP_MODE.SCP_01_05
    elseif (scp_mode > 2 or scp_mode <=  10) then
      GP_SCP_MODE = _M.SCP_MODE.SCP_02_15
    else
      error("error: " .. scp_mode .. " not supported yet")
    end
  end	

  --FIXME: SCP02 has 2 byte sequence + 6 bytes card challenge but the challenge is discarded.
  --get card challenge
  local card_challenge = string.sub(update_response, offset+1, offset + 16);
  offset = offset + #card_challenge

  -- get card cryptogram
  local card_cryptogram  = string.sub(update_response, offset+1, offset + 16);
  offset = offset + #card_cryptogram

  log.print(log.DEBUG, "Card Challenge = " .. card_challenge)
  log.print(log.DEBUG, "Card Cryptogram = " .. card_cryptogram)	

  if (key_set.KEY_VERSION > 0 and keyVersion ~= key_set.KEY_VERSION) then
    error("Key version did not match")
  end	

  local diversified_derived_key = _M.diversify_key_rpc(key_derivation_type, update_response, key_set)

  --Derive session keys
  local seq

  --deriveSessionKeysSCP01(diversified_derived_key, random_challenge, card_challenge)

  if (scpMajorVersion == 1) then
    GP_SESSION_KEYS = deriveSessionKeysSCP01(diversified_derived_key, random_challenge, card_challenge)
  elseif (scpMajorVersion == 2) then
    --seq = Arrays.copyOfRange(update_response, 12, 14)
    seq = string.sub(update_response, 25, 28)
    --log.print(log.DEBUG, "seq " .. tostring(seq))
    GP_SESSION_KEYS = deriveSessionKeysSCP02(diversified_derived_key, seq, false)
  else
    error("Session key derivation for SCP03 not supported")
  end		

  local my_cryptogram = compute_mac(GP_SESSION_KEYS.KEY_ENC, bytes.concat(random_challenge, card_challenge), true)	

  if (card_cryptogram ~= tostring(my_cryptogram)) then
    error("Mac do not match!")
  end

  GP_CARD_CHALLENGE = card_challenge
  GP_HOST_CHALLENGE =  random_challenge	
  GP_SCP_VERSION = scpMajorVersion

  return response
end

---------------------------------------------------------
-- initial update
-- 
---------------------------------------------------------
function _M.init_update(key_set, host_challenge, apdu_mode, key_derivation_type, scp_mode, cardobj)
  local sw, response
  local random_challenge = ""

  log.print(log.DEBUG, "key_derivation_type = " .. tostring(key_derivation_type))

  if (host_challenge == nil) then
    math.randomseed(os.time())
    math.random() -- remove the 1st random
    for i=0,7 do		
      random_challenge = random_challenge .. string.format("%02x", math.random(255))
    end
    log.print(log.DEBUG, "Random = " .. random_challenge)
  else
    random_challenge = host_challenge
  end	

  sw, response = card.send_auto(create_cmd_apdu(0x80, 0x50, key_set.KEY_VERSION, key_set.KEY_ID, random_challenge))

  if sw == 0x6982 or sw == 0x6983 then
    long.print(log.ERROR, "INITIALIZE UPDATE failed, card LOCKED?")
  end

  verify_sw(sw, 0x9000)

  local update_response = tostring(response)

  if (#update_response/2 ~= 28 and #update_response/2 ~= 29 and #update_response/2 ~= 32) then
    error("Response length %d is wrong (see length)?", #response/2)
  end

  --Parse the response
  local offset = 0	
  local diversification_data = string.sub(update_response, 1, 20)
  offset = offset + #diversification_data;

  --log.print("abcd" .. bytes.sub(response, offset, offset+1))
  --log.print(log.INFO, "offset " .. offset .. " diversification_data " .. tostring(diversification_data))

  --Get used key version from response
  --log.print(log.INFO, "offset  " .. tostring(offset))
  local keyVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  --Get major SCP version from Key Information field in response
  local scpMajorVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  CARD_KEY_VERSION = keyVersion;
  CARD_SCP_VERSION = scpMajorVersion

  log.print(log.DEBUG, "Key Version (Hex) = " .. string.format("%02x", keyVersion))
  log.print(log.DEBUG, "SCP Major Version (Hex) = " .. string.format("%02x", scpMajorVersion))

  -- set the selected scp mode	
  if  (scp_mode == _M.SCP_MODE.SCP_ANY) then
    if (scpMajorVersion == 1) then		
      GP_SCP_MODE = _M.SCP_MODE.SCP_01_05
    elseif (scpMajorVersion == 2) then
      GP_SCP_MODE = _M.SCP_MODE.SCP_02_15
    elseif (scpMajorVersion == 3) then
      log.print(log.ERROR, "SCP03 is not supported");
    end
  else
    log.print(log.WARNING, "Overriding SCP version: card reports " .. scpMajorVersion .. " but user requested " .. scp_mode)		
    if (scp_mode >= 1 or scp_mode <= 2) then
      GP_SCP_MODE = _M.SCP_MODE.SCP_01_05
    elseif (scp_mode > 2 or scp_mode <=  10) then
      GP_SCP_MODE = _M.SCP_MODE.SCP_02_15
    else
      error("error: " .. scp_mode .. " not supported yet")
    end
  end	

  --FIXME: SCP02 has 2 byte sequence + 6 bytes card challenge but the challenge is discarded.
  --get card challenge
  local card_challenge = string.sub(update_response, offset+1, offset + 16);
  offset = offset + #card_challenge

  -- get card cryptogram
  local card_cryptogram  = string.sub(update_response, offset+1, offset + 16);
  offset = offset + #card_cryptogram

  log.print(log.DEBUG, "Card Challenge = " .. card_challenge)
  log.print(log.DEBUG, "Card Cryptogram = " .. card_cryptogram)	

  if (key_set.KEY_VERSION > 0 and keyVersion ~= key_set.KEY_VERSION) then
    error("Key version did not match")
  end	

  local diversified_derived_key = _M.diversify_key(key_derivation_type, update_response, key_set)

  --Derive session keys
  local seq

  --deriveSessionKeysSCP01(diversified_derived_key, random_challenge, card_challenge)

  if (scpMajorVersion == 1) then
    GP_SESSION_KEYS = deriveSessionKeysSCP01(diversified_derived_key, random_challenge, card_challenge)
  elseif (scpMajorVersion == 2) then
    --seq = Arrays.copyOfRange(update_response, 12, 14)
    seq = string.sub(update_response, 25, 28)
    --log.print(log.DEBUG, "seq " .. tostring(seq))
    GP_SESSION_KEYS = deriveSessionKeysSCP02(diversified_derived_key, seq, false)
  else
    error("Session key derivation for SCP03 not supported")
  end		

  local my_cryptogram = compute_mac(GP_SESSION_KEYS.KEY_ENC, bytes.concat(random_challenge, card_challenge), true)	

  if (card_cryptogram ~= tostring(my_cryptogram)) then
    error("Mac do not match!")
  end

  GP_CARD_CHALLENGE = card_challenge
  GP_HOST_CHALLENGE =  random_challenge	
  GP_APDU_MODE = apdu_mode
  GP_SCP_VERSION = scpMajorVersion

  return sw, response
end


--do the external authenticate
function _M.external_authenticate()	
  local host_cryptogram = compute_mac(GP_SESSION_KEYS.KEY_ENC, bytes.concat(GP_CARD_CHALLENGE, GP_HOST_CHALLENGE), true)
  local apdu = create_cmd_apdu(0x84, 0x82, tonumber(GP_APDU_MODE), 0x00, tostring(host_cryptogram))
  local secure_apdu

  C_MAC = bytes.new(8,"00 00 00 00 00 00 00 00")		
  if (GP_SCP_VERSION == 2) then	
    secure_apdu = generateMAC_SCP02(bytes.new(8, apdu));
  elseif (GP_SCP_VERSION == 1) then
    log.print(log.ERROR, "SCP01 session key derivation not yet implemented")
    error("SCP01 session key derivation not yet implemented")
  else
    error("SCPX Not implemented yet")
  end

  local sw, response = card.send(secure_apdu)
  verify_sw(sw, 0x9000)
end


function _M.put_keyset(new_key_set)
  local isReplace = false

  --if not virgin card then replace the key
  if (CARD_KEY_VERSION ~= 0x00 and CARD_KEY_VERSION ~= 255) then
    isReplace = true
  end

  -- if replace then change P1 with the old key version/id
  local P1 = 0x00; 
  if isReplace == true then
    log.print(log.DEBUG, "P1 = CARD_KEY_VERSION = " .. CARD_KEY_VERSION)
    P1 = CARD_KEY_VERSION
  end

--  -- OR with new key ID
  local P2 = 0x80 | new_key_set.KEY_ID

  local encodedKeyData

  if CARD_SCP_VERSION == 1 then
    log.print(log.ERROR, "SCP 01 is not yet implemented")
    error("SCP 01 is not yet implemented")
  elseif CARD_SCP_VERSION == 2 then
    encodedKeyData = tostring(encodeNewKey(new_key_set, false))
  else
    error("Not yet implemented")
  end      

  log.print(log.DEBUG, "encodedKeyData " .. encodedKeyData)

  local apdu
  local sw, response 

  log.print(log.DEBUG, "GP_APDU_MODE = " .. _M.GP_APDU_MODE)

  if (GP_APDU_MODE == _M.APDU_MODE.CLR) then 
    apdu = create_cmd_apdu(0x80, 0xD8, P1, P2, encodedKeyData)
    sw, response = card.send_auto(apdu)
    verify_sw(sw, 0x9000)
  else
--  log.print(log.DEBUG, "C_MAC " .. tostring(C_MAC))
--  log.print(log.DEBUG, "mac ses key " .. tostring(bytes.sub(GP_SESSION_KEYS["MAC"], 0,7)))
--  log.print(log.DEBUG, "mac ses key " .. tostring(bytes.sub(GP_SESSION_KEYS["MAC"], 0,15)))

    apdu = create_cmd_apdu(0x84, 0xD8, P1, P2, encodedKeyData)

    ---- Compute the MAC --
    local des_key = bytes.new(8,bytes.sub(GP_SESSION_KEYS.KEY_MAC, 0,7))
    local SDES_ECB = crypto.create_context(crypto.ALG_DES_ECB, des_key)
    C_MAC = crypto.encrypt(SDES_ECB, C_MAC)			

    local secure_apdu = generateMAC_SCP02(bytes.new(8, apdu));
    sw, response = card.send_auto(secure_apdu)
    verify_sw(sw, 0x9000)
  end

end


function _M.get_current_scp_version(update_response)

  if (#update_response/2 ~= 28 and #update_response/2 ~= 29 and #update_response/2 ~= 32) then
    error("Response length %d is wrong (see length)?", #response/2)
  end

  --Parse the response
  local offset = 0	
  local diversification_data = string.sub(update_response, 1, 20)
  offset = offset + #diversification_data;

  --log.print("abcd" .. bytes.sub(response, offset, offset+1))
  --log.print(log.INFO, "offset " .. offset .. " diversification_data " .. tostring(diversification_data))

  --Get used key version from response
  --log.print(log.INFO, "offset  " .. tostring(offset))
  local keyVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  CARD_KEY_VERSION = keyVersion;

  --Get major SCP version from Key Information field in response
  local scpMajorVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  CARD_SCP_VERSION = scpMajorVersion

  return scpMajorVersion

end

function _M.get_current_key_version(update_response)

  if (#update_response/2 ~= 28 and #update_response/2 ~= 29 and #update_response/2 ~= 32) then
    error("Response length %d is wrong (see length)?", #response/2)
  end

  --Parse the response
  local offset = 0	
  local diversification_data = string.sub(update_response, 1, 20)
  offset = offset + #diversification_data;

  --log.print("abcd" .. bytes.sub(response, offset, offset+1))
  --log.print(log.INFO, "offset " .. offset .. " diversification_data " .. tostring(diversification_data))

  --Get used key version from response
  --log.print(log.INFO, "offset  " .. tostring(offset))
  local keyVersion = tonumber(string.sub(update_response, offset+1, offset+2), 16)
  offset = offset+2

  return keyVersion  
end


-- Global platform send get status APDU command
local function getConcatenatedStatus(p1, data)
  local  sw, response = card.send_auto(create_cmd_apdu(CLA_GP, INS_GET_STATUS, p1, 0x00, data))

  if (sw ~= 0x9000 and sw ~= 0x6310) then
    return response
  end

  while (sw == 0x6310) do
    sw, response = card.send_auto(create_cmd_apdu(CLA_GP, INS_GET_STATUS, p1, 0x01, data))

    if (sw ~= 0x9000 and sw ~=0x6310) then
      error("Fail on get status command SW= " .. tostring(sw))
    end
  end

  return response
end


-- Global platform get status
function _M.getStatus()
  local p1s = { 0x80, 0x40 }
  local data = "4F00"

  for i=1,#p1s do
    local response= getConcatenatedStatus(p1s[i], data)  
  end

end


return _M