--------------------------------------------------------------------------------
--	Author	:	Bondhan Novandy
--	Date	  :	January 2016
--	INFO	  :	Implementation of Global Platform (see GlobalPlatformPro) in LUA
--	License	:	MIT License
--------------------------------------------------------------------------------

--global variables
GP_SESSION_KEYS = {}
GP_SCP_MODE = 0
GP_APDU_MODE = 0
GP_SCP_VERSION = 2
GP_CARD_CHALLENGE = ""
GP_HOST_CHALLENGE = ""
C_MAC = bytes.new(8,"0000000000000000")

--The apdu mode for secure messaging
APDU_MODE = {["CLR"] = 0x0, ["MAC"] = 0x01, ["ENC"] = 0x02, ["RMAC"] = 0x10}

--Key diversification mode
KEY_DIVERSIFY_MODE = {["NONE"] = 0x00, ["VISA2"] = 0x01, ["EMV"] = 0x02}

--Key type
KEY_TYPE = {["ENC"] = 1, ["MAC"] = 2, ["KEK"] = 3}

--SCP Mode
SCP_MODE = { ["SCP_ANY"] = 0, ["SCP_01_05"] = 1, ["SCP_01_15"] = 2, ["SCP_02_04"] = 3, ["SCP_02_05"] = 4,
			 ["SCP_02_0A"] = 5, ["SCP_02_0B"] = 6, ["SCP_02_14"] = 7, ["SCP_02_15"] = 8, ["SCP_02_1A"] = 9, ["SCP_02_1B"] = 10}		 
       
function doWithError(str)
 log.close_logfile()
 error(str)
end
			 
-- verify SW1 and SW2
function verify_sw(recv_sw, ref_sw) 
	if (recv_sw ~= ref_sw) then
   
		doWithError("Received " .. string.format("sw = %x", recv_sw) .. " Expect " .. string.format("sw = %x", ref_sw))
	end
	
	return true
end


-- ternary operation just like in C
function ternary ( cond , T , F )
    if cond then return T else return F end
end

-- Get the value of the data by its tag
-- parameter: 
--		tag 
--		resp
function get_value_by_tag(tag, resp)
	local tlv_tag, tlv_value, tlv_tail = asn1.split(resp)
	
	if tlv_tag ~= nill then
		if tlv_tag == tag then
			return tlv_value, tlv_tail
		else
			return get_value_by_tag(tag, tlv_value)
		end
	end

end

-- Select the applet
-- parameter: 
--		aid is applet AID
--		cardobj is the reference to terminal (pcsc_card or pcsc_sam)
function select_applet(aid, cardobj)
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
			doWithError("AID not found!")			
		end
	end		
	
	return cm
end

--basic method to verify if the key is valid
function verify_key(key, length)
	if (#key/2 ~= length) then
		doWithError("Wrong key length")
	end
	
	if (string.find(key, "%x") == nil) then
		doWithError("key is not hex value")
	end	
		
	return true
end


-- compos a key set
function set_kmc(key_enc, key_mac, key_dek, key_version, key_id)
	local key_set_table = {}
	
	if (key_version == nil) then
		key_set_table["keyVersion"] = 0x00
	else
		key_set_table["keyVersion"] = key_version
	end
	
	if (key_id == nil) then
		key_set_table["keyId"] = 0x00
	else
		key_set_table["keyId"] = key_id
	end
	
	if (key_enc == nil) then
		key_set_table["ENC"] = bytes.new(8,"404142434445464748494A4B4C4D4E4F")
		log.print(log.WARNING, "key is set to default value 404142434445464748494A4B4C4D4E4F")
	else
		if verify_key(key_enc, 16) == true then
			key_set_table["ENC"] = bytes.new(8,key_enc)
		end
	end
	
	if (key_mac == nil) then
		key_set_table["MAC"] = bytes.new(8,"404142434445464748494A4B4C4D4E4F")
		log.print(log.WARNING, "key is set to default value 404142434445464748494A4B4C4D4E4F")
	else
		if verify_key(key_mac, 16) == true then
			key_set_table["MAC"] = bytes.new(8,key_mac)
		end
	end
	
	if (key_dek == nil) then
		key_set_table["KEK"] = bytes.new(8,"404142434445464748494A4B4C4D4E4F")
		log.print(log.WARNING, "key is set to default value 404142434445464748494A4B4C4D4E4F")
	else
		if verify_key(key_dek, 16) == true then
			key_set_table["KEK"] = bytes.new(8,key_dek)
		end
	end
	
	log.print(log.DEBUG, "KMC ENC = " .. tostring(key_set_table["ENC"]))
	log.print(log.DEBUG, "KMC MAC = " .. tostring(key_set_table["MAC"]))
	log.print(log.DEBUG, "KMC KEK = " .. tostring(key_set_table["KEK"]))
	
	return key_set_table
end

-- build command apdu
function create_cmd_apdu(cla, ins, p1, p2, data)
	local apdu = string.format("%02x", cla) .. string.format("%02x", ins) .. string.format("%02x", p1) .. string.format("%02x", p2) 
	
	if (data == nil) then
		apdu = apdu .. "00"
	else
		apdu = apdu .. string.format("%02x", #data/2) .. data
	end
	
	return string.upper(apdu)
end

-- filling the diversification data using VISA methodology
function fillVisa(update_response, key_type)
	local data = ""
	data = data .. string.sub(update_response, 1, 4) .. string.sub(update_response, 9, 16) .. "F0" .. string.format("%02x", key_type)
	data = data .. string.sub(update_response, 1, 4) .. string.sub(update_response, 9, 16) .. "0F" .. string.format("%02x", key_type)
	
	log.print(log.DEBUG, "diversification data visa = " .. data)
	return bytes.new(8, data)
end

-- filling the diversification data using EMV methodology
function fillEmv(update_response, key_type)
	local data = ""
	data = data .. string.sub(update_response, 9, 20) .. "F0" .. string.format("%02x", key_type)
	data = data .. string.sub(update_response, 9, 20) .. "0F" .. string.format("%02x", key_type)
	
	log.print(log.DEBUG, "diversification data EMV = " .. data)
	return bytes.new(8, data)
end

-- Method to diviersify the card key
function diversify_key(divers_mode, update_response, key_set)
	local diversified_key = key_set
	local divers_string = ""
		
	if divers_mode == KEY_DIVERSIFY_MODE["NONE"] then
		log.print(log.DEBUG, "Not doing key diversification")
		return diversified_key
	end
	
	local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
			
	for i=KEY_TYPE["ENC"],KEY_TYPE["KEK"] do
		
		if divers_mode == KEY_DIVERSIFY_MODE["VISA2"] then
			divers_string = fillVisa(update_response, i)
			--log.print(log.DEBUG, "i = " .. i)
		elseif divers_mode == KEY_DIVERSIFY_MODE["EMV"] then
			divers_string = fillEmv(update_response, i)	
			--log.print(log.DEBUG, "i = " .. i)
		end	
		
		local key
		if (i == KEY_TYPE["ENC"]) then
			key = key_set["ENC"]
		elseif (i == KEY_TYPE["MAC"]) then
			key = key_set["MAC"]
		elseif (i == KEY_TYPE["KEK"]) then
			key = key_set["KEK"]
		end
				
		local TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, key)
				
		if (i == KEY_TYPE["ENC"]) then
			diversified_key["ENC"] = crypto.encrypt(TDES_ECB, divers_string, iv)			
			log.print(log.DEBUG, "Derived key ENC = " .. tostring(diversified_key["ENC"]))
		elseif (i == KEY_TYPE["MAC"]) then
			diversified_key["MAC"] = crypto.encrypt(TDES_ECB, divers_string, iv)			
			log.print(log.DEBUG, "Derived key MAC = " .. tostring(diversified_key["MAC"]))
		elseif (i == KEY_TYPE["KEK"]) then
			diversified_key["KEK"] = crypto.encrypt(TDES_ECB, divers_string, iv)
			log.print(log.DEBUG, "Derived key KEK = " .. tostring(diversified_key["KEK"]))			
		end	

		iv = bytes.new(8,"00 00 00 00 00 00 00 00")			
	end	
	
	return diversified_key
end

--session key derivation based on SCP01
function deriveSessionKeysSCP01(diversified_derived_key, rnd_challenge, card_challenge)
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
	local TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, diversified_derived_key["ENC"])
	local key = crypto.encrypt(TDES_ECB, derivationData, iv)
	session_key["ENC"] = key
	
	iv = bytes.new(8,"00 00 00 00 00 00 00 00")
	TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, diversified_derived_key["MAC"])
	key = crypto.encrypt(TDES_ECB, derivationData, iv)
	session_key["MAC"] = key
	
	iv = bytes.new(8,"00 00 00 00 00 00 00 00")
	TDES_ECB = crypto.create_context(crypto.ALG_DES2_EDE_ECB, diversified_derived_key["KEK"])
	key = crypto.encrypt(TDES_ECB, derivationData, iv)
	session_key["KEK"] = key
	
	log.print(log.DEBUG, "SCP01 Session Key ENC = " ..  tostring(session_key["ENC"]))
	log.print(log.DEBUG, "SCP01 Session Key MAC = " ..  tostring(session_key["MAC"]))
	log.print(log.DEBUG, "SCP01 Session Key KEK = " ..  tostring(session_key["KEK"]))
	
	return  session_key	
end


--session key derivation based on SCP02
function deriveSessionKeysSCP02(diversified_derived_key, seq, implicit_channel)
	local session_key = {}

	local enc_sku_derivation = bytes.new(8,"0182" .. seq .. "000000000000000000000000")
	local kek_sku_derivation = bytes.new(8,"0181" .. seq .. "000000000000000000000000")
	local mac_sku_derivation = bytes.new(8,"0101" .. seq .. "000000000000000000000000")

	local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
	local TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, diversified_derived_key["ENC"])
	local key = crypto.encrypt(TDES_CBC, enc_sku_derivation, iv)
	session_key["ENC"] = key
	
	iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
	TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, diversified_derived_key["MAC"])
	key = crypto.encrypt(TDES_CBC, mac_sku_derivation, iv)
	session_key["MAC"] = key
	
	iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
	TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC, diversified_derived_key["KEK"])
	key = crypto.encrypt(TDES_CBC, kek_sku_derivation, iv)
	session_key["KEK"] = key
		
	log.print(log.DEBUG, "SCP02 diversification data ENC = " ..  tostring(enc_sku_derivation))
	log.print(log.DEBUG, "SCP02 diversification data MAC = " ..  tostring(mac_sku_derivation))
	log.print(log.DEBUG, "SCP02 diversification data KEK = " ..  tostring(kek_sku_derivation))
	
	log.print(log.DEBUG, "SCP02 Session Key ENC = " ..  tostring(session_key["ENC"]))
	log.print(log.DEBUG, "SCP02 Session Key MAC = " ..  tostring(session_key["MAC"]))
	log.print(log.DEBUG, "SCP02 Session Key KEK = " ..  tostring(session_key["KEK"]))
	
	return session_key			
end

-- Compute MAC
function compute_mac(key, text, doPad)
	local TDES_CBC
	local iv = bytes.new(8,"00 00 00 00 00 00 00 00")	
	
	if (doPad == true) then	
	 TDES_CBC = crypto.create_context(crypto.ALG_DES2_EDE_CBC +  crypto.PAD_ISO9797_P2, key)	
	end
	
	local result = crypto.encrypt(TDES_CBC, text, iv)
	
	log.print(log.DEBUG, "Computed MAC = " .. tostring(result))
	return bytes.sub(result, result:format("%l")-8)
end

-- initial update command
function init_update(key_set, host_challenge, apdu_mode, key_derivation_type, scp_mode, cardobj)
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
		
	sw, response = card.send_auto(create_cmd_apdu(0x80, 0x50, key_set["keyVersion"], key_set["keyId"], random_challenge))
	
	if sw == 0x6982 or sw == 0x6983 then
		long.print(log.doWithError, "INITIALIZE UPDATE failed, card LOCKED?")
	end
	
	verify_sw(sw, 0x9000)
	
	local update_response = tostring(response)
		
	if (#update_response/2 ~= 28 and #update_response/2 ~= 29 and #update_response/2 ~= 32) then
		doWithError("Response length %d is wrong (see length)?", #response/2)
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
	
	log.print(log.DEBUG, "Key Version (Hex) = " .. string.format("%02x", keyVersion))
	log.print(log.DEBUG, "SCP Major Version (Hex) = " .. string.format("%02x", scpMajorVersion))
	
	-- set the selected scp mode	
	if  (scp_mode == SCP_MODE["SCP_ANY"]) then
		if (scpMajorVersion == 1) then		
				GP_SCP_MODE = SCP_MODE["SCP_01_05"];
		elseif (scpMajorVersion == 2) then
				GP_SCP_MODE = SCP_MODE["SCP_02_15"];
		elseif (scpMajorVersion == 3) then
				log.print(log.doWithError, "SCP03 is not supported");
		end
	else
		log.print(log.WARNING, "Overriding SCP version: card reports " .. scpMajorVersion .. " but user requested " .. scp_mode)		
		if (scp_mode >= 1 or scp_mode <= 2) then
			GP_SCP_MODE = SCP_MODE["SCP_01_05"]
		elseif (scp_mode > 2 or scp_mode <=  10) then
			GP_SCP_MODE = SCP_MODE["SCP_02_15"]
		else
			doWithError("doWithError: " .. scp_mode .. " not supported yet")
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
	
	if (key_set["keyVersion"] > 0 and keyVersion ~= key_set["keyVersion"]) then
		doWithError("Key version did not match")
	end	

	local diversified_derived_key = diversify_key(key_derivation_type, update_response, key_set)
	
	--Derive session keys
	local seq
		
	--deriveSessionKeysSCP01(diversified_derived_key, random_challenge, card_challenge)
	
	if (scpMajorVersion == 1) then
		GP_SESSION_KEYS = deriveSessionKeysSCP01(diversified_derived_key, random_challenge, card_challenge)
	elseif (scpMajorVersion == 2) then
		--seq = Arrays.copyOfRange(update_response, 12, 14)
		seq = string.sub(update_response, 25, 28)
		log.print(log.DEBUG, "seq " .. tostring(seq))
		GP_SESSION_KEYS = deriveSessionKeysSCP02(diversified_derived_key, seq, false)
	else
		doWithError("Session key derivation for SCP03 not supported")
	end		

	local my_cryptogram = compute_mac(GP_SESSION_KEYS["ENC"], bytes.concat(random_challenge, card_challenge), true)	
	
	if (card_cryptogram ~= tostring(my_cryptogram)) then
		doWithError("Mac do not match!")
	end
	
	GP_CARD_CHALLENGE = card_challenge
	GP_HOST_CHALLENGE =  random_challenge	
	GP_APDU_MODE = apdu_mode
	GP_SCP_VERSION = scpMajorVersion
end

--Compute the mac of apdu based on scp02
function generateMAC_SCP02(apdu_cmd)
	
	local CBC_MAC = crypto.create_context(crypto.ALG_ISO9797_M3 + crypto.PAD_ISO9797_P2, GP_SESSION_KEYS["MAC"]);	
	local total = bytes.get(apdu_cmd, 4) + 0x08
	bytes.set(apdu_cmd, 4, total)
	
	C_MAC = crypto.mac_iv(CBC_MAC, apdu_cmd, C_MAC)
	
	log.print(log.DEBUG, "apdu =  " .. tostring(apdu_cmd))
	log.print(log.DEBUG, "C_MAC =  " .. tostring(C_MAC))
	
	return bytes.concat(apdu_cmd, C_MAC)
end

--do the external authenticate
function external_authenticate()	
	local host_cryptogram = compute_mac(GP_SESSION_KEYS["ENC"], bytes.concat(GP_CARD_CHALLENGE, GP_HOST_CHALLENGE), true)
	local apdu = create_cmd_apdu(0x84, 0x82, tonumber(GP_APDU_MODE), 0x00, tostring(host_cryptogram))
	local secure_apdu
	
	C_MAC = bytes.new(8,"00 00 00 00 00 00 00 00")		
	if (GP_SCP_VERSION == 2) then	
		secure_apdu = generateMAC_SCP02(bytes.new(8, apdu));
	elseif (GP_SCP_VERSION == 1) then
		
	end
	
	local sw, response = card.send(secure_apdu)
	verify_sw(sw, 0x9000)
end