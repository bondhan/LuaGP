package.path = "C:\\SCPComLib8.14\\MCES_8.14\\ChipCoding\\Scripts\\LuaGP\\?.lua;" .. package.path 
--log.print(log.INFO, "path = " .. package.path)

require "lualib.gp_std"


--///////////////////////////////////////////////////////////////////////////////
--MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN 
--///////////////////////////////////////////////////////////////////////////////
local CM_AID
local VISA_AID = "A0000000031010"

CM_AID = nil

--Set Key Set
--local KMC_ENC = "404142434445464748494A4B4C4D4E4F"
--local KMC_MAC = "404142434445464748494A4B4C4D4E4F"
--local KMC_DEK = "404142434445464748494A4B4C4D4E4F"

--local KMC_ENC = "4755525557414C54455244534F555A41"
--local KMC_MAC = "4755525557414C54455244534F555A41"
--local KMC_DEK = "4755525557414C54455244534F555A41"

--local KMC_ENC = "47454D5850524553534F53414D504C45"
--local KMC_MAC = "47454D5850524553534F53414D504C45"
--local KMC_DEK = "47454D5850524553534F53414D504C45"

local KMC_ENC = "464F4C45454F43494951524054454940"
local KMC_MAC = "464F4C45454F43494951524054454940"
local KMC_DEK = "464F4C45454F43494951524054454940"

--Set secure messaging type
local apdu_mode = APDU_MODE["CLR"]

--Set key diversification
local key_div = KEY_DIVERSIFY_MODE["EMV"]

--the SCP mode
local scp_mode = SCP_MODE["SCP_02_15"]

--random challenge
local  host_random = nil --"1122334455667788"

card  = pcsc_card

--//////////////////////////////////////////////////////////////////////////////////////////
-- CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG CONFIG 
--//////////////////////////////////////////////////////////////////////////////////////////

local reader_name = "O2Micro CCID SC Reader 0"
--local reader_name=card_reader

--connect to reader name
local isconnected = card.connect_reader(reader_name)
if (isconnected == false) then
	error("Cannot connect to reader")
	return
end

--get the atr
local atr = card.get_atr()
log.print(log.INFO,"Card ATR = " .. atr)

--Select CM/AID
select_applet(CM_AID, card)

local kmc_key_set = set_kmc(KMC_ENC, KMC_MAC, KMC_DEK)

--local key_div = KEY_DIVERSIFY_MODE["NONE"]
log.print(log.DEBUG, "key_derivation_type = " .. tostring(key_div))

init_update(kmc_key_set, host_random, apdu_mode, key_div, scp_mode, card)

external_authenticate()