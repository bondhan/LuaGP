package.path = "C:\\SCPComLib8.14\\MCES_8.14\\ChipCoding\\Scripts\\LuaGP\\?.lua;" .. package.path 
--log.print(log.INFO, "path = " .. package.path)

require "lualib.gp"

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

local KMC_ENC = "47454D5850524553534F53414D504C45"
local KMC_MAC = "47454D5850524553534F53414D504C45"
local KMC_DEK = "47454D5850524553534F53414D504C45"

--Set secure messaging type
local apdu_mode = APDU_MODE["CLR"]

--Set key diversification
local key_div = KEY_DIVERSIFY_MODE["VISA2"]

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

log.print(log.DEBUG, "Delete existing applet")
sw, response  = card.send_auto("80E40080124F1036333666366432653639366536363666")
--verify_sw(sw,0x9000)

log.print(log.DEBUG, "Install applet")
sw, response  = card.send_auto("80E602001D103633366636643265363936653636366608A000000003000000000000")
verify_sw(sw,0x9000)


log.print(log.DEBUG, "Loading applet ...")
sw, response  = card.send_auto("80E80000FFC48202D0010023DECAFFED0202040001103633366636643265363936653636366608636F6D2F696E666F02002100230021001400150036000E01D2000A00280000006C047000000000000002010004001502020107A0000000620101000107A0000000030000030014011034663730346436353664343936653636000106000E000000800300FF000701000000740701D2000633033203290410142905181D16053D04415B29054125181D16053D04415B290541258D000032181D16053D04415B29054125181D16053D04415B290541258D000029048F00013D1F16048C0002181D0441181D258B00037A0232188C00041E60120332700A1D900B28045903")
verify_sw(sw,0x9000)

sw, response  = card.send_auto("80E80001FF011F1E6CF67A0423188B000560037A198B00062D1A04257501460004FFB80015FFB90057FFC70112FFC800971A03251100FF531100806A08116E008D00071A052561071A06256008116B008D00071A072510086A081167008D00071903100C10088D0008190310088B0009A800F81A03251100FF531100806A08116E008D00071A052561071A06256008116B008D00071A0725056A081167008D00071A038D000A8D000B3B1903058B0009A800B81A03251100FF531100806A08116E008D00071A05256008116B008D00071A062560141A0625046A0E1A0625056A08116B008D00071A0725056A081167008D00071A0625610E1A03038D000C8D000B3B7024")
verify_sw(sw,0x9000)

sw, response  = card.send_auto("80E88002D61A0625046B0E1A03058D000C8D000B3B70121A0625056B0C1A03048D000C8D000B3B1903058B0009703C0332038D000C117FFF6C0E117FFF900B280459030170ED1A031F8D000B3B038D000C29041A0516048D000B3B1903078B00097008116D008D00077A08000A00000000000000000000050036000D06801005010002000600005A03800302068003000380030303800A01068007010681010203800A0806800809068010060680081009002800000024251C05070A071A072B100D090715100C050307150B170C0B030F030F0307081705090708")
verify_sw(sw,0x9000)

sw, response  = card.send_auto("80E60C003A103633366636643265363936653636366610346637303464363536643439366536361034663730346436353664343936653636010003C9010000")
verify_sw(sw,0x9000)


