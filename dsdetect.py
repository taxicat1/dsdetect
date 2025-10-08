"""
Analyze a Nintendo DS ROM file (.nds) for the presence of DS Protect.
"""

import struct
import argparse


# Signatures for identification purposes
dsprot_identifying_signatures = {
	"1.05"          :  [ 0xBAFE0F18, 0xE59CAF7A, 0xE2861884, 0xE1C5DA54, 0xEA018A6B, 0xEB0070C2 ],
	"1.06"          :  [ 0xBAFE9B10, 0xE59CFA77, 0xE2862A71, 0xE1C54E3D, 0xEA01879D, 0xEB005FDF ],
	"1.08"          :  [ 0xBAFE4040, 0xE59C2300, 0xE2852226, 0xE1C5CBE8, 0xEA01612F, 0xEB004979 ],
	"1.10"          :  [ 0xBAFE29A2, 0xE59CC95B, 0xE285D70A, 0xE1C5442C, 0xEA01FD7E, 0xEB001CFC ],
	"1.20"          :  [ 0xE3580F00, 0xBAFE7DF8, 0xE284DFF9, 0xE1C2059D, 0xEA014DE4, 0xEB002F0C ],
	"1.22"          :  [ 0xE3581567, 0xBAFEE339, 0xE284DAD2, 0xE1C27622, 0xEA017231, 0xEB0037EE ],
	"1.23"          :  [ 0xEBAA0113, 0xE4064EC7, 0xEF013596, 0xE5212F83, 0xE7EE335B, 0xE83B197C ],
	"1.23z"         :  [ 0xEBAA0114, 0x40064EB7, 0x5F013696, 0xE5211F83, 0xE7EF335B, 0xE84B197C ],
	"1.25"          :  [ 0xEBB6DF66, 0xE42F6211, 0xEF56B5AA, 0xE5B903FD, 0xE7D29154, 0xE859697C ],
	"1.26"          :  [ 0xEB8FBC31, 0xE4EC10CF, 0xEF73E592, 0xE59A0B7E, 0xE78CB309, 0xE87F3ED1 ],
	"1.27"          :  [ 0xE8DFFE17, 0xE43DF0DE, 0x2AE8335C, 0x0AC09826, 0xE7A838DC, 0xE891A6FC ],
	"1.28"          :  [ 0xE2ED720B, 0xEF69D1B1, 0x2EC32A41, 0x1AA3E665, 0xE9E1C153, 0xE49E8D9C ],
	"2.00"          :  [ 0x0819FF33, 0xE4A1EF1C, 0x5A85A2B3, 0xEA0D2A0F, 0xE0D6BD78, 0xE29D9377 ],
	"2.00 Instant"  :  [ 0x0849EA8B, 0xE33B6243, 0x53B2D501, 0xE6847168, 0xEBD886D7, 0xEE3C09C0 ],
	"2.01"          :  [ 0x08D5310E, 0xE41BDB46, 0x5A3D9627, 0xEAF8FC79, 0xE016C9E7, 0xE2EB8130 ],
	"2.01 Instant"  :  [ 0x08637DD1, 0xE3618CB3, 0x5356F520, 0xE6B110CA, 0xEB4C1E5C, 0xEED91028 ],
	"2.03"          :  [ 0x08B76046, 0xE4177F2F, 0x5AB21C99, 0xEA2AF4B1, 0xE0FE885A, 0xE202FC9E ],
	"2.03 Instant"  :  [ 0x08B76046, 0xE4177F2F, 0x5AB21C99, 0xEA2AF4B1, 0xE0FE885A, 0xE2029EFC ],
	"2.05"          :  [ 0x08A27510, 0xE47AB3C3, 0x5A289302, 0xEAA6CAC8, 0xE00D75D5, 0xE2D2FE01 ],
	"2.05 Instant"  :  [ 0x08A27510, 0xE47AB3C3, 0x5A289302, 0xEAA6CAC8, 0xE00D75D5, 0xE2D2FE00 ]
}


# Extra signatures for deadstripping detection for versions prior to 1.23
# These are encrypted regions of the six exported functions that may be deadstripped
dsprot_deadstrip_signatures = {
	"1.05" : [
		[ 0xE3585B63, 0x1359500F, 0x0A01C324, 0xE12EA0DA, 0xEA01ACAB, 0xEB005514 ],
		[ 0xE358AD36, 0x1359ABB6, 0x0A01E6D4, 0xE12EFACC, 0xEA014452, 0xEB003304 ],
		[ 0xE35885D0, 0x13594184, 0x0A01951B, 0xE12E4DE0, 0xEA0181F1, 0xEB00350E ],
		[ 0xE358F4DA, 0x1359EDA6, 0x0A018384, 0xE12E7EAF, 0xEA01BAFB, 0xEB002E8E ],
		[ 0xE35826EA, 0x135BB4F5, 0x0A01DF82, 0xE12E37F3, 0xEA0177AB, 0xEB0009A1 ],
		[ 0xE35809D2, 0x135B187D, 0x0A01F04F, 0xE12E6E17, 0xEA01F5F8, 0xEB000E5E ]
	],
	
	"1.06" : [
		[ 0xE35B1927, 0x13581BD1, 0x0A01FF55, 0xE12E284D, 0xEA01D0D2, 0xEB0048F8 ],
		[ 0xE35B66BB, 0x1358C054, 0x0A01D318, 0xE12ED9C9, 0xEA019EF2, 0xEB0059B5 ],
		[ 0xE35B773A, 0x13585DE5, 0x0A01153F, 0xE12E9837, 0xEA013E94, 0xEB003481 ],
		[ 0xE35B4BB1, 0x13581782, 0x0A012AFD, 0xE12EFEAE, 0xEA01FEF6, 0xEB0065C5 ],
		[ 0xE35854E5, 0x135BBE29, 0x0A01BDFC, 0xE12EB155, 0xEA015905, 0xEB0012F0 ],
		[ 0xE3582047, 0x135B3BCA, 0x0A0146C4, 0xE12E90C2, 0xEA018744, 0xEB0076BB ]
	],
	
	"1.08" : [
		[ 0x135AEB36, 0x0A010EEB, 0xE1A1498E, 0xE12E119F, 0xEA01D073, 0xEB004EF9 ],
		[ 0x135A5340, 0x0A010F1E, 0xE1A14DF4, 0xE12EA8B8, 0xEA012DFD, 0xEB00292E ],
		[ 0x135A6243, 0x0A019F5D, 0xE1A169FA, 0xE12E44F7, 0xEA0188B7, 0xEB001186 ],
		[ 0x135A8847, 0x0A01EC66, 0xE1A11A12, 0xE12E96CB, 0xEA01BA9F, 0xEB001CC4 ],
		[ 0x135210C7, 0x0A015FD2, 0xE59CA175, 0xE12E0BB3, 0xEA016000, 0xEB0072A8 ],
		[ 0x13528232, 0x0A019A0D, 0xE59CF1EC, 0xE12E2693, 0xEA018397, 0xEB007CD4 ]
	],
	
	"1.10" : [
		[ 0xE35BCB52, 0x1358724E, 0x0A012693, 0xE12E5134, 0xEA01F7B7, 0xEB006981 ],
		[ 0xE35B3772, 0x1358E0BF, 0x0A01D00F, 0xE12EA6A2, 0xEA01E9B0, 0xEB0061AE ],
		[ 0xE35BAAA4, 0x13587067, 0x0A014769, 0xE12EB317, 0xEA0183FF, 0xEB002578 ],
		[ 0xE35B0958, 0x135895A0, 0x0A015ADE, 0xE12E4A16, 0xEA015954, 0xEB00275E ],
		[ 0xE35BBB70, 0x13584B7B, 0x0A01B2C0, 0xE12E6E43, 0xEA015657, 0xEB000351 ],
		[ 0xE35B64E9, 0x1358A8AB, 0x0A011212, 0xE12EBA06, 0xEA01E653, 0xEB002E37 ]
	],
	
	"1.20" : [
		[ 0xE35BD43E, 0x13583820, 0x0A016F3F, 0xE12EE88F, 0xEA0181D9, 0xEB0053EF ],
		[ 0xE35BF41E, 0x135869AF, 0x0A017078, 0xE12EE6BF, 0xEA01246D, 0xEB001D7A ],
		[ 0xE35BD684, 0x13583D21, 0x0A018D6B, 0xE12E2E02, 0xEA0196BE, 0xEB0058A8 ],
		[ 0xE35BDF63, 0x135817C6, 0x0A012D90, 0xE12E1D1E, 0xEA017112, 0xEB00129E ],
		[ 0xE35BB7A9, 0x13586DFA, 0x0A014395, 0xE12E5CB1, 0xEA01F535, 0xEB00496B ],
		[ 0xE35B3EF8, 0x1358E1D7, 0x0A01AEBF, 0xE12EB9C1, 0xEA017102, 0xEB004165 ]
	],
	
	"1.22" : [
		[ 0xE35BCC84, 0x1358DA50, 0x0A01898F, 0xE12EF5B4, 0xEA01442A, 0xEB005C87 ],
		[ 0xE35BC43E, 0x135876D9, 0x0A01EFDF, 0xE12E1AE2, 0xEA011B08, 0xEB002393 ],
		[ 0xE35B4A95, 0x1358DF1F, 0x0A0101C5, 0xE12ECE2F, 0xEA013D85, 0xEB0066D9 ],
		[ 0xE35BCDD2, 0x13589696, 0x0A01F2AA, 0xE12EF7AF, 0xEA0179AC, 0xEB000639 ],
		[ 0xE35BDD3E, 0x135877C5, 0x0A014724, 0xE12E790A, 0xEA01BFE0, 0xEB001530 ],
		[ 0xE35BD809, 0x13581476, 0x0A016812, 0xE12E6D7C, 0xEA01F81B, 0xEB0066F1 ]
	]
}


# Non-unique and non-identifying signatures used to find the start of DS Protect once its existence and version has already been assumed
# These signatures are taken from random unique-ish instructions near the top of DS Protect
# This also has to be careful about ignoring linker-generated veneers
dsprot_starts = {
	"1.05" : {
		"signature" : [ 0xE1A05FA0, 0xE080E00E, 0xE085E1CE, 0xE0CCEE94, 0xE065CF00, 0xE0855F6C ],
		"start_word" : 0xE92D4008
	},
	
	"1.06" : {
		"signature" : [ 0xE1A05FA0, 0xE080E00E, 0xE085E1CE, 0xE0CCEE94, 0xE065CF00, 0xE0855F6C ],
		"start_word" : 0xE92D4008
	},
	
	"1.08" : {
		"signature" : [ 0xE1A05FA0, 0xE080E00E, 0xE085E1CE, 0xE0CCEE94, 0xE065CF00, 0xE0855F6C ],
		"start_word" : 0xE92D4008
	},
	
	"1.10" : {
		"signature" : [ 0xE1A05FA0, 0xE080C00C, 0xE085C1CC, 0xE0C3CC9E, 0xE0653F00, 0xE0853F63 ],
		"start_word" : 0xE92D4070
	},
	
	"1.20" : {
		"signature" : [ 0xE1A05FA0, 0xE080C00C, 0xE085C1CC, 0xE0C3CC9E, 0xE0653F00, 0xE0853F63 ],
		"start_word" : 0xE92D4070
	},
	
	"1.22" : {
		"signature" : [ 0xE1A05FA0, 0xE080C00C, 0xE085C1CC, 0xE0C3CC9E, 0xE0653F00, 0xE0853F63 ],
		"start_word" : 0xE92D4070
	},
	
	# Non-deadstripped below here
	# These can *almost* be used as identifying signatures but there are some issues with doing that
	
	"1.23" : {
		"signature" : [ 0xE92CC71E, 0xE24CD291, 0xE59EB8F2, 0xE59E4395, 0xE3A12084, 0xE293B9DA ],
		"start_word" : 0xE92CC71E
	},
	
	"1.23z" : {
		"signature" : [ 0xE92C9485, 0xE24C0AF7, 0xE59EF9D4, 0xE59ED498, 0xE3A1F8C6, 0xE2933CF6 ],
		"start_word" : 0xE92C9485
	},
	
	"1.25" : {
		"signature" : [ 0xE912EB8A, 0xE272975B, 0xE5A07B6B, 0xE5A0C7D9, 0xE39F086B, 0xE2BC7031 ],
		"start_word" : 0xE912EB8A
	},
	
	"1.26" : {
		"signature" : [ 0xE9D246DD, 0xE2B22913, 0xE5600233, 0xE56093E6, 0xE35F7233, 0xE27CA462 ],
		"start_word" : 0xE9D246DD
	},
	
	"1.27" : {
		"signature" : [ 0xE9D25446, 0xE2B2ED4F, 0xE5600448, 0xE560CF55, 0xE35FEE09, 0xE27C8889 ],
		"start_word" : 0xE9D25446
	},
	
	"1.28" : {
		"signature" : [ 0xE9D25969, 0xE2B299BD, 0xE560C0BB, 0xE560D394, 0xE35F3D6F, 0xE27CBC9D ],
		"start_word" : 0xE9D25969
	},
	
	"2.00" : {
		"signature" : [ 0xE90DCC27, 0xE262FEA0, 0xE5ED5163, 0xE5A96627, 0xE2008C97, 0xE5836F62 ],
		"start_word" : 0xE90DCC27
	},
	
	"2.00 Instant" : {
		"signature" : [ 0xE1591016, 0xE1F608A7, 0x1067D0B9, 0xE2838DA7, 0xE5B1A0AA, 0xE10C4E5B ],
		"start_word" : 0xE1591016
	},
	
	"2.01" : {
		"signature" : [ 0xE544AA7C, 0xE2101ACD, 0xE285D21C, 0xE5BE7C13, 0xE31ED5CD, 0x15828B6F ],
		"start_word" : 0xE544AA7C
	},
	
	"2.01 Instant" : {
		"signature" : [ 0xE163F679, 0xE144FE2F, 0x1039FBE9, 0xE2676FBD, 0xE50DB097, 0xE1039C36 ],
		"start_word" : 0xE163F679
	},
	
	"2.03" : {
		"signature" : [ 0xE55782E3, 0x07AB2322, 0xE5C6F662, 0x0071B9B9, 0xE3BFEB43, 0xF6710525 ],
		"start_word" : 0xE55782E3
	},
	
	"2.03 Instant" : {
		"signature" : [ 0xE17B5FC7, 0x00339B8C, 0x10BE397E, 0xF297C17D, 0x17D33891, 0xF666ED0D ],
		"start_word" : 0xE17B5FC7
	},
	
	"2.05" : {
		"signature" : [ 0xE59BAE7A, 0xC7DB398C, 0xA98402BE, 0x8EDD81A5, 0x71645D9F, 0x868429A1 ],
		"start_word" : 0xE59BAE7A
	},
	
	"2.05 Instant" : {
		"signature" : [ 0xE125034C, 0xC2665F4D, 0xD2E983FF, 0xB4174C1B, 0x9945A10D, 0x7ADC0FC6 ],
		"start_word" : 0xE125034C
	}
}


def bytes_to_u32s(bytes_obj):
	return [ x[0] for x in struct.iter_unpack("<L", bytes_obj) ]


def idx_of_signature(text, signature):
	# Simple dumb algorithm: check for all indices of the start, then investigate if those are full matches later
	# Since these are random 32-bit numbers, the false positive rate on the start of the pattern should be basically zero
	def potential_indices(text, signature):
		idx = -1
		value = signature[0]
		end = len(text) - len(signature)
		while idx < end:
			try:
				idx = text.index(value, idx + 1, end)
				yield idx
			except ValueError:
				break
		
		return
	
	for idx in potential_indices(text, signature):
		if text[idx : idx + len(signature)] == signature:
			return idx
	
	return False


def dsprotect_deadstrip_pattern(code_words, dsprot_ver):
	if dsprot_ver not in dsprot_deadstrip_signatures:
		return False
	
	deadstripped_functions = list()
	
	for i in range(len(dsprot_deadstrip_signatures[dsprot_ver])):
		signature = dsprot_deadstrip_signatures[dsprot_ver][i]
		idx = idx_of_signature(code_words, signature)
		if idx is False:
			deadstripped_functions.append(i + 1)
	
	if len(deadstripped_functions) == 0:
		return False
	
	return deadstripped_functions


def dsprotect_ram_offset(code_words, dsprot_ver):
	start_signature = dsprot_starts[dsprot_ver]["signature"]
	start_word = dsprot_starts[dsprot_ver]["start_word"]
	
	start_signature_idx = idx_of_signature(code_words, start_signature)
	
	if start_signature_idx is False:
		return False
	
	while code_words[start_signature_idx] != start_word:
		if start_signature_idx == 0:
			return False
		
		start_signature_idx -= 1
	
	return start_signature_idx * 4


def has_dsprotect(raw_code, region_ram_start, region_print_name):
	# Do a single pass converting the entire blob to u32s, then match in 32-bit compares
	code_words = bytes_to_u32s(raw_code)
	
	detected = False
	for dsprot_ver in dsprot_identifying_signatures:
		identifier_idx = idx_of_signature(code_words, dsprot_identifying_signatures[dsprot_ver])
		if identifier_idx is not False:
			ram_offset = dsprotect_ram_offset(code_words, dsprot_ver)
			if ram_offset is not False:
				location = region_ram_start + ram_offset
				deadstrip_pattern = dsprotect_deadstrip_pattern(code_words, dsprot_ver)
				
				print("")
				print(f"DS Protect found @ {region_print_name}")
				print(f"Version: {dsprot_ver}")
				print(f"Address: {location:08X}")
				
				if deadstrip_pattern is not False:
					deadstrip_str = ", ".join(map(str, deadstrip_pattern))
					print(f"Deadstripped: {deadstrip_str}")
				
				detected = True
	
	return detected


def decompress(data, min_subsequence=3):
	# This is REALLY SLOW and probably can't be improved with pure Python
	header = data[-8:]
	
	deltas, offset = struct.unpack("<LL", header)
	
	padding = deltas >> 24
	size = deltas & 0x00FFFFFF
	
	total_size = len(data) + offset
	
	write_idx = total_size - 1
	read_idx = len(data) - padding - 1
	read_end_idx = len(data) - size - 1
	
	# Extend buffer to size
	data.extend(bytearray(total_size - len(data)))
	
	# Begin decompression
	while read_idx > read_end_idx:
		flags = data[read_idx]
		read_idx -= 1
		
		for f in range(8):
			if (flags & 0x80) == 0:
				# Copy byte
				data[write_idx] = data[read_idx]
				write_idx -= 1
				read_idx -= 1
			else:
				info = (data[read_idx] << 8) | data[read_idx - 1]
				read_idx -= 2
				
				# Extract count and displacement of copy
				count = (info >> 12) + min_subsequence
				disp = (info & 0x0FFF) + min_subsequence
				
				# Execute copy
				for i in range(count):
					data[write_idx] = data[write_idx + disp]
					write_idx -= 1
			
			flags <<= 1
			
			if read_idx <= read_end_idx:
				break


def check_arm9_overlays(romfile):
	CARDRomRegion = struct.Struct("<LL")
	FATEntry      = struct.Struct("<LL")
	OverlayInfo   = struct.Struct("<LLLLLLLL")
	
	# Get FAT location/size
	romfile.seek(0x48)
	fat_offset, fat_size = CARDRomRegion.unpack(romfile.read(CARDRomRegion.size))
	
	# Read FAT entries
	romfile.seek(fat_offset)
	fat_entries = list(FATEntry.iter_unpack(romfile.read(fat_size)))
	
	# Get ARM9 overlay table location/size
	romfile.seek(0x50)
	arm9_ovy_tbl_offset, arm9_ovy_tbl_size = CARDRomRegion.unpack(romfile.read(CARDRomRegion.size))
	
	# Get ARM9 overlay entries
	romfile.seek(arm9_ovy_tbl_offset)
	arm9_ovy_tbl_raw = romfile.read(arm9_ovy_tbl_size)
	
	# Check each overlay
	detected = False
	for ovy_id, ram_start, size, bss_size, sinit_start, sinit_end, file_id, flag in OverlayInfo.iter_unpack(arm9_ovy_tbl_raw):
		start, end = fat_entries[file_id]
		
		romfile.seek(start)
		ovy_bytes = bytearray(romfile.read(end - start))
		
		try:
			# Check if the overlay is compressed
			if flag & 0x01000000:
				decompress(ovy_bytes)
				
			# Optimization: DS Protect will be detectable before the sinit region, so we can truncate everything after that
			sinit_offset = sinit_start - ram_start
			ovy_bytes = ovy_bytes[:sinit_offset]
			
			detected |= has_dsprotect(ovy_bytes, ram_start, f"overlay {ovy_id}")
		
		except:
			print(f"WARNING: Failed to analyze overlay {ovy_id}")
			continue
	
	return detected


def check_arm9_static(romfile):
	ARM9Info = struct.Struct("<LLLL")
	ModuleParamMagic = 0x2106C0DE
	
	# Get ARM9 location/size
	romfile.seek(0x20)
	arm9_offset, arm9_entry, arm9_ram_start, arm9_size = ARM9Info.unpack(romfile.read(ARM9Info.size))
	
	# Get ARM9 static region
	romfile.seek(arm9_offset)
	arm9_bytes = bytearray(romfile.read(arm9_size))
	
	# Check if the static region is compressed
	# Must search for the module parameters in crt0
	search_start = arm9_entry - arm9_ram_start
	search_end = search_start + 0x1000 # Arbitrary, should be fine
	search_data = bytes_to_u32s(arm9_bytes[search_start:search_end])
	
	try:
		idx = search_data.index(ModuleParamMagic, 3)
		if search_data[idx - 3] != 0:
			decompress(arm9_bytes)
		
		return has_dsprotect(arm9_bytes, arm9_ram_start, "static region")
	
	except:
		print("WARNING: Failed to analyze ARM9 static region")
		return False


def print_gsdd_warning():
	print("")
	print("WARNING: Golden Sun - Dark Dawn")
	print("")
	print("This game has DS Protect 2.01 in overlay 334, and 2.01 Instant in overlay 335.")
	print("")
	print("This is a hardcoded printout. This game cannot be analyzed normally.")
	print("It uses a proprietary method of code compression that is currently unsupported.")


def is_gsdd(game_code):
	return game_code.startswith("BO5")


def rom_game_info(romfile):
	romfile.seek(0x0)
	game_title = romfile.read(12).decode("ascii").rstrip("\x00")
	game_code = romfile.read(4).decode("ascii")
	
	return game_title, game_code.rstrip()


def quick_rom_is_valid(romfile):
	romfile.seek(0, 2)
	size = romfile.tell()
	
	if size < 8388608 or size > 536870912:
		return False
	
	# Don't actually enforce this size=2^n thing in case of ROM trimming
	#if (size & (size - 1)) != 0:
	#	return False
	
	romfile.seek(0x14E)
	logo_and_checksum = romfile.read(16)
	
	if logo_and_checksum != b"\x3C\xAF\xD6\x25\xE4\x8B\x38\x0A\xAC\x72\x21\xD4\xF8\x07\x56\xCF":
		return False
	
	return True


def check_rom(romfile):
	if not quick_rom_is_valid(romfile):
		print(f"ERROR: Invalid ROM file: {romfile.name}")
		return
	
	game_title, game_code = rom_game_info(romfile)
	
	print("")
	print(f"Game: [{game_code}] {game_title}")
	
	if is_gsdd(game_code):
		print_gsdd_warning()
		return
	
	detected = check_arm9_static(romfile)
	detected |= check_arm9_overlays(romfile)
	
	if not detected:
		print("")
		print("DS Protect not detected")


def dsdetect_main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("rom", type=argparse.FileType("rb"))
	
	args = parser.parse_args()
	check_rom(args.rom)


if __name__ == "__main__":
	dsdetect_main()
