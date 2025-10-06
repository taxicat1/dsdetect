"""
Analyze a Nintendo DS ROM file (.nds) for the presence of DS Protect.
"""

import struct
import argparse


dsprot_signatures = {
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


def has_signature(text, signature):
	# Simple dumb algorithm: check for all indices of the start, then investigate if those are full matches later
	# Since these are random 32-bit numbers, the false positive rate on the start of the pattern should be basically zero
	def potential_indices(text, signature):
		idx = 0
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
		matching = True
		for i in range(len(signature)):
			if text[idx + i] != signature[i]:
				matching = False
				break
			
		if matching:
			return True
	
	return False


def bytes_to_u32s(bytes_obj):
	return [ x[0] for x in struct.iter_unpack("<L", bytes_obj) ]


def has_dsprotect(raw_code, print_region_name):
	# Do a single pass converting the entire blob to u32s, then match in 32-bit compares
	code_words = bytes_to_u32s(raw_code)
	
	detected = False
	for dsprot_ver in dsprot_signatures:
		if has_signature(code_words, dsprot_signatures[dsprot_ver]):
			print("")
			print(f"DS Protect found @ {print_region_name}")
			print(f"Version: {dsprot_ver}")
			detected = True
	
	return detected


def decompress(data, min_subsequence=3):
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
			
			detected |= has_dsprotect(ovy_bytes, f"overlay {ovy_id}")
		
		except:
			print(f"Warning: failed to analyze overlay {ovy_id}")
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
	romfile.seek(arm9_offset + (arm9_entry - arm9_ram_start))
	search_data = bytes_to_u32s(romfile.read(0x1000))
	
	try:
		idx = search_data.index(ModuleParamMagic, 3)
		if search_data[idx - 3] != 0:
			decompress(arm9_bytes)
		
		return has_dsprotect(arm9_bytes, "static region")
	
	except:
		print("Warning: failed to analyze ARM9 static region")
		return False


def check_gsdd(romfile):
	romfile.seek(0xC)
	code = romfile.read(4).decode("ascii")
	return code.startswith("BO5")


def print_gsdd_warning():
	print("")
	print("WARNING: Golden Sun - Dark Dawn")
	print("")
	print("This game has DS Protect 2.01 in overlay 334, and 2.01 Instant in overlay 335.")
	print("")
	print("This is a hardcoded printout. This game cannot be analyzed normally.")
	print("It uses a proprietary method of code compression that is currently unsupported.")


def check_rom(romfile):
	if check_gsdd(romfile):
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
