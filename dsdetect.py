import struct
import array
import argparse

key_data_dict = {
	"1.06"  :  [ 0x0317, 0x1DFA, 0x4979, 0x1476, 0x4544, 0x4EF9, 0x292E, 0x1186, 0x1CC4, 0x72A8, 0x7CD4 ],
	"1.07"  :  [ 0x3530, 0x3089, 0x5FDF, 0x0D2C, 0x350E, 0x48F8, 0x59B5, 0x3481, 0x65C5, 0x12F0, 0x76BB ],
	"1.08"  :  [ 0x4276, 0x7A4A, 0x70C2, 0x476E, 0x1961, 0x5514, 0x3304, 0x350E, 0x2E8E, 0x09A1, 0x0E5E ],
	"1.10"  :  [ 0x66F2, 0x2F11, 0x1CFC, 0x4F55, 0x1729, 0x6981, 0x61AE, 0x2578, 0x275E, 0x0351, 0x2E37 ],
	"1.20"  :  [ 0x0F57, 0x0D8B, 0x0314, 0x7EF6, 0x2F0C, 0x480C, 0x03F9, 0x735A, 0x53EF, 0x1D7A, 0x58A8, 0x129E, 0x496B, 0x4165, 0x6506, 0x7566, 0x38AD, 0x1F1A ],
	"1.22"  :  [ 0x3B74, 0x67FA, 0x239B, 0x298C, 0x37EE, 0x0C13, 0x31F6, 0x38CA, 0x5C87, 0x2393, 0x66D9, 0x0639, 0x1530, 0x66F1, 0x63ED, 0x0BAE, 0x1800, 0x093F ]
}


garbage_data_dict = {
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


# Stolen from https://github.com/magical/nlzss
def decompress_ovy_lzss10(indata, decompressed_size):
	data = bytearray()
	it = iter(indata)
	disp_extra = 3
	
	def writebyte(b):
		data.append(b)
	
	def readbyte():
		return next(it)
	
	def readshort():
		a = next(it)
		b = next(it)
		return (a << 8) | b
	
	def copybyte():
		data.append(next(it))
	
	while len(data) < decompressed_size:
		flagarray = readbyte()
		for f in range(8):
			flag = flagarray & 0x80
			flagarray <<= 1
			
			if flag == 0:
				copybyte()
			else:
				sh = readshort()
				count = (sh >> 0xc) + 3
				disp = (sh & 0xfff) + disp_extra
				
				for _ in range(count):
					writebyte(data[-disp])
			
			if decompressed_size <= len(data):
				break
	
	if len(data) != decompressed_size:
		raise Exception("decompressed size does not match the expected size")
	
	return data


def decompress_overlay(raw_ovy):
	header = raw_ovy[-8:]
	
	end_delta, start_delta = struct.unpack("<LL", header)
	
	padding = end_delta >> 0x18
	end_delta &= 0xFFFFFF
	decompressed_size = start_delta + end_delta
	
	data = bytearray()
	data.extend(raw_ovy[-end_delta:-padding])
	data.reverse()
	
	uncompressed_data = decompress_ovy_lzss10(data, decompressed_size)
	uncompressed_data.reverse()
	
	prepend = bytearray()
	prepend.extend(raw_ovy[0:-end_delta])
	
	return prepend + uncompressed_data


# Code stolen from https://github.com/pret/ds_disassembly_tools -> dump_fs
# This is not efficient, the overlays could be decompressed on-the-fly while checking them
# But this only takes like a second anyway, even on 512 MB ROMs
def check_overlays(table, allocs, rom):
	def is_pointer(addr):
		return (addr & 0xFF000000) == 0x02000000
	
	def is_func_return_word(word):
		return (word == 0xE12FFF1E) or (word & 0xFFFF0000 == 0xE8BD0000)
	
	ret = 0
	for ovy_id, ram_start, size, bss_size, sinit_start, sinit_end, file_id, flag in table:
		start, end = allocs[file_id]
		rom.seek(start)
		ovy_bytes = rom.read(end - start)
		
		if flag & 0x01000000:
			# Compressed
			try:
				ovy_bytes = decompress_overlay(ovy_bytes)
			except:
				print(f'Malformed overlay @ {ovy_id} -- skipping')
				continue
		
		if (len(ovy_bytes) % 4) != 0:
			print(f'Malformed overlay @ {ovy_id} -- skipping')
			continue
		
		# Interpret overlay bytes as array of 32-bit little endian unsigned integers
		ovy_data = [x[0] for x in struct.iter_unpack("<L", ovy_bytes)]
		
		sinit_offset = (sinit_start - ram_start) // 4
		
		
		# MAC address check: determines if this overlay is DS Protect
		mac_addr_found = False
		mac_addr_offset = sinit_offset - 1
		for i in range(min(len(ovy_data), 100)): # Arbitrary
			if mac_addr_offset <= 0:
				break
			
			# MAC address data words
			if ovy_data[mac_addr_offset] == 0x0000CEFF and ovy_data[mac_addr_offset - 1] == 0xFF40F6FF:
				mac_addr_found = True
				break
			
			mac_addr_offset -= 1
		
		if not mac_addr_found:
			continue
		
		
		# If we passed the above check, this must be some variant of DS Protect
		ret = 1
		print('')
		print(f'DS Protect found @ ovy {ovy_id}')
		version_match = False
		
		
		# Determine garbage words
		garbage_data = None
		garbage_data_offset = mac_addr_offset - 2
		while True:
			# End of data, give up
			if garbage_data_offset <= 1:
				break
			
			# Found what looks like a function return, give up
			if is_func_return_word(ovy_data[garbage_data_offset]):
				break
			
			# Found what looks like the end of a table, give up
			if ovy_data[garbage_data_offset] == 0 and ovy_data[garbage_data_offset-1] == 0:
				break
			
			# Found pointers, skip them in case they're actual rodata (2.00+ does this)
			if is_pointer(ovy_data[garbage_data_offset]):
				garbage_data_offset -= 1
				continue
			
			# Treat 6 previous words as tag
			garbage_data_offset -= 5
			garbage_data_words = ovy_data[garbage_data_offset:garbage_data_offset+6]
			
			# Reject if any of the words are apparently something else
			if any(is_func_return_word(word) or is_pointer(word) for word in garbage_data_words):
				break
			
			# Accept this
			garbage_data = garbage_data_words
			break
		
		# If we found garbage data, try to identify it
		if garbage_data:
			#garbage_str = " ".join(f'{n:08x}' for n in garbage_data)
			#print(f'Garbage words: {garbage_str}')
			
			for v in garbage_data_dict:
				if garbage_data == garbage_data_dict[v]:
					print(f'Version: {v}')
					version_match = True
					break
		
		# If no garbage data was found, proceed to searching for encryption keys
		else:
			keys = []
			i = 0
			while i < mac_addr_offset:
				# Checking for encryption start macros
				if ovy_data[i] == 0xEA000000 and (ovy_data[i+1] & 0xFFFF0000) == 0xEB000000:
					keys.append(ovy_data[i+1] & 0x0000FFFF)
				
				i += 1
			
			if len(keys) > 0:
				#key_str = " ".join(f'{k:04x}' for k in keys)
				#print(f'Encryption keys: {key_str}')
				
				for v in key_data_dict:
					# Checking if the found keys match, or are a subset of, the known matches
					# Must do this because of possible deadstripping
					if set(key_data_dict[v]) >= set(keys):
						print(f'Version: {v}')
						version_match = True
						break
		
		if not version_match:
			print("Version unknown!")
	
	
	return ret


def check_rom(romfile):
	class StructReader(struct.Struct):
		def read(self, file):
			return self.unpack(file.read(self.size))
	
	CARDRomRegion = StructReader('<LL')
	FATEntry	  = StructReader('<LL')
	OverlayInfo   = StructReader('<LLLLLLLL')
	
	def read_table(rom, ofs):
		rom.seek(ofs)
		off, size = CARDRomRegion.read(rom)
		rom.seek(off)
		return rom.read(size)
	
	def parse_fat(raw_table):
		return list(FATEntry.iter_unpack(raw_table))
	
	def parse_overlays(raw_table):
		return list(OverlayInfo.iter_unpack(raw_table))
	
	fat_raw  = read_table(romfile, 0x48)
	ovy9_raw = read_table(romfile, 0x50)
	
	allocs = parse_fat(fat_raw)
	ovy9 = parse_overlays(ovy9_raw)
	
	ret = 0
	ret += check_overlays(ovy9, allocs, romfile)
	if ret == 0:
		print('')
		print('DS Protect not detected')


def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('rom', type=argparse.FileType('rb'))
	
	args = parser.parse_args()
	check_rom(args.rom)


if __name__ == "__main__":
	main()

