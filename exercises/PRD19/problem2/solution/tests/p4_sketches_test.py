#!/usr/bin/env python3

import sys
import os
import subprocess
import re
import crcmod
import socket
import os.path

filename_bm_ip 		= "bm_test.txt"
filename_bm_final   = "bm_results.txt"

filename_cm_ip 		= "cm_test.txt"
filename_cm_final 	= "cm_results.txt"

arg_sketch 		= str(sys.argv[1])
arg_json 		= str(sys.argv[2])

def sketch_bm():

	with open(filename_bm_ip) as f:

		 for line in f:

		 	crc32_bm_1	= crcmod.Crc(0x104c11db7, initCrc=0x00000000, xorOut=0xFFFFFFFF)

			try:
				crc32_bm_1.update(socket.inet_aton(line))
			except socket.error:
				continue		 	

		 	crc32_bm_1_hex = crc32_bm_1.hexdigest()
		 	crc32_bm_1_dec = int(crc32_bm_1_hex, 16)
		 	crc32_bm_1_mod = crc32_bm_1_dec % 131072	

		 	sketch_bm_src 	= str(subprocess.check_output(["echo \"register_read bm_register_final " + str(crc32_bm_1_mod) + " \" | /usr/local/bin/simple_switch_CLI --json " + arg_json], shell=True))

		 	final_bm_src 	= re.search(" \\d+",sketch_bm_src).group(0)[1:]	

		 	if os.path.exists(filename_bm_final):
		 		append_write = 'a' # append if already exists
		 	else:
		 		append_write = 'w' # make a new file if not

		 	file_write = open(filename_bm_final,append_write)
		 	file_write.write(line.rstrip() + " " + final_bm_src + "\n")

		 	file_write.close()

def sketch_cm():

	with open(filename_cm_ip) as f:

		for line in f:

			regex_src_ip,regex_dst_ip = re.search("\\d+\\.\\d+\\.\\d+\\.\\d+,\\d+\\.\\d+\\.\\d+\\.\\d+",line).group(0).split(",")

			crc32_cm_2	= crcmod.Crc(0x104c11db7, initCrc=0x00000000, xorOut=0xFFFFFFFF)

			try:
				crc32_cm_2.update(socket.inet_aton(regex_src_ip))
				crc32_cm_2.update(socket.inet_aton(regex_dst_ip))
			except socket.error:
				continue

			crc32_cm_2_hex = crc32_cm_2.hexdigest()
			crc32_cm_2_dec = int(crc32_cm_2_hex, 16)
			crc32_cm_2_mod = crc32_cm_2_dec % 131072	

			sketch_cm 	= str(subprocess.check_output(["echo \"register_read cm_register_final " + str(crc32_cm_2_mod) + " \" | /usr/local/bin/simple_switch_CLI --json " + arg_json], shell=True))

			final_cm  	= re.search(" \\d+",sketch_cm).group(0)[1:]		

			if os.path.exists(filename_cm_final):
				append_write = 'a' # append if already exists
			else:
				append_write = 'w' # make a new file if not

			file_write = open(filename_cm_final,append_write)
			file_write.write(line.rstrip() + " " + final_cm + "\n")

			file_write.close()

if (arg_sketch == "bm"):
	sketch_bm()
elif (arg_sketch == "cm"):
	sketch_cm()