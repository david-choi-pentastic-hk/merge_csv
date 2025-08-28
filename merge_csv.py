# Copyright (c) 2025 Pentastic Security Limited. All rights reserved.

# @file merge_csv.py
# @brief Merges a bunch of CSV files into a single CSV file.
# @author David Choi <david.choi@pentastic.hk>
# @version 2025.08.13 15:45
PROGRAM_NAME   = "merge_csv.py"
PROGRAM_BRIEF  = "Merges a bunch of CSV files into a single CSV file."
AUTHORS_STRING = "David Choi <david.choi@pentastic.hk>"
VERSION_STRING = "2025.08.13 15:45"

import platform # to obtain OS platform
import sys # to retrieve command line arguments
import os  # to handle file I/O operations
import csv # to read and write CSV files
import tempfile # to create temporary files
import shutil # to copy files
import xml.etree.ElementTree as ET # to read XML files

# how to use: python3 merge_csv.py [src_dir_path = "./"] [dest_csv_output_path = src_dir_path + "merge_csv_output.csv"]

IS_WINDOWS = (platform.system() == "Windows")

# @return true if option flag is detected, false otherwise.
def check_option_flags():
	if (len(sys.argv) >= 2):
		arg = sys.argv[1]
		if (arg.startswith("-")):
			if (arg == "-v" or arg == "--version"):
				print("Script:  " + PROGRAM_NAME)
				print("Brief:   " + PROGRAM_BRIEF)
				print("Author:  " + AUTHORS_STRING)
				print("Version: " + VERSION_STRING)
			else:
				print("")
				if not(arg == "-h" or arg == "--help"):
					print("Option flag " + arg + " not recognized.")
					print("")
				print("Command Line Interface - " + PROGRAM_NAME)
				print("")
				print("How to use:")
				print('>' if IS_WINDOWS else '$', 'python3 ' + sys.argv[0] + ' [src_dir_path = "."] [dest_csv_output_path = src_dir_path + "merge_csv_output.csv"]')
				if IS_WINDOWS:
					option_flags_usage = """
╔════════════════════╦═════════════╗
║ Option Flag(s)     ║ Usage       ║
╠════════════════════╬═════════════╣
║ -h or --help       ║ For Manual  ║
║ -v or --version    ║ For Version ║
╚════════════════════╩═════════════╝"""
				else:
					option_flags_usage = """
╭────────────────────┬─────────────╮
│ Option Flag(s)     │ Usage       │
├────────────────────┼─────────────┤
│ -h or --help       │ For Manual  │
│ -v or --version    │ For Version │
╰────────────────────┴─────────────╯"""
				print(option_flags_usage)
				print("")
				print("Param src_dir_path:");
				print("The path to the folder containing all the .csv files to be merged.")
				src_dir_path_example = "C:\\" if IS_WINDOWS else "/"
				src_dir_path_example += os.path.join("Users", "Dave CH", "Documents", "proj", "Pentast", "ness", "scan_results")
				print("e.g. \"" + src_dir_path_example + "\"");
				print("")
				print("Param dest_csv_output_path:")
				print("The path to the CSV output file.")
				dest_csv_output_path_example = "C:\\" if IS_WINDOWS else "/"
				dest_csv_output_path_example += os.path.join("Users", "Dave CH", "Documents", "proj", "Pentast", "ness", "output.csv")
				print("e.g. \"" + dest_csv_output_path_example + "\"");
				print("")
				
				print("""Note:
The .nessus file with the same filepath as the .csv file is used to determine
whether the authentication has passed or failed.

If the corresponding .nessus file is not found,
the value in this field would be set to \"Unknown\".

e.g. If the program can find \"A2 pentaDB.csv\" in the source folder,
it will also look fo rpentaDB.nessus in the same source folder.
""")
			return True
	return False

def merge_csv(src_dir_path, src_csv_file_names, dest_csv_file_path):
	ENCODING = "utf-8"
	
	# reads the IP address of host from the CSV table
	HOST_COLUMN_INDEX = 4 # counting from 0, 'Host' will be the 4th column

	# inserts 'Device' column to the left of 'Host' Column
	DEVICE_COLUMN_NAME = "Device"
	DEVICE_COLUMN_INDEX = 4 # counting from 0, 'Device' will be the 4th column
	# ['Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 'Risk', 'Device', 'Host', ...]
	
	# inserts 'Auth' column to the right of 'Host' Column
	AUTH_COLUMN_NAME = "Auth"
	AUTH_COLUMN_INDEX = 6 # counting from 0, 'Auth' will be the 6th column
	# ['Plugin ID', 'CVE', 'CVSS v2.0 Base Score', 'Risk', 'Device', 'Host', 'Auth', ...]
	
	src_csv_file_count = len(src_csv_file_names)
	# reminds the user to double check the source folder path
	if (src_csv_file_count == 0):
		print("Warning: No csv files found in the source folder.")
		print("Please double check the source folder path.")
		return
	
	print("Merging \"" + os.path.join(src_dir_path, "*.csv") + "\" files.")
	print("")
	
	# opens a temporary destination file
	# don't delete the file automatically, we will delete it after copying to destination is completed
	with tempfile.NamedTemporaryFile(mode='w+t', encoding=ENCODING, newline='', delete=False) as temp_file:
		# creates a CSV writer
		csv_writer = csv.writer(temp_file)
		
		dest_csv_header = ""
		
		# copies the data from the remaining CSV files
		src_csv_file_index = 0
		for src_csv_file_name in src_csv_file_names:
			src_csv_file_path = os.path.join(src_dir_path, src_csv_file_name)
			
			# informs the user of our progress
			print("Processing \"" + src_csv_file_path + "\"", end="")
			print(" (", src_csv_file_index, "/", src_csv_file_count, end="")
			print(" = ", int(src_csv_file_index / src_csv_file_count * 100), "% )", sep="")
			
			# obtains the CSV filename without the ".csv" extension
			src_csv_file_name_no_extension = src_csv_file_name[0 : len(src_csv_file_name) - len(".csv")]
			
			# parses the source XML file to retrieve auth pass/fail value
			host_creds_success_count = 0
			host_creds_failed_count = 0
			creds_scans_ok = {}
			
			src_xml_file_name = src_csv_file_name_no_extension + ".nessus"
			src_xml_file_path = os.path.join(src_dir_path, src_xml_file_name)
			if (os.path.exists(src_xml_file_path) and os.path.isfile(src_xml_file_path)):
				xml_tree = ET.parse(src_xml_file_path)
				xml_root = xml_tree.getroot()
				
				#policy = xml_root.find("Policy")
				#preferences = policy.find("Preferences")
				#server_preferences = preferences.find("ServerPreferences")
				
				#for pref in server_preferences.findall("preference"):
				#	name = pref.find("name").text
				#	if name == "hostCredsSuccessCount":
				#		host_creds_success_count = pref.find("value").text
				#	elif name == "hostCredsFailedCount":
				#		host_creds_failed_count = pref.find("value").text
				
				report = xml_root.find("Report")
				for report_host in report.findall("ReportHost"):
					ip = report_host.attrib["name"]
					host_properties = report_host.find("HostProperties")
					for tag in host_properties.findall("tag"):
						if (tag.attrib["name"] == "Credentialed_Scan"):
							creds_scans_ok[ip] = "Pass" if (tag.text == "true") else "Fail"
							print("IP:", ip, "Auth:", creds_scans_ok[ip])
							break
			
			# parses the source CSV file
			with open(src_csv_file_path, 'r', encoding=ENCODING) as src_csv_file:
				# creates a CSV reader
				csv_reader = csv.reader(src_csv_file)
				
				# reads the header
				header = next(csv_reader)
				
				# inserts the device column for the header
				header.insert(DEVICE_COLUMN_INDEX, DEVICE_COLUMN_NAME)
				
				# inserts the auth column for the header
				header.insert(AUTH_COLUMN_INDEX, AUTH_COLUMN_NAME)
				
				if (src_csv_file_index == 0):
					# copies this header to the destination CSV file
					dest_csv_header = header
					csv_writer.writerow(dest_csv_header)
				else:
					# checks if this header matches the destination CSV file header
					if (header != dest_csv_header):
						print("Warning: CSV header mismatch.")
				
				# uses the name of the source CSV file as the device name
				device_name = src_csv_file_name_no_extension
				for row in csv_reader:
					# gets the IP of this row
					host_ip = row[HOST_COLUMN_INDEX]
					
					# inserts the device name for this row
					row.insert(DEVICE_COLUMN_INDEX, device_name)
					
					# default value is unknown
					auth_passed_string = "Unknown"
					if (host_ip in creds_scans_ok):
						auth_passed_string = creds_scans_ok[host_ip]
					# inserts the auth value for this row
					# Pass/Fail is retrieved from the XML file
					row.insert(AUTH_COLUMN_INDEX, auth_passed_string)
					
					# copies this row to the destination CSV file
					csv_writer.writerow(row)
			
			src_csv_file_index += 1
		
	# copy the temp file to the destination CSV file
	shutil.copyfile(temp_file.name, dest_csv_file_path)
	
	# delete the temp file
	os.remove(temp_file.name)
	
	print("")
	print("Merged \"" + os.path.join(src_dir_path, "*.csv") + "\" files and")
	print("Saved at \"" + dest_csv_file_path + "\"")
	print("")

def main():
	# the working directory is the default source dir
	src_dir_path = "."
	
	if (check_option_flags()):
		return
	
	# checks if user passed designated source folder from command line
	if (len(sys.argv) >= 2):
		# user passed designated source folder from command line
		src_dir_path = sys.argv[1]
		# removes double-quotes at beginning and end of src_dir_path
		if (src_dir_path.startswith("\"")):
			src_dir_path = src_dir_path[1]
		if (src_dir_path.endswith("\"")):
			src_dir_path = src_dir_path[0 : len(src_dir_path) - 1]
		if (not os.path.isdir(src_dir_path)):
			print("Error: src_dir_path = \"" + src_dir_path + "\" is not a folder.")
			return
	
	# the default CSV output file path
	dest_csv_file_path = os.path.join(src_dir_path, "merge_csv_output.csv")
	
	# checks if user passed destination CSV file path from command line
	if (len(sys.argv) >= 3):
		# user passed destination CSV file path from command line
		dest_csv_file_path = sys.argv[2]
		# removes double-quotes at beginning and end of dest_csv_file_path
		if (dest_csv_file_path.startswith("\"")):
			dest_csv_file_path = dest_csv_file_path[1]
		if (dest_csv_file_path.endswith("\"")):
			dest_csv_file_path = dest_csv_file_path[0 : len(dest_csv_file_path) - 1]
		if (not dest_csv_file_path.lower().endswith(".csv")):
			print("Error: dest_csv_file_path = \"" + dest_csv_file_path + "\" does not end with \".csv\".")
			return
		dest_csv_dir_path = os.path.dirname(dest_csv_file_path)
		if (dest_csv_dir_path != ""):
			if (not os.path.exists(dest_csv_dir_path)):
				print("Error: dest_csv_file_path is under \"" + dest_csv_dir_path + "\", which does not exist.")
				return
			if (not os.path.isdir(dest_csv_dir_path)):
				print("Error: dest_csv_file_path is under \"" + dest_csv_dir_path + "\", which is not a directory.")
				return
	
	# gets all file entries (sorted) from the source folder
	src_dir_contents = sorted(os.listdir(src_dir_path))
	
	print("Looking for \"" + os.path.join(src_dir_path, "*.csv") + "\" files.")
	print("")
	
	dest_csv_file_exists = os.path.exists(dest_csv_file_path)
	
	src_csv_file_names = []
	# processes each entry in the source folder one by one
	for src_file_name in src_dir_contents:
		# gets full path to this source file
		src_file_path = os.path.join(src_dir_path, src_file_name)
		if (not os.path.isfile(src_file_path)):
			# this entry is not a file, so we skip it
			continue
		if (not src_file_name.lower().endswith(".csv")):
			# this file is not a CSV file, so we skip it
			continue
		# The entry must be a CSV file at this stage.
		# If the destination csv file already existed,
		# make sure not to include it in the merging list.
		if (not dest_csv_file_exists or not os.path.samefile(src_file_path, dest_csv_file_path)):
			src_csv_file_names.append(src_file_name)
	
	# merge all CSV files into one
	merge_csv(src_dir_path, src_csv_file_names, dest_csv_file_path)
	# possible enhancements todo : Don't merge all CSV files into one.
	# Instead, merge "A2 *.csv" into "A2.csv", "F6 *.csv" into "F6.csv"

if __name__ == "__main__":
	main()