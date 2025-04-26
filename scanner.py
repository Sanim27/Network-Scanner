#!/home/sanim27/Desktop/net_scanner/myenv/bin/python3
import nmap
import argparse
import xml.etree.ElementTree as ET
import smtplib
from email.mime.text import MIMEText
import yaml
import schedule
import time
import logging

#load configuration
with open('config.yaml','r') as f:
	config=yaml.safe_load(f)

#setup logging
logging.basicConfig(filename='scanner.log', level=logging.INFO)


class NetworkScanner:
	def __init__(self):
		self.nm=nmap.PortScanner()
	
	def run_scan(self,target,scan_type='default'):
		try:
			arguments=self._get_scan_arguments(scan_type)
			self.nm.scan(target,arguments=arguments)
			return self.nm.analyse_nmap_xml_scan()
		except Exception as e:
			logging.error(f"Scan Failed:{e}")
			return None
	
	def _get_scan_arguments(self,scan_type):
		scan_profiles = {
			'quick' : '-T4 -F',
			'full' : '-p- -sV',
			'stealth' : '-sS -D ' + ','.join(config['decoys']),
			'os-detect' : '-O',
			'version-detect' : '-sV',
			'aggressive' : '-T4 -A',
			'udp-scan' : '-sU',
			'top-ports-2000' : '--top-ports 2000',
			'slow-scan' : '-T1',
			'ipv6-scan' : '-6',
			}
			
		return scan_profiles.get(scan_type, '-T4')
		
	def parse_results(self, scan_data):
    		open_ports = []
    		for ip, host in scan_data.get('scan', {}).items():
        		for proto in host.get('tcp', {}):
            		port = host['tcp'][proto]
            		if port['state'] == 'open':
                		open_ports.append({
                    		'ip': ip,  # Add IP to the result
                    		'port': proto,
                    		'service': port['name'],
                    		'version': port.get('version', 'unknown')
                		})
    		return open_ports
	
	def send_alert(self,message):
		try:
			msg=MIMEText(message)
			msg['Subject'] = 'Network Scanner Alert'
			msg['From'] = config['email']['sender']
			msg['To'] = config['email']['receiver']
			
			with smtplib.SMTP(config['email']['smtp_server'], config['email']['smtp_port']) as server:
				server.starttls()
				server.login(config['email']['user'] , config['email']['password'])
				server.send_message(msg)
			logging.info("Alert sent successfully")
		except Exception as e:
			logging.error(f"Failed to send alert {e}")


def run_scheduled_scan(scanner,target,scan_type):
	logging.info(f"Running scheduled scan on {target}")
	results=scanner.run_scan(target,scan_type)
	if results:
		open_ports=scanner.parse_results(results)
		if open_ports:
			scanner.send_alert(f"Scheduled scan found open ports: {open_ports}")

def main():
	parser=argparse.ArgumentParser(description='Automated Network Scanner')
	parser.add_argument('-t','--target',required=True,help='Target (eg, 192.168.1.0/24)')
	parser.add_argument('-s','--scan-type',choices=['quick','full','stealth','os-detect','version-detect','aggressive','udp-scan','top-ports-2000','slow-scan','ipv6-scan'],default='quick',help='Type of Scan')
	parser.add_argument('--schedule', type=int, help='Run scan every X minutes')
	
	args=parser.parse_args()
	scanner=NetworkScanner()
	
	if args.schedule:
		schedule.every(args.schedule).minutes.do(run_scheduled_scan, scanner, args.target, args.scan_type)
		while True:
			schedule.run_pending()
			time.sleep(1)
	else:
		results=scanner.run_scan(args.target,args.scan_type)
		if results:
			open_ports=scanner.parse_results(results)
			if open_ports:
				scanner.send_alert(f"Open ports detected: {open_ports}") 
			

if __name__=="__main__":
	main()

			
			

	
