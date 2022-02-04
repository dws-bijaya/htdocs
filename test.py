import errno, pprint
import ipaddress
import random
from typing import OrderedDict


def die(data):
	pprint.pprint(data)
	exit()


what = 'dns-query'
if what == "dns-query":
	import re
	sample = """
	Nameserver 69.16.222.254:
			dreamandcleantriad.com has SOA record ns.liquidweb.com. admin.liquidweb.com. 2021042208 86400 7200 3600000 14400
	Nameserver 69.16.223.254:
			dreamandcleantriad.com has SOA record ns.liquidweb.com. admin.liquidweb.com. 2021042208 86400 7200 3600000 14400
	"""

	class settings:
		HOST_BIN = "/usr/bin/host"

	class network_tools:

		spf_qualifier = {'+': 'Pass', '-': 'Fail', '~': 'SoftFail', '?': 'Neutral'}
		spf_desc = {
		    'v': 'Version of the SPF record',
		    'ip4': 'If the IPv4 address falls inside the specified range, the match is made.',
		    'ip6': 'If the IPv6 address falls inside the specified range, the match is made.',
		    'include': 'The provided domain is searched for the word \'allow.\'',
		    'ptr': 'Check if the specified domain has a DNS \'PTR\' record for the IP address.',
		    'exists': 'This method is used to generate an arbitrary host name for DNS \'A\' record queries.',
		    'redirect': 'The SPF record for Value will be the current domains SPF record',
		    'unknown': 'Unknown'
		}
		mail_providers = {
		    "spf": {
		        "_spf.protonmail.ch": [
		            "ProtonMail",
		            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQBAMAAADt3eJSAAAABGdBTUEAALGPC/xhBQAAAAFzUkdCAK7OHOkAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAACRQTFRFAAAABgcnBgcnBgcnBgcnBgcnBgcnBgcnBgcnBgcnBgcn////iNxquAAAAAp0Uk5TAEDPgBDvMN9wIE1fJQEAAAABYktHRAsf18TAAAAACXBIWXMAAABIAAAASABGyWs+AAAAOUlEQVQI12OQWrVq1SITBgYGEGPV0gQoY9UyGGO5A5SxqgHGUIAxFsAYKzEYCzAUN6AbGIZmKcgZALt/QmenSzMUAAAAJXRFWHRkYXRlOmNyZWF0ZQAyMDIwLTAyLTExVDE4OjQ3OjMxKzAwOjAw7BdsZgAAACV0RVh0ZGF0ZTptb2RpZnkAMjAyMC0wMi0xMVQxODo0NzozMSswMDowMJ1K1NoAAAAZdEVYdFNvZnR3YXJlAEFkb2JlIEltYWdlUmVhZHlxyWU8AAAAAElFTkSuQmCC"
		        ],
		        "_spf.google.com": [
		            "Google Workspace",
		            "data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjUwIiBoZWlnaHQ9IjMyIiBmaWxsPSJub25lIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxnIGNsaXAtcGF0aD0idXJsKCNjbGlwMCkiPjxwYXRoIGQ9Ik0xMzAuMyAyLjM4M2gyLjk0M2wtNS44NTYgMjEuOTVoLTIuODg0TDExOS43OCA5Ljg2N2gtLjExM2wtNC43MyAxNC40NjZoLTIuODg0bC02LjEwMy0yMS45NWgyLjk0M2w0LjYzNCAxNy4yODRoLjEyTDExOC40IDUuMzMzaDIuNjRsNC43NSAxNC4zMzRoLjEyM0wxMzAuMyAyLjM4M3pNMTMyLjk3NyAxNi44MjdjMC0yLjMxMS43MjUtNC4yMjMgMi4xNzYtNS43MzRhNy40MjggNy40MjggMCAwMTUuNTUtMi4yNyA3LjMzNiA3LjMzNiAwIDAxNS41MiAyLjI3YzEuNDc0IDEuNTE0IDIuMjEgMy40MjUgMi4yMSA1LjczNHMtLjczNiA0LjIyLTIuMjEgNS43MzZhNy4zMTIgNy4zMTIgMCAwMS01LjUyIDIuMjY3IDcuNDIgNy40MiAwIDAxLTUuNTUtMi4yNjdjLTEuNDQ5LTEuNTEzLTIuMTc0LTMuNDI1LTIuMTc2LTUuNzM2em0yLjgyIDBjMCAxLjYxNS40NzEgMi45MjQgMS40MTMgMy45MjZhNC44MTEgNC44MTEgMCAwMDcgMGMuOTQtMS4wMDIgMS40MS0yLjMxIDEuNDEtMy45MjZzLS40NzMtMi45MTQtMS40Mi0zLjg5NGE0Ljc1MiA0Ljc1MiAwIDAwLTcgMGMtLjkzNiAxLTEuNDAzIDIuMjk4LTEuNDAzIDMuODk0ek0xNTMuMjU3IDI0LjMzM2gtMi44MlY5LjMxM2gyLjY5NnYyLjQ1NGguMTI0Yy4zMzktLjg2Ljk2MS0xLjU4IDEuNzYzLTIuMDRhNC45MTUgNC45MTUgMCAwMTIuNjIzLS44NDQgNS4yNiA1LjI2IDAgMDEyLjA4NC4zN0wxNTguODcgMTJhNC42NjggNC42NjggMCAwMC0xLjY2Ny0uMjE3IDMuNjY0IDMuNjY0IDAgMDAtMi43NzYgMS4yOSA0LjI5NiA0LjI5NiAwIDAwLTEuMTggM2wuMDEgOC4yNnpNMTc0LjI1IDI0LjMzM2gtMy40MDNsLTQuNjk0LTcuMDc2LTIuMyAyLjI3djQuODA2aC0yLjgyVjIuMzgzaDIuODJ2MTMuNTI0bDYuNTA0LTYuNTk0aDMuNjE2di4xMjRsLTUuODU2IDUuODI2IDYuMTMzIDguOTU0di4xMTZ6IiBmaWxsPSIjNUY2MzY4Ii8+PHBhdGggZD0iTTE4Ni40NiAyMC4xN2MwIDEuMzExLS41NzMgMi40MTYtMS43MiAzLjMxMy0xLjE0Ny44OTgtMi41OTEgMS4zNDMtNC4zMzMgMS4zMzRhNi44NjcgNi44NjcgMCAwMS00LTEuMTggNi41MDYgNi41MDYgMCAwMS0yLjQ1NC0zLjExNGwyLjUxNy0xLjA3M2E0LjY2MSA0LjY2MSAwIDAwMS42MSAyLjEwMyAzLjkwOSAzLjkwOSAwIDAwMi4zMzcuNzggNC4wNjggNC4wNjggMCAwMDIuMjUtLjZjLjYwNC0uMzg2LjkwNi0uODQ2LjkwNi0xLjM4IDAtLjk2LS43MzYtMS42NjUtMi4yMS0yLjExNmwtMi41NzMtLjY0NGMtMi45MjctLjczNS00LjM4OS0yLjE0NS00LjM4Ny00LjIzYTMuOTEyIDMuOTEyIDAgMDExLjY2Ny0zLjI5N2MxLjExNy0uODMgMi41NC0xLjI0MyA0LjI4LTEuMjQzYTYuOTYxIDYuOTYxIDAgMDEzLjYwMy45NSA1LjE2MyA1LjE2MyAwIDAxMi4yNiAyLjU2bC0yLjUxMyAxLjA0NGEzLjE5NSAzLjE5NSAwIDAwLTEuMzk3LTEuNDkgNC4zOCA0LjM4IDAgMDAtMi4xNjMtLjU1NCAzLjY0NCAzLjY0NCAwIDAwLTEuOTc3LjU1NCAxLjU4NSAxLjU4NSAwIDAwLS44NzMgMS4zMzNjMCAuODU4LjgwOCAxLjQ3MSAyLjQyMyAxLjg0bDIuMjY3LjU4M2MyLjk4Ny43NDcgNC40OCAyLjI1NiA0LjQ4IDQuNTI3ek0xOTYuMjU3IDI0LjgzYTYuNDY3IDYuNDY3IDAgMDEtMy4wMi0uNzAzIDUuMzE0IDUuMzE0IDAgMDEtMi4xMDQtMS44N0gxOTFsLjEzMyAyLjA3NnY2LjYzaC0yLjgyVjkuMzEzSDE5MVYxMS40aC4xMmE1LjMxMiA1LjMxMiAwIDAxMi4xMDMtMS44NyA2LjY2OCA2LjY2OCAwIDAxOC4wNSAxLjYyMyA4LjIxNyA4LjIxNyAwIDAxMi4xMTQgNS42NjcgOC4xMzMgOC4xMzMgMCAwMS0yLjExNCA1LjY2NyA2LjQ1MSA2LjQ1MSAwIDAxLTUuMDE2IDIuMzQzem0tLjQ2LTIuNTczYTQuNDAxIDQuNDAxIDAgMDAzLjQwMy0xLjUzNGMuOTItMS4wMDQgMS4zOC0yLjMwMyAxLjM4LTMuODk2YTUuNjAyIDUuNjAyIDAgMDAtMS4zOC0zLjg5NCA0LjU3NyA0LjU3NyAwIDAwLTUuMjk0LTEuMTMyIDQuNTg3IDQuNTg3IDAgMDAtMS41NDYgMS4xMzIgNS42NjUgNS42NjUgMCAwMC0xLjMzMyAzLjg5NCA1LjcxNyA1LjcxNyAwIDAwMS4zMzMgMy45MjYgNC40NzUgNC40NzUgMCAwMDMuNDM3IDEuNTA0ek0yMTEuMTMgOC44MjNjMi4wODQgMCAzLjczLjU1NiA0LjkzNyAxLjY2NyAxLjIwNiAxLjExMSAxLjgxIDIuNjQgMS44MSA0LjU4N3Y5LjI1NmgtMi43di0yLjA3NmgtLjEyNGMtMS4xNjQgMS43MTctMi43MiAyLjU3NS00LjY2NiAyLjU3M2E2LjA3IDYuMDcgMCAwMS00LjE1Ny0xLjQ3IDQuNzAyIDQuNzAyIDAgMDEtMS42NjctMy42NjcgNC40NjcgNC40NjcgMCAwMTEuNzctMy43MjNjMS4xNzYtLjkyIDIuNzQ1LTEuMzggNC43MDctMS4zOCAxLjY3NSAwIDMuMDU1LjMwNyA0LjE0Ljkydi0uNjQ3YTMuMjA1IDMuMjA1IDAgMDAtMS4xOC0yLjQ5NiA0LjAwMSA0LjAwMSAwIDAwLTIuNzE3LTEuMDM0IDQuMzM0IDQuMzM0IDAgMDAtMy43NDMgMmwtMi40ODMtMS41NjNjMS4zNzEtMS45NjQgMy4zOTUtMi45NDcgNi4wNzMtMi45NDd6bS0zLjY1IDEwLjkxN2EyLjIzOSAyLjIzOSAwIDAwLjkzNyAxLjg0IDMuNDM5IDMuNDM5IDAgMDAyLjE5Ljc1M0E0LjUwMyA0LjUwMyAwIDAwMjEzLjc4MyAyMWE0LjEzMiA0LjEzMiAwIDAwMS4zOTQtMy4wOTdjLS44ODktLjY5My0yLjExMS0xLjA0LTMuNjY3LTEuMDQzYTQuNzc2IDQuNzc2IDAgMDAtMi44NjcuODMgMi40NTUgMi40NTUgMCAwMC0xLjE2MyAyLjA1ek0yMjcuNDQgMjQuODNhNy40MTkgNy40MTkgMCAwMS01LjU1LTIuMjY3IDguMDc5IDguMDc5IDAgMDEtMi4xNzctNS43MzZjMC0yLjMxMS43MjYtNC4yMjMgMi4xNzctNS43MzRhNy40MTcgNy40MTcgMCAwMTUuNTUtMi4yNyA2Ljg4MSA2Ljg4MSAwIDAxNi41OTMgNC4zMzRsLTIuNTc2IDEuMDczYy0uNzk2LTEuODgtMi4xOTYtMi44Mi00LjItMi44MmE0LjM2MSA0LjM2MSAwIDAwLTMuMzM0IDEuNTYzIDUuNjM0IDUuNjM0IDAgMDAtMS4zOCAzLjg2NCA1LjYyMyA1LjYyMyAwIDAwMS4zOCAzLjg2MyA0LjM2NSA0LjM2NSAwIDAwMy4zMzQgMS41NjdjMi4wNjQgMCAzLjUxNS0uOTQxIDQuMzUzLTIuODI0bDIuNTE3IDEuMDc0YTYuNzMgNi43MyAwIDAxLTIuNTk0IDMuMTUgNy4zMzIgNy4zMzIgMCAwMS00LjA5MyAxLjE2M3pNMjQyLjYyMyAyNC44M2E3LjE5IDcuMTkgMCAwMS01LjQ2LTIuMjY3Yy0xLjQyOS0xLjUxMy0yLjE0NC0zLjQyNS0yLjE0Ni01LjczNi0uMDAzLTIuMzExLjY5My00LjIxOCAyLjA4Ni01LjcyYTYuOTE4IDYuOTE4IDAgMDE1LjMzNC0yLjI4NGMyLjIyMiAwIDQgLjcyMSA1LjMzMyAyLjE2NCAxLjMzMyAxLjQ0MiAxLjk5MiAzLjQ2IDEuOTc3IDYuMDU2bC0uMDMuMzA3SDIzNy45YTQuODkgNC44OSAwIDAwMS40NzMgMy41NTcgNC43MDIgNC43MDIgMCAwMDMuMzc0IDEuMzMzYzEuNzk3IDAgMy4yMDctLjkgNC4yMy0yLjdsMi41MTYgMS4yMjdhNy40OTMgNy40OTMgMCAwMS0yLjgwNiAyLjk3MyA3Ljc1MSA3Ljc1MSAwIDAxLTQuMDY0IDEuMDl6bS00LjUwNi05LjgxM2g4LjYxNmEzLjc1NiAzLjc1NiAwIDAwLTEuMjczLTIuNTljLS43NjctLjY4NS0xLjc5NC0xLjAyNy0zLjA4My0xLjAyN2E0LjA5IDQuMDkgMCAwMC0yLjc0NC45OCA0LjY2NiA0LjY2NiAwIDAwLTEuNTE2IDIuNjM3eiIgZmlsbD0iIzVGNjM2OCIvPjxwYXRoIGQ9Ik0xMi41ODcgMjQuODI2QzUuNzQ3IDI0LjgyNiAwIDE5LjI1MyAwIDEyLjQxM1M1Ljc0NyAwIDEyLjU4NyAwYTExLjgxNiAxMS44MTYgMCAwMTguNSAzLjQybC0yLjM5IDIuMzkzYTguNjM3IDguNjM3IDAgMDAtNi4xMS0yLjQyMyA4LjkgOC45IDAgMDAtOC44OTcgOS4wMjMgOC45IDguOSAwIDAwOC44OTcgOS4wMmMzLjIzNiAwIDUuMDgtMS4zIDYuMjYtMi40OC45Ny0uOTcgMS42MDMtMi4zNjMgMS44NDYtNC4yN2gtOC4xOTZ2LTMuMzlIMjRjLjEzLjY5OC4xOTIgMS40MDcuMTgzIDIuMTE3IDAgMi41NDMtLjY5NiA1LjY5My0yLjkzNiA3LjkzMy0yLjE4NyAyLjI3LTQuOTcgMy40ODMtOC42NiAzLjQ4M3oiIGZpbGw9IiM0Mjg1RjQiLz48cGF0aCBkPSJNNDEuMzg3IDE2LjgzM2E4IDggMCAxMS0xMy42NTUtNS42NjIgOC4wMDggOC4wMDggMCAwMTEzLjY3MSA1LjY2MmgtLjAxNnptLTMuNTA3IDBjMC0yLjg3Ni0yLjA4My00Ljg0My00LjUtNC44NDNzLTQuNTAzIDEuOTY3LTQuNTAzIDQuODQzYzAgMi44NzcgMi4wODYgNC44MzQgNC41MDMgNC44MzQgMi40MTcgMCA0LjUtMiA0LjUtNC44MzR6IiBmaWxsPSIjRUE0MzM1Ii8+PHBhdGggZD0iTTU4LjgxNyAxNi44MzNhOCA4IDAgMTEtMTYgMCA4IDggMCAwMTE2IDB6bS0zLjUwNyAwYzAtMi44NzYtMi4wODMtNC44NDMtNC41LTQuODQzcy00LjUwMyAxLjk2Ny00LjUwMyA0Ljg0M2MwIDIuODc3IDIuMDgzIDQuODM0IDQuNTAzIDQuODM0czQuNS0yIDQuNS00LjgzNHoiIGZpbGw9IiNGQkJDMDQiLz48cGF0aCBkPSJNNzUuNDkgOS4zMzN2MTQuMzM0YzAgNS45MDMtMy40OCA4LjMzMy03LjU5MyA4LjMzM2E3LjYxIDcuNjEgMCAwMS03LjA4LTQuNzIzTDYzLjg3MyAyNmMuNTQ0IDEuMyAxLjg3NCAyLjg0MyA0LjAyNCAyLjg0MyAyLjYzIDAgNC4yNjYtMS42MzMgNC4yNjYtNC42OVYyM2gtLjEyM2E1LjQ1IDUuNDUgMCAwMS00LjIwMyAxLjgxN2MtNCAwLTcuNjY3LTMuNDg0LTcuNjY3LTcuOTY0czMuNjY3LTguMDIzIDcuNjY3LTguMDIzYTUuNTI3IDUuNTI3IDAgMDE0LjIwMyAxLjc4N2guMTIzVjkuMzMzaDMuMzI3em0tMy4wODcgNy41NGMwLTIuODE2LTEuODc2LTQuODczLTQuMjY2LTQuODczcy00LjQ0NyAyLjA1Ny00LjQ0NyA0Ljg3M2MwIDIuODE3IDIuMDI3IDQuNzk0IDQuNDQ3IDQuNzk0czQuMjY2LTIuMDIgNC4yNjYtNC44MDR2LjAxeiIgZmlsbD0iIzQyODVGNCIvPjxwYXRoIGQ9Ik04MS41MjMuODQ3djIzLjQ4Nkg3OFYuODQ3aDMuNTIzeiIgZmlsbD0iIzM0QTg1MyIvPjxwYXRoIGQ9Ik05NS4xMjcgMTkuNDY3bDIuNzIzIDEuODE2YTcuOTU3IDcuOTU3IDAgMDEtNi42NjcgMy41NDRjLTQuNTM2IDAtNy45MjYtMy41MTQtNy45MjYtOCAwLTQuNzU0IDMuNDItOCA3LjUzMy04czYuMTcgMy4zIDYuODM3IDUuMDg2bC4zNzMuOTItMTAuNjY3IDQuNDJjLjgxNyAxLjYwNyAyLjA4NyAyLjQyNCAzLjg3NCAyLjQyNCAxLjc4NiAwIDMuMDEzLS44NzcgMy45Mi0yLjIxem0tOC4zOC0yLjg3N2w3LjE0LTIuOTY3Yy0uMzk0LTEtMS41NzQtMS42OTYtMi45NjctMS42OTZhNC4zOCA0LjM4IDAgMDAtNC4xNzMgNC42NjN6IiBmaWxsPSIjRUE0MzM1Ii8+PC9nPjxkZWZzPjxjbGlwUGF0aCBpZD0iY2xpcDAiPjxwYXRoIGZpbGw9IiNmZmYiIGQ9Ik0wIDBoMjQ5LjY2N3YzMkgweiIvPjwvY2xpcFBhdGg+PC9kZWZzPjwvc3ZnPg=="
		        ]
		    }
		}

		@classmethod
		def exec_host(self, domain, nsserver='8.8.8.8'):
			import subprocess
			cmd = [settings.HOST_BIN]
			cmd.extend([random.choice(['-4', '-6']), '-v', '-W', '1', '-a'])
			cmd.append(domain)
			if not nsserver:
				nsserver = '8.8.8.8'

			#
			cmd.append(nsserver)
			#die(cmd)
			stderr = None
			try:
				process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
				stdout, stderr = process.communicate()
				stderr = stderr.replace(b"%s: " % settings.HOST_BIN.encode(), b'').strip(b"\n").decode()
				stdout = stdout.decode()
			except Exception as e:
				stderr = "Command execution failed"
				pass
			if not stderr and not stdout:
				stderr = "Command execution failed"

			#print(stdout)
			return (stderr, stdout)

		@classmethod
		def only_dns_only(self, domain, nsserver):
			pass

		@classmethod
		def _parse_ns_query(self, domain, result, shortonly=True):
			#ns = [ns[1].strip(".") for ns in re.findall(r"%s\.\s+\d+\s+(IN|MX|TXT|A|SOA|AAAA|CAA)\s+NS\s+(.*)" % (domain, ), result, re.I)]
			matches = re.findall(r"(%s|(([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}))\.\s+(\d+)\s+IN\s+(|MX|TXT|A|SOA|AAAA|CAA|NS)\s+(.*)" % (domain, ), result, re.I)
			keys = {}
			#print(matches)
			for match in matches:
				key, val = match[4], match[5]
				#exit([key, val, match])
				if key not in keys:
					keys[key] = []
				if key == 'NS':
					val = val.strip('.')
				keys[key].append((val, match[0], match[3]))

			if 'NS' in keys:
				for ns_idx in range(len(keys['NS'])):
					#exit(keys['NS'][ns_idx])
					if 'AAAA' in keys:
						for _ns in keys['AAAA']:
							#exit([_ns[1], keys['NS'][ns_idx][0]])
							if _ns[1] == keys['NS'][ns_idx][0]:
								keys['NS'][ns_idx] += ({'AAAA': _ns[0]}, )
								break

					if 'A' in keys:
						for _ns in keys['A']:
							#print(_ns)
							#exit(keys['NS'][ns_idx])
							if _ns[1] == keys['NS'][ns_idx][0]:
								try:
									(keys['NS'][ns_idx][3])
									keys['NS'][ns_idx][3]['A'] = _ns[0]
								except:
									keys['NS'][ns_idx] += ({'A': _ns[0]}, )
								break

			#die(keys)
			return keys

		@classmethod
		def parse_nsresponse(result):
			pass

		@classmethod
		def _expand_ip(self, ipaddr):
			try:
				ipaddr = '192.168.255.244'
				ip4 = ipaddress.IPv4Network(ipaddr)
				for ip in ip4:
					print(ip)
			except Exception as e:
				raise e

			exit()

		@classmethod
		def _check_in_spfip(self, ipaddr, spf):
			try:
				#spf = "64.91.0.0/16"
				ip4 = ipaddress.IPv4Network(spf)
				return (ipaddress.ip_address(ipaddr) in ip4)
			except Exception as e:
				pass
			return False

		@classmethod
		def get_spf(self, zones):
			spf = [(txt[0].strip('"'), txt[1], txt[2]) for txt in (zones['TXT'] if 'TXT' in zones else []) if txt[0].lstrip('"').startswith('v=spf1')]
			return spf[0] if spf else None

		@classmethod
		def parse_spf(self, spf_record):
			if spf_record is None or not len(spf_record):
				return None

			mechanisms = spf_record[0].split(" ")
			spf = OrderedDict()
			rip4 = r"^(\+|-|~|\?)?ip4:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/(\d+))?"
			rip6 = r"^(\+|-|~|\?)?ip6:((?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4})(\/(\d+))?"
			for mechanism in mechanisms:
				mechanism = mechanism.strip().lower()

				vreg = "^v=(.[^ ]*)$"
				vm = re.findall(vreg, mechanism, re.I)
				if len(vm) == 1:
					spf["version"] = {'errno': 0, 'errmsg': '+OK', 'data' []}
					spf["version"]['v'] = vm[0]
					if vm[0] not in ['spf1']:
						spf["version"]['errno'] = 1
						spf["version"]['errmsg'] = 'Invalid spg version found'
					continue

				areg = "^(\+|-|~|\?)?(all)$"
				mam = re.findall(areg, mechanism, re.I)
				if len(mam) == 1:
					qualifier = '+'
					try:
						qualifier = mam[0][0] if mip4[0][0] else '+'
					except:
						pass
					if 'all' not in spf:
						spf['all'] = []

					spf['all'].append((qualifier, self.spf_qualifier[qualifier], 'all'))
					continue

				mip4 = re.findall(rip4, mechanism, re.I)
				if len(mip4) == 1:
					qualifier = '+'
					try:
						qualifier = mip4[0][0] if mip4[0][0] else '+'
					except:
						pass
					ip = mip4[0][1]
					ip_prefix = mip4[0][3]

					if 'ip4' not in spf:
						spf['ip4'] = []

					spf['ip4'].append((qualifier, self.spf_qualifier[qualifier], ip, ip_prefix))
					continue

					#exit([mip4, mechanism, ip, ip_prefix])
				#exit("Not Found")
				#The "ip6" mechanism
				mip6 = re.findall(rip6, mechanism, re.I)
				if len(mip6) == 1:
					qualifier = '+'
					try:
						qualifier = mip6[0][0] if mip6[0][0] else '+'
					except:
						pass
					ip = mip6[0][1]
					prefix = mip6[0][3]
					if 'ip6' not in spf:
						spf['ip6'] = []

					spf['ip6'].append((qualifier, self.spf_qualifier[qualifier], ip, prefix))
					continue

				#The "a" mechanism
				ripa = r"^(\+|-|~|\?)?a(:?)((([a-z0-9]\-*[a-z0-9]*){1,63}\.?){1,255})?(/?(\d+))?"
				mipa = re.findall(ripa, mechanism, re.I)
				print(mechanism)
				if len(mipa) == 1:
					qualifier = '+'
					try:
						qualifier = mipa[0][0] if mipa[0][0] else '+'
					except:
						pass

					domain = ''
					if mipa[0][1] == ":":
						domain = mipa[0][2]
						if not domain:
							break
					#die(domain)
					prefix = mipa[0][6]
					if 'a' not in spf:
						spf['a'] = []

					spf['a'].append((qualifier, self.spf_qualifier[qualifier], domain, prefix))
					continue

			die([spf])

		@classmethod
		def _parse_spf_records(self, rec_zones, ipaddr):
			spf = {}
			rec_zones['TXT'] = ["v=spf1 a:mail.solarmora.com ip4:192.72.10.10 include:_spf.google.com ~all"]
			rec_zones['TXT'] = ["v=spf1 ip4:192.168.0.0/16 include:_spf.google.com include:sendyourmail.com ~all"]
			rec_zones['TXT'] = ["v=spf1 ip4:64.91.0.0/16 include:spf.mandrillapp.com ?all"]

			for txt in (rec_zones['TXT'] if 'TXT' in rec_zones else []):
				if txt.lstrip('"').startswith('v=spf1'):
					matches = re.findall(r'^(v=spf1)((\s+(include|ip4|ip6|a)(?:\\:(.[^\s]*))))*\s+((.)all)', txt, re.I)
					exit(matches)
					for match in matches:
						if match[0] not in spf:
							spf[match[0]] = []

						mailer_name, spf_pass = None, False
						if match[0].lower() == "include" and match[1] in self.mail_providers['spf']:
							mailer_name = self.mail_providers['spf'][match[1]]
							spf_pass = True
						elif match[0].lower() == "ip4":
							spf_pass = self._check_in_spfip(ipaddr, match[1])
							exit([spf_pass])
						spf[match[0]].append((match[1], spf_pass, mailer_name))
					break
			exit(spf)

	spf_record = ('v=spf1 ~ip4:64.91.229.99 -ip6:2402:3a80:1224:6d81:ac62:11e1:1333:1f51/24 ?a:collax.com/34 ~all', 'collabx.com', '3600')
	parse_spf = network_tools.parse_spf(spf_record)
	exit()

	domain, nsserver = "collabx.com", 'ns.liquidweb.com'
	errmsg, all_records = network_tools.exec_host(domain, nsserver)
	#print(all_records)
	if errmsg:
		exit(errmsg)

	#
	zones = network_tools._parse_ns_query(domain, all_records)
	#exit([zones])
	#nsserver = None
	if nsserver is None and 'NS' in zones and len(zones['NS']):
		try:
			nsserver = random.choice(zones['NS'])[3]['A']
		except Exception as e:
			nsserver = random.choice(zones['NS'])[0]
	#die(zones)
	spf_record = network_tools.get_spf(zones)
	#exit(spf_record)
	parse_spf = network_tools.parse_spf(spf_record)

	domain_a = zones['A'][0]

	spf_records = network_tools._parse_spf_records(zones, domain_a)
	exit()
	#errmsg, all_records = network_tools.exec_host(domain, nsserver, nameonly=nameonly)

	#print(result)
	exit([domain, nsserver])

	stderr, result = None, """
	Using domain server:
Name: ns.liquidweb.com
Address: 2607:fad0:0:8917::a#53
Aliases: 

collabx.com name server ns1.liquidweb.com.
collabx.com name server ns.liquidweb.com.

	"""
	ns = network_tools._parse_ns_query(domain, result)
	exit()

import socket, os, sys
from urllib.parse import urlparse

from contextlib import contextmanager
import signal


def raise_error(signum, frame):
	"""This handler will raise an error inside gethostbyname"""
	raise OSError


@contextmanager
def set_signal(signum, handler):
	"""Temporarily set signal"""
	old_handler = signal.getsignal(signum)
	signal.signal(signum, handler)
	try:
		yield
	finally:
		signal.signal(signum, old_handler)


@contextmanager
def set_alarm(time):
	"""Temporarily set alarm"""
	signal.setitimer(signal.ITIMER_REAL, time)
	try:
		yield
	finally:
		signal.setitimer(signal.ITIMER_REAL, 0)  # Disable alarm


@contextmanager
def raise_on_timeout(time):
	"""This context manager will raise an OSError unless
    The with scope is exited in time."""
	with set_signal(signal.SIGALRM, raise_error):
		with set_alarm(time):
			yield


from urllib.request import urlopen
from json import load

sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "/bin/")
from bin.countries import countries


class ip_info:
	@classmethod
	def get_country_by_code():
		pass

	@classmethod
	def _by_ip_info(self, response, addr):
		url = 'https://ipinfo.io/' + addr + '/json'
		try:
			res = urlopen(url)
			data = load(res)
			response['city'] = data['city'] if 'city' in data else None
			response['region'] = data['region'] if 'region' in data else None
			response['country'] = data['country'] if 'country' in data else None
			response['loc'] = data['loc'] if 'loc' in data else None
			response['org'] = data['org'] if 'org' in data else None
			response['postal'] = data['postal'] if 'postal' in data else None
			response['timezone'] = data['timezone'] if 'timezone' in data else None
		except Exception as e:
			raise e
			pass
		exit([data])
		return None

	@classmethod
	def fetch(self, addr):
		response = {'ip': addr, 'anycast': True, 'city': None, 'region': None, 'country': None, 'loc': None, 'org': None, 'postal': None, 'timezone': None}
		ret = self._by_ip_info(response, addr)


class domain_to_ip:
	@classmethod
	def filter_domain(self, domain_url):
		try:
			uparts = urlparse(domain_url)
			return uparts.netloc.split(":")[0]
		except Exception as e:
			pass
		return None

	@classmethod
	def domin2ip(self, domain):
		try:
			with raise_on_timeout(0.4):
				data = socket.gethostbyname_ex(domain)
				return data[2][0]
		except Exception as e:
			return None


import requests

url = "http://web.archive.org/cdx/search/cdx?url=www.sudlows.com&from=2021"  #&to=2020"
#url = "http://archive.org/wayback/available?url=www.sudlows.com&timestamp=20200101"

response = requests.get(url)
print(response.text)
exit()

domain_name = domain_to_ip.filter_domain('ftp://rankwatch.com:9866')
addr_ip = domain_to_ip.domin2ip(domain_name)
ip_data = ip_info.fetch(addr_ip)
exit([domain_name, addr_ip, ip_data])

import email, smtplib, ssl

from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from email.parser import BytesParser, Parser
from email.policy import default

message = MIMEMultipart()
message["From"] = 'Bijaya Kumar <bijaya@tickethuddle.com>'


#exit([headers['from'].addresses[0]])
def build_emailaddresses(emailids):
	emailaddresses = []
	for emailid in emailids:
		stremail = 'From: {0}\n'.format(emailid)
		try:
			headers = Parser(policy=default).parsestr(stremail)
			display_name, email_domain = headers['From'].addresses[0].display_name, headers['From'].addresses[0].domain
			emailaddresses = {'display_name': display_name, 'address': '{0}@{1}'.format(headers['From'].addresses[0].username, email_domain)}
			#xit([display_name, email_domain])
		except Exception as e:
			raise e
			return None
	return emailaddresses


emails = ['Bijaya Kumar <bijaya@tickethuddle.com>', 'Bijaya Behera <bijaya@tickethuddle.com>']
emailaddresses = build_emailaddresses(emails)
exit([emailaddresses])
'''
import math
import sys
x = list(range(1, int(sys.argv[1]) + 1))
######################
threadid = int(sys.argv[2])
maxlimit = int(sys.argv[3])
mxthread = int(sys.argv[4])

######################
totalrecords = len(x)
threadrecords = math.ceil(totalrecords / mxthread)
diffrecords = (threadrecords * mxthread) - totalrecords
#exit([(threadid - 11) in list(range(0, mxthread - diffrecords))])
thisthreadrecords = threadrecords if (threadid - 11) in list(range(0, mxthread - diffrecords)) else threadrecords - 1
#exit([thisthreadrecords, totalrecords, math.ceil(totalrecords / mxthread)])
min_offset = 0 if threadid - 11 == 0 else sum([threadrecords if (_thread - 11) in list(range(0, mxthread - diffrecords)) else threadrecords - 1 for _thread in list(range(11, threadid))])
print(list(range(11, threadid)), list(range(0, mxthread - diffrecords)), threadrecords)
max_offset = min_offset + thisthreadrecords
print([min_offset, max_offset], thisthreadrecords, x[min_offset:max_offset])
import time
the_offset = min_offset
print("====================================")
while True:
	sql_limit = (max_offset - the_offset) if the_offset + maxlimit > max_offset else maxlimit
	records = x[the_offset:the_offset + sql_limit]
	if not records:
		break
	print(" LIMIT %d, %d ===> for thread = %d, allows = %d " % (the_offset, sql_limit, threadid, thisthreadrecords), records)
	the_offset += len(records)
	time.sleep(1)

exit()

print(x)
exit()
'''


def manual_comp():
	import pickle
	file = '/Applications/XAMPP/htdocs/keywords2.dat'
	with open(file, 'rb') as p:
		keywords_urls = pickle.load(p)

	url_table = '<table>'
	url_table += '<tr><th width="10%">Sr No</th><th width="20%">Keyword</th><th>URLs</th></tr>'
	srno = 1
	for keyword, urls in keywords_urls.items():
		urldata = '<ol>'
		for url in urls:
			urldata += f'<li>{url}</li>'
		urldata += '</ul>'
		url_table += f'<tr><td>{srno}</td><td>{keyword}</td><td>{urldata}</td></tr>'
		srno += 1
	url_table += '</table>'
	#exit([url_table])

	divifor = '<hr/>'

	comp_table = '<table>'
	comp_table += '<tr><th width="5%">Sr No</th><th width="20%">Keyword A</th><th width="20%">Keyword B</th><th>URLs</th><th>%</th></tr>'
	keys = list(keywords_urls.keys())
	llen = len(keys)
	srno = 1
	kw_urls = {}
	for i in range(llen):
		keyword_1 = keys[i]
		urls_1 = keywords_urls[keyword_1]
		for j in range(i + 1, llen):
			keyword_2 = keys[j]

			urls_2 = keywords_urls[keyword_2]
			diff = urls_1 & urls_2
			urldata = ''
			per_matched = len(diff)
			if per_matched >= 3:
				if keyword_1 not in kw_urls:
					kw_urls[keyword_1] = []

				kw_urls[keyword_1].append(keyword_2)
				#print([keyword_1, keyword_2, len(diff)])
				urldata = '<ol>'
				for comp_url in diff:
					urldata += f'<li>{comp_url}</li>'
				urldata = '</ol>'
			comp_table += f'<tr><td>{srno}</td><td>{keyword_1}</td><td>{keyword_2}</td><td>{urldata}</td><td>{per_matched}</td></tr>'
			srno += 1
	#exit(keywords_urls)
	#exit()
	comp_table += '</table>'

	kw_urls = {}
	kw_urls['search engine optimization resellers'] = ['seo reseller agency']
	kw_urls['white label seo'] = [
	    'white label seo company', 'white label seo reseller', 'white label seo services', 'private label seo reseller', 'best white label seo', 'best white label seo services', 'white label seo reseller services', 'seo reseller services'
	]
	kw_urls['seo reseller services'] = ['white label seo reseller services', 'white label seo', 'white label seo services', 'best seo reseller company', 'private label seo reseller']

	kw_urls['white label seo services'] = [
	    'white label seo', 'white label seo company', 'white label seo reseller services', 'best white label seo', 'private label seo reseller', 'white label local seo services', 'white label seo reseller', 'best white label seo services'
	]
	kw_urls['white label seo reseller'] = [
	    'white label seo', 'white label seo company', 'best white label seo services', 'private label seo reseller', 'white label local seo services', 'white label seo services', 'best white label seo', 'white label seo reseller services'
	]
	kw_urls['white label seo company'] = [
	    'white label seo', 'white label seo reseller', 'private label seo reseller', 'white label seo services', 'best white label seo', 'best white label seo services', 'white label local seo services', 'white label seo reseller services'
	]
	kw_urls['seo reseller company'] = ['top seo resellers', 'seo reseller agency']
	kw_urls['white label local seo'] = ['white label local seo services', 'white label seo reseller services', 'best white label seo', 'local seo reseller', 'private label seo reseller']
	kw_urls['white label seo agency'] = ['white label seo services for agencies', 'white label seo providers', 'white label seo solutions']
	kw_urls['local seo reseller'] = ['white label local seo']
	kw_urls['white label seo services for agencies'] = ['white label seo agency', 'white label seo solutions', 'white label seo providers', 'white label seo for agencies']
	kw_urls['private label seo reseller'] = [
	    'white label seo', 'white label seo company', 'white label seo reseller', 'white label local seo services', 'white label seo reseller services', 'white label seo services', 'best white label seo', '	best white label seo services'
	]
	kw_urls['best white label seo'] = [
	    'white label seo', 'white label seo company', 'white label seo services', 'best white label seo services', 'private label seo reseller', 'white label local seo services', 'white label seo reseller', '	white label seo reseller services'
	]
	kw_urls['best seo reseller'] = ['top seo resellers', 'seo reseller agency']
	kw_urls['white label seo reseller services'] = [
	    'white label seo services', 'seo reseller services', 'private label seo reseller', 'white label seo', 'best seo reseller company', 'best white label seo', 'white label local seo', 'white label local seo services'
	]
	kw_urls['white label local seo services'] = [
	    'private label seo reseller', 'white label local seo', 'white label seo company', 'white label seo reseller', 'white label seo services', 'best white label seo', 'white label seo', 'white label seo reseller services'
	]
	kw_urls['best white label seo services'] = ['white label seo reseller', 'white label seo', 'white label seo company', 'best white label seo', 'white label seo services', 'private label seo reseller', 'white label local seo services']
	kw_urls['best seo reseller company'] = ['white label seo reseller services', 'seo reseller services']
	kw_urls['top white label seo companies'] = ['best white label seo company', 'white label seo solutions', 'white label seo for agencies', 'white label seo providers']
	kw_urls['best white label seo company'] = ['white label seo solutions', 'top white label seo companies', 'white label seo for agencies', 'white label seo providers']
	kw_urls['seo reseller agency'] = ['best seo reseller', 'seo reseller company', 'search engine optimization resellers', 'outsource seo reseller', 'top seo resellers']
	kw_urls['outsource seo reseller'] = ['seo reseller agency']
	kw_urls['white label seo providers'] = ['white label seo solutions', 'white label seo agency', 'white label seo services for agencies', 'white label seo for agencies', 'top white label seo companies', 'best white label seo company']
	kw_urls['white label seo solutions'] = ['white label seo providers', 'best white label seo company', 'white label seo services for agencies', 'white label seo agency', 'white label seo for agencies', 'top white label seo companies']
	kw_urls['white label seo for agencies'] = ['white label seo services for agencies', 'white label seo solutions', 'white label seo providers', 'top white label seo companies', 'best white label seo company']
	kw_urls['top seo resellers'] = ['best seo reseller', 'seo reseller agency', 'seo reseller company']

	#exit([len(list(kw_urls.keys()))])
	import copy
	idex = 0
	kw_urls_arr = [(item, kws) for item, kws in kw_urls.copy().items()]
	#print(kw_urls_arr)
	for i in range(len(kw_urls_arr)):
		keywords_1 = kw_urls_arr[i][1]
		keyword_a = kw_urls_arr[i][0]
		for j in range(i + 1, len(kw_urls_arr)):
			for keyword_1 in keywords_1:
				if keyword_1 in kw_urls:
					kw_urls[keyword_1] = []
					break
				if keyword_1 in kw_urls_arr[j][1]:
					kw_urls[keyword_a].remove(keyword_1)

		#exit([kw_urls['white label seo']])

	ourtools_table = '<table>'
	comp_table += '<tr><th width="5%">Sr No</th><th width="20%">Keyword A</th><th>URLs</th></tr>'
	srno = 1
	for keyword, keywords in kw_urls.item():
		if keywords:
			urls = '<ol>'
			for _keyword in keywords:
				urls += '<li>' + _keyword + '</li>'
			comp_table += f'<tr><td>srno</td><td>{srno}</td><td>{urls}</td></tr>'
	comp_table += '</table'
	exit([kw_urls])
	exit(file)


exit(manual_comp())

import requests
import sys
url = "http://webservice.consultuscare.com:8585/ConsultusWebService.asmx"
url = "http://66.70.176.45/test.php?cmd=sleep"
headers = {'content-type': 'application/soap+xml', 'SOAPAction': "http://ConsultusCare.com/GetActiveCourseList"}

what = int(sys.argv[1])
if what == 1:
	headers = {'content-type': 'text/xml', 'SOAPAction': "http://ConsultusCare.com/GetActiveCourseList"}
	body = """<?xml version="1.0" encoding="utf-8"?>
			<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
				<soap:Body>
				  <GetActiveCourseList xmlns="http://ConsultusCare.com/">
      			<Connection>CarerLive</Connection>
   				 </GetActiveCourseList>
				</soap:Body>
			</soap:Envelope>"""

	body = """<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <GetActiveCourseList xmlns="http://ConsultusCare.com/">
        <Connection>CarerLive</Connection>
      </GetActiveCourseList>
    </soap:Body>
  </soap:Envelope>"""

	print(body)

if what == 2:
	headers = {'content-type': 'text/xml', 'SOAPAction': "http://ConsultusCare.com/GetActiveCourseList"}
	body = """<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
		<soap:Body>
			<GetActiveCourseList xmlns="http://ConsultusCare.com/">
				<Connection>NursingLive</Connection>
			</GetActiveCourseList>
		</soap:Body>
	</soap:Envelope>
	"""
#Dev or Test or CarerLive or NursingLive
#DA3454F7EC269D583F49C75CC0AD3AEDA291B02BF2279E8F9EE267EFFD1BEE99DC625CB57B0747D380FCBCFE0EF0811FA37D4B761E52B138810D5FD9CADC51921EE1EE53633475F886236891E535CA4A<
if what == 3:
	headers = {'content-type': 'text/xml', 'SOAPAction': "http://ConsultusCare.com/GetToken"}
	body = """<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
		<soap:Body>
			<GetToken xmlns="http://ConsultusCare.com/">
				<Connection>CarerLive</Connection>
				<PassPhrase>string</PassPhrase>
			</GetToken>
		</soap:Body>
	</soap:Envelope>
	"""
#DA3454F7EC269D583F49C75CC0AD3AEDA291B02BF2279E8F9EE267EFFD1BEE99DC625CB57B0747D380FCBCFE0EF0811FA37D4B761E52B138810D5FD9CADC51921EE1EE53633475F886236891E535CA4A

if what == 4:
	headers = {'content-type': 'text/xml', 'SOAPAction': "http://ConsultusCare.com/GetTimetableForCourse"}
	body = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetTimetableForCourse xmlns="http://ConsultusCare.com/">
      <Connection>CarerLive</Connection>
      <CourseId>8c96d22e-58c2-4415-84cb-8eab790227ec</CourseId>
      <StartDate>2020-12-01T10:00:00</StartDate>
      <EndDate>2020-12-12T23:00:00</EndDate>
    </GetTimetableForCourse>
  </soap:Body>
</soap:Envelope>"""

response = requests.post(url, data=body, headers=headers)
print(response.content.decode())
with open('/Applications/XAMPP/htdocs/courselist.xml', 'w') as p:
	p.write(response.content.decode())
exit()

from struct import *
import hashlib
u1 = hashlib.md5(b'GeeksforGeeks').digest()
u2 = hashlib.md5(b'GeeksforGeeks2').digest()
u3 = hashlib.md5(b'GeeksforGeeks3').digest()
u4 = hashlib.md5(b'GeeksforGeeks4').digest()
u5 = hashlib.md5(b'GeeksforGeeks5').digest()
u6 = hashlib.md5(b'GeeksforGeeks6').digest()
u7 = hashlib.md5(b'GeeksforGeeks7').digest()
u8 = hashlib.md5(b'GeeksforGeeks8').digest()
u9 = hashlib.md5(b'GeeksforGeeks9').digest()
u10 = hashlib.md5(b'GeeksforGeeks10').digest()

md5_urls = [u1, u2, u3, u4, u5, u6, u7, u8, u9, u10]


def pack_md5_urls(urls_mds, hexdigit=False):
	arr = bytearray()
	for url_mds in urls_mds:
		arr.extend(url_mds)
	return arr


pack_urls_md5 = pack_md5_urls(md5_urls)
print(len(pack_urls_md5))
unpack_urls_md5 = unpack_md5_urls(pack_urls_md5)

exit(len(pack_md5_urls(md5_urls)))
x = pack('H', 800000000)
y = unpack('H', x)
print(y, calcsize('H'))
