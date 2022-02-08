import errno
import pprint
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

    spf_errmsg = {
        'INVALID_QUALIFIER': (1, 'Invalid qualifier found'),
        'INVALID_NETMASK': (2, 'It is not a valid netmask'),
        'EMPTY_VALUE': (3, 'Empty value found.'),
        'INVALID_IPv4_ADDRESS': (4, 'Invalid IPv4 Address'),
        'INVALID_IPv6_ADDRESS': (5, 'Invalid IPv6 Address'),
        'INVALID_NETMASK_OR_IPADDRESS': (6, 'Invalid netmask or IP Address.'),
        'INVALID_IPv4_HOST_BITS_SET': (7, 'Invalid IPv4/IPv6 host bits set.'),
        'NO_ALL_FOUND': (8, 'No all machanim found.'),
        'NO_VERSION_MACHANISM': (8, 'No version machanim found.'),
        'INVALID_MACHANISM': (9, 'Invalid machanism found.'),
        'TAG_MUST_BET_AT_END': (9, 'Tag must be at position:Last.')
    }
    spf_qualifier = {'+': 'Pass', '-': 'Fail', '~': 'SoftFail',
                     '?': 'Neutral', '~~unknown~~': 'Unknown Qualifier.'}
    spf_desc = {
        'v': 'Version of the SPF record',
        'ip4': 'If the IPv4 address falls inside the specified range, the match is made.',
        'ip6': 'If the IPv6 address falls inside the specified range, the match is made.',
        'a': 'Match if IP has a DNS \'A\' record in given domain.',
        'mx': 'Match if IP is one of the MX hosts for given domain name.',
        'include': 'The provided domain is searched for the word \'allow.\'',
        'ptr': 'Check if the specified domain has a DNS \'PTR\' record for the IP address.',
        'exists': 'This method is used to generate an arbitrary host name for DNS \'A\' record queries.',
        'redirect': 'The SPF record for Value will be the current domains SPF record',
        'unknown': 'Unknown',
        'invalid_spf_version': 'Invalid SPF version found.'
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
        # die(cmd)
        stderr = None
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()
            stderr = stderr.replace(
                b"%s: " % settings.HOST_BIN.encode(), b'').strip(b"\n").decode()
            stdout = stdout.decode()
        except Exception as e:
            stderr = "Command execution failed"
            pass
        if not stderr and not stdout:
            stderr = "Command execution failed"

        # print(stdout)
        return (stderr, stdout)

    @classmethod
    def only_dns_only(self, domain, nsserver):
        pass

    @classmethod
    def _parse_ns_query(self, domain, result, shortonly=True):
        #ns = [ns[1].strip(".") for ns in re.findall(r"%s\.\s+\d+\s+(IN|MX|TXT|A|SOA|AAAA|CAA)\s+NS\s+(.*)" % (domain, ), result, re.I)]
        matches = re.findall(
            r"(%s|(([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}))\.\s+(\d+)\s+IN\s+(|MX|TXT|A|SOA|AAAA|CAA|NS)\s+(.*)" % (domain, ), result, re.I)
        keys = {}
        # print(matches)
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
                # exit(keys['NS'][ns_idx])
                if 'AAAA' in keys:
                    for _ns in keys['AAAA']:
                        #exit([_ns[1], keys['NS'][ns_idx][0]])
                        if _ns[1] == keys['NS'][ns_idx][0]:
                            keys['NS'][ns_idx] += ({'AAAA': _ns[0]}, )
                            break

                if 'A' in keys:
                    for _ns in keys['A']:
                        # print(_ns)
                        # exit(keys['NS'][ns_idx])
                        if _ns[1] == keys['NS'][ns_idx][0]:
                            try:
                                (keys['NS'][ns_idx][3])
                                keys['NS'][ns_idx][3]['A'] = _ns[0]
                            except:
                                keys['NS'][ns_idx] += ({'A': _ns[0]}, )
                            break

        # die(keys)
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
        spf = [(txt[0].strip('"'), txt[1], txt[2]) for txt in (
            zones['TXT'] if 'TXT' in zones else []) if txt[0].lstrip('"').startswith('v=spf1')]
        return spf[0] if spf else None

    @classmethod
    def parse_spf(self, spf_record):
        if spf_record is None or not len(spf_record):
            return (None, None)

        spf_err = 0
        mechanisms = spf_record[0].split(" ")
        spf = []
        # die(mechanisms)
        last_mechanism = None
        for mechanism in mechanisms:
            mechanism = mechanism.strip().lower()
            print(mechanism)
            if not mechanism:
                continue

            # The "spfversion" mechanism
            spf_err, cont = self._parse_spf_machanism_spfversion(
                mechanism, spf, spf_err)
            #exit([cont, spf])
            if cont:
                continue

            # The "ip4" mechanism
            spf_err, cont = self._parse_spf_machanism_ip4(
                mechanism, spf, spf_err)
            #exit([cont, spf])
            if cont:
                continue

            # The "ip6" mechanism
            spf_err, cont = self._parse_spf_machanism_ip6(
                mechanism, spf, spf_err)
            if cont:
                continue

            # The "a" mechanism
            spf_err, cont = self._parse_spf_machanism_a(
                mechanism, spf, spf_err)
            if cont:
                continue

            # The "mx" mechanism
            spf_err, cont = self._parse_spf_machanism_mx(
                mechanism, spf, spf_err)
            if cont:
                continue

            # The "ptr" mechanism
            spf_err, cont = self._parse_spf_machanism_ptr(
                mechanism, spf, spf_err)
            if cont:
                continue

            # die(mechanism)
            # The "exists" mechanism
            spf_err, cont = self._parse_spf_machanism_exists(
                mechanism, spf, spf_err)
            if cont:
                continue

            # The "include" mechanism
            spf_err, cont = self._parse_spf_machanism_include(
                mechanism, spf, spf_err)
            if cont:
                continue

            # The "redirect" mechanism
            spf_err, cont = self._parse_spf_machanism_redirect(
                mechanism, spf, spf_err)
            if cont:
                continue

            # The "all" mechanism
            spf_err, cont = self._parse_spf_machanism_all(
                mechanism, spf, spf_err)
            if cont:
                continue

            spf_err, cont = self._parse_spf_machanism_fallback(
                mechanism, spf, spf_err)
            if cont:
                continue

        # Redirect found
        # die(spf)
        # die(list(spf.keys())[-1][0])
        redirects = spf['redirect']['data'] if 'redirect' in spf else []
        if len(redirects) > 0 and '__last:mechanism__' in spf and spf['__last:mechanism__'] != 'redirect':
            for i in range(len(redirects)):
                redirects[i] = (redirects[i][0], redirects[i][1], redirects[i][2],
                                self.spf_errmsg['TAG_MUST_BET_AT_END'][1], redirects[i][4])
                # print(i)
            spf['redirect']['data']

        die([redirects, len(redirects)])

        if 'all' not in spf:
            spf["all"] = {'errno': self.spf_errmsg['NO_ALL_FOUND'][0],
                          'errmsg': self.spf_errmsg['NO_ALL_FOUND'][1], 'data': []}
            spf_err += 1

        if 'version' not in spf:
            spf["version"] = {'errno': self.spf_errmsg['NO_VERSION_MACHANISM'][0],
                              'errmsg': self.spf_errmsg['NO_VERSION_MACHANISM'][1], 'data': []}
            spf_err += 1

        (None, None)
        die([spf])

    @classmethod
    def _parse_spf_machanism_spfversion(self, mechanism, spf, spf_err):
        regex = "^v=(.[^ ]*)$"
        matches = re.findall(regex, mechanism, re.I)
        if not len(matches):
            return (spf_err, False)

        spf_data = {'type': 'v', 'prefix': '',
                    'value': matches[0], 'prefix_desc': ''}
        spf_data['description'] = self.spf_desc['v']
        spf_data['error'] = ''
        if matches[0] not in ['spf1']:
            spf_data['error'] = self.spf_errmsg['invalid_spf_version']
        spf.append(spf_data)
        spf_err += 1
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_fallback(self, mechanism, spf, spf_err):
        #mechanism = '-ip6:2402:3a80:1224:6d81:ac62:11e1:1333:1f51/87'
        # die(mechanism)
        #mechanism = "~ip4:64.91.229.99/34"
        #mechanism = "ip=weqw"
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)([a-z0-9]+)((|([:=]?)|([:=]?)(.*)?))$"
        matches = re.findall(regex, mechanism, re.I)
        #die([matches, mechanism])
        if len(matches) == 0:
            return (spf_err, False)
        mchm = matches[0][1]
        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][len(
            matches[0]) - 1] if matches[0][5] == ":" or matches[0][5] == "=" else ''
        #die([qualifier, val, matches[0][5]])
        if mchm in ['all', 'a', 'ip4', 'ip6', 'mx', 'ptr', 'exists', 'include', 'redirect']:
            return (spf_err, False)

        spf[mchm] = {'errno': 0, 'errmsg': '+OK', 'data': []}
        spf[mchm]['errno'] = self.spf_errmsg['INVALID_MACHANISM'][0]
        spf[mchm]['errmsg'] = self.spf_errmsg['INVALID_MACHANISM'][1]
        spf_err += 1
        spf[mchm]['data'].append((qualifier, self.spf_qualifier[qualifier]
                                  if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~'], val))
        #exit([qualifier, prefix, domain, spf])
        spf['__last:mechanism__'] = 'mchm'
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_redirect(self, mechanism, spf, spf_err):
        #mechanism = "?redirect=rankwatch.collabx.com"
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)redirect(\=)?(((([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,}))))?)$"
        matches = re.findall(regex, mechanism, re.I)
        #die([matches, mechanism])
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        domain = matches[0][3] if matches[0][1] == "=" and matches[0][5] else ''
        #die([qualifier, val, domain])
        if "redirect" not in spf:
            spf["redirect"] = {'errno': 0, 'errmsg': '+OK', 'data': []}

        if qualifier not in self.spf_qualifier:
            spf["redirect"]['errno'] = self.spf_errmsg['INVALID_QUALIFIER'][0]
            spf["redirect"]['errmsg'] = self.spf_errmsg['INVALID_QUALIFIER'][1]
            spf_err += 1
        elif domain == '':
            spf["redirect"]['errno'] = self.spf_errmsg['EMPTY_VALUE'][0]
            spf["redirect"]['errmsg'] = self.spf_errmsg['EMPTY_VALUE'][1]
            spf_err += 1

        spf['redirect']['data'].append((qualifier, self.spf_qualifier[qualifier]
                                        if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~'], val, '', domain))
        #exit([qualifier, domain, spf['redirect']])
        spf['__last:mechanism__'] = 'redirect'
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_ip4(self, mechanism, spf, spf_err):
        #mechanism = '-ip6:2402:3a80:1224:6d81:ac62:11e1:1333:1f51/87'
        # die(mechanism)
        mechanism = "~ip4:64.91.229.99/34"
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)ip4(:)?((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(\/(\d+))?)$"
        matches = re.findall(regex, mechanism, re.I)
        die([matches, mechanism])
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        netmask = matches[0][len(matches[0]) -
                             1] if matches[0][1] == ":" else matches[0][4]
        domain = matches[0][3] if matches[0][1] == ":" and matches[0][5] else ''
        #die([qualifier, val, prefix, domain])
        if netmask:
            try:
                netmask = int(netmask)
            except:
                netmask = 0

        errno, errmsg = 0, '+OK'
        if qualifier not in self.spf_qualifier:
            errno, errmsg = self.spf_errmsg['INVALID_QUALIFIER']
        elif netmask and domain:
            try:
                ipaddress.IPv4Network('%s/%s' % (domain, netmask))
            except ValueError as e:
                errno, errmsg = self.spf_errmsg['INVALID_IPv4_HOST_BITS_SET']
                spf["ip4"]['errno'] = self.spf_errmsg['INVALID_IPv4_HOST_BITS_SET'][0]
            except ipaddress.AddressValueError as e:
                errno, errmsg = self.spf_errmsg['INVALID_IPv4_ADDRESS']
            except ipaddress.NetmaskValueError as e:
                errno, errmsg = self.spf_errmsg['INVALID_NETMASK']
            except:
                errno, errmsg = self.spf_errmsg['INVALID_NETMASK_OR_IPADDRESS']

        # val =
        spf_data = {'type': 'ip4', 'prefix': qualifier, 'value': val, 'netmask': netmask, 'ip': domain,
                    'prefix_desc': self.spf_qualifier[qualifier] if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~']}
        spf_data['description'] = self.spf_desc['ip4']
        spf_data['error'] = errmsg
        spf_err = spf_err + (1 if errno else 0)
        spf.append(spf_data)
        #exit([qualifier, prefix, domain, spf])
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_ip6(self, mechanism, spf, spf_err):
        #mechanism = '-ip6:2402:3a80:1224:6d81:ac62:11e1:1333:1f51/87'
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)ip6(:)?(((?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4})(\/(\d+))?)$"
        matches = re.findall(regex, mechanism, re.I)
        #die([matches, mechanism])
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        netmask = matches[0][len(matches[0]) -
                             1] if matches[0][1] == ":" else matches[0][4]
        domain = matches[0][3] if matches[0][1] == ":" and matches[0][5] else ''
        #die([qualifier, val, prefix, domain])
        if netmask:
            try:
                netmask = int(netmask)
            except:
                netmask = 0

        errno, errmsg = 0, '+OK'

        if qualifier not in self.spf_qualifier:
            errno, errmsg = self.spf_errmsg['INVALID_QUALIFIER']
        elif netmask and domain:
            try:
                ipaddress.IPv6Network('%s/%s' % (domain, netmask))
            except ValueError as e:
                errno, errmsg = self.spf_errmsg['INVALID_IPv4_HOST_BITS_SET']
            except ipaddress.AddressValueError as e:
                errno, errmsg = self.spf_errmsg['INVALID_IPv4_ADDRESS']
            except ipaddress.NetmaskValueError as e:
                errno, errmsg = self.spf_errmsg['INVALID_NETMASK']
            except:
                errno, errmsg = self.spf_errmsg['INVALID_NETMASK_OR_IPADDRESS']

        spf_data = {'type': 'ip6', 'prefix': qualifier, 'value': val, 'netmask': netmask, 'ip': domain,
                    'prefix_desc': self.spf_qualifier[qualifier] if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~']}
        spf_data['description'] = self.spf_desc['ip6']
        spf_data['error'] = errmsg
        spf_err = spf_err + (1 if errno else 0)
        spf.append(spf_data)
        # die(spf)
        #exit([qualifier, prefix, domain, spf])
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_a(self, mechanism, spf, spf_err):
        #mechanism = '?a:rankwatch.collabx.com'
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)a(:)?((/(\d+))?((([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,}))))?(/(\d+))?)$"
        matches = re.findall(regex, mechanism, re.I)
        #die([matches, mechanism])
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        netmask = matches[0][len(matches[0]) -
                             1] if matches[0][1] == ":" else matches[0][4]
        domain = matches[0][5] if matches[0][1] == ":" and matches[0][5] else ''
        #die([qualifier, val, prefix, domain])
        if netmask:
            try:
                netmask = int(netmask)
            except:
                netmask = 0

        errno, errmsg = 0, '+OK'
        if qualifier not in self.spf_qualifier:
            errno, errmsg = self.spf_errmsg['INVALID_QUALIFIER']
        elif not (netmask > 1 and netmask < 33):
            errno, errmsg = self.spf_errmsg['INVALID_NETMASK']

        spf_data = {'type': 'a', 'prefix': qualifier, 'value': val, 'netmask': netmask, 'domain': domain,
                    'prefix_desc': self.spf_qualifier[qualifier] if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~']}
        spf_data['description'] = self.spf_desc['a']
        spf_data['error'] = errmsg
        spf_err = spf_err + (1 if errno else 0)
        spf.append(spf_data)
        # die(spf)
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_mx(self, mechanism, spf, spf_err):
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)mx(:)?((/(\d+))?((([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,}))))?(/(\d+))?)$"
        matches = re.findall(regex, mechanism, re.I)
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        netmask = matches[0][len(matches[0]) -
                             1] if matches[0][1] == ":" else matches[0][4]
        domain = matches[0][5] if matches[0][1] == ":" and matches[0][5] else ''
        #die([qualifier, val, netmask, domain])
        if netmask:
            try:
                netmask = int(netmask)
            except:
                netmask = 0

        errno, errmsg = 0, '+OK'
        if qualifier not in self.spf_qualifier:
            errno, errmsg = self.spf_errmsg['INVALID_QUALIFIER']
        elif not (netmask > 1 and netmask < 33):
            errno, errmsg = self.spf_errmsg['INVALID_NETMASK']

        spf_data = {'type': 'mx', 'prefix': qualifier, 'value': val, 'netmask': netmask, 'domain': domain,
                    'prefix_desc': self.spf_qualifier[qualifier] if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~']}
        spf_data['description'] = self.spf_desc['mx']
        spf_data['error'] = errmsg
        spf_err = spf_err + (1 if errno else 0)
        spf.append(spf_data)
        # die(spf)
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_ptr(self, mechanism, spf, spf_err):
        mechanism = "ptr:gggg"
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)ptr(:)?(((([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,}))))?)$"
        matches = re.findall(regex, mechanism, re.I)
        die([matches])
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        domain = matches[0][3] if matches[0][1] == ":" and matches[0][3] else ''
        #die([qualifier, val, domain, matches, matches[0][1] == ":", matches[0][3], domain])
        errno, errmsg = 0, '+OK'

        if qualifier not in self.spf_qualifier:
            errno, errmsg = self.spf_errmsg['INVALID_QUALIFIER']
        elif matches[0][1] == ":" and not domain:
            errno, errmsg = self.spf_errmsg['EMPTY_VALUE']

        spf_data = {'type': 'ptr', 'prefix': qualifier, 'value': val, 'domain': domain,
                    'prefix_desc': self.spf_qualifier[qualifier] if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~']}
        spf_data['description'] = self.spf_desc['ptr']
        spf_data['error'] = errmsg
        spf_err = spf_err + (1 if errno else 0)
        spf.append(spf_data)
        die(spf)
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_exists(self, mechanism, spf, spf_err):
        #mechanism = "?exists:rankwatch.collabx.com"
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)exists(:)?(((([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,}))))?)$"
        matches = re.findall(regex, mechanism, re.I)
        #die([matches, mechanism])
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        domain = matches[0][3] if matches[0][1] == ":" and matches[0][5] else ''
        #die([qualifier, val, domain])
        if "exists" not in spf:
            spf["exists"] = {'errno': 0, 'errmsg': '+OK', 'data': []}

        if qualifier not in self.spf_qualifier:
            spf["exists"]['errno'] = self.spf_errmsg['INVALID_QUALIFIER'][0]
            spf["exists"]['errmsg'] = self.spf_errmsg['INVALID_QUALIFIER'][1]
            spf_err += 1
        elif domain == '':
            spf["exists"]['errno'] = self.spf_errmsg['EMPTY_VALUE'][0]
            spf["exists"]['errmsg'] = self.spf_errmsg['EMPTY_VALUE'][1]
            spf_err += 1

        spf['exists']['data'].append((qualifier, self.spf_qualifier[qualifier]
                                      if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~'], val, domain))
        #exit([qualifier, domain, spf['exists']])
        spf['__last:mechanism__'] = 'exists'
        return (spf_err, True)

    @classmethod
    def _parse_spf_machanism_include(self, mechanism, spf, spf_err):
        regex = r"^(\+|-|~|\?|[^0-9-A-z]?)include(:)?((((([\da-zA-Z])([_\w-]{,62})\.){,127}(([\da-zA-Z])[_\w-]{,61})?([\da-zA-Z]\.((xn\-\-[a-zA-Z\d]+)|([a-zA-Z\d]{2,}))))))?$"
        matches = re.findall(regex, mechanism, re.I)
        # die(matches)
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][2]
        domain = matches[0][3] if matches[0][1] == ":" and matches[0][5] else ''
        #die([qualifier, val, domain])
        if "include" not in spf:
            spf["include"] = {'errno': 0, 'errmsg': '+OK', 'data': []}

        if qualifier not in self.spf_qualifier:
            spf["include"]['errno'] = self.spf_errmsg['INVALID_QUALIFIER'][0]
            spf["include"]['errmsg'] = self.spf_errmsg['INVALID_QUALIFIER'][1]
            spf_err += 1
        elif domain == '' or val == "":
            spf["include"]['errno'] = self.spf_errmsg['EMPTY_VALUE'][0]
            spf["include"]['errmsg'] = self.spf_errmsg['EMPTY_VALUE'][1]
            spf_err += 1

        spf['include']['data'].append((qualifier, self.spf_qualifier[qualifier]
                                       if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~'], val, domain))
        #exit([qualifier, domain, spf])
        spf['__last:mechanism__'] = 'include'
        return (spf_err, True)

    @classmethod
    def _parse_spf_records(self, rec_zones, ipaddr):
        spf = {}
        rec_zones['TXT'] = [
            "v=spf1 a:mail.solarmora.com ip4:192.72.10.10 include:_spf.google.com ~all"]
        rec_zones['TXT'] = [
            "v=spf1 ip4:192.168.0.0/16 include:_spf.google.com include:sendyourmail.com ~all"]
        rec_zones['TXT'] = [
            "v=spf1 ip4:64.91.0.0/16 include:spf.mandrillapp.com ?all"]

        for txt in (rec_zones['TXT'] if 'TXT' in rec_zones else []):
            if txt.lstrip('"').startswith('v=spf1'):
                matches = re.findall(
                    r'^(v=spf1)((\s+(include|ip4|ip6|a)(?:\\:(.[^\s]*))))*\s+((.)all)', txt, re.I)
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

    @classmethod
    def _parse_spf_machanism_all(self, mechanism, spf, spf_err):
        regex = "^(\+|-|~|\?|[^0-9-A-z]?)(all)$"
        matches = re.findall(regex, mechanism, re.I)
        # exit(matches)
        if len(matches) == 0:
            return (spf_err, False)

        qualifier = matches[0][0] if matches[0][0] else '+'
        val = matches[0][1]
        spf["all"] = {'errno': 0, 'errmsg': '+OK', 'data': []}
        spf['all']['data'].append((qualifier, self.spf_qualifier[qualifier]
                                   if qualifier in self.spf_qualifier else self.spf_qualifier['~~unknown~~'], val))
        #exit([qualifier, prefix, domain, spf])
        spf['__last:mechanism__'] = 'all'
        return (spf_err, True)


if __name__ == '__main__':

    spf_record = ('v=spf1 ~ip4:64.91.229.99 -ip6:2402:3a80:1224:6d81:ac62:11e1:1333:1f51/24 ?a:collax.com/34 *mx:rankwatch.collabx.com/32 -ptr:rankwatch.com  -exists:rankwatch.com ~include:rankwatch.com redirect=abcd.com ~all', 'collabx.com', '3600')
    parse_spf = network_tools.parse_spf(spf_record)
    exit()

    domain, nsserver = "collabx.com", 'ns.liquidweb.com'
    errmsg, all_records = network_tools.exec_host(domain, nsserver)
    # print(all_records)
    if errmsg:
        exit(errmsg)

    #
    zones = network_tools._parse_ns_query(domain, all_records)
    # exit([zones])
    #nsserver = None
    if nsserver is None and 'NS' in zones and len(zones['NS']):
        try:
            nsserver = random.choice(zones['NS'])[3]['A']
        except Exception as e:
            nsserver = random.choice(zones['NS'])[0]
    # die(zones)
    spf_record = network_tools.get_spf(zones)
    # exit(spf_record)
    parse_spf = network_tools.parse_spf(spf_record)

    domain_a = zones['A'][0]

    spf_records = network_tools._parse_spf_records(zones, domain_a)
    exit()
    #errmsg, all_records = network_tools.exec_host(domain, nsserver, nameonly=nameonly)

    # print(result)
    exit([domain, nsserver])
