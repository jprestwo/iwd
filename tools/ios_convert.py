#!/usr/bin/python3

import subprocess
import sys
import os
import argparse
from xml.etree import ElementTree

iwd_dir='/var/lib/iwd'
cert_path = None

description = '''
Convert iOS mobileconfig file to IWD format. Currently only TTLS and PEAP are
supported. Inner methods supported are PAP, CHAP, MSCHAP, MSCHAPv2.
'''

parser = argparse.ArgumentParser(description=description)
parser.add_argument('-i', '--input', nargs='?', required=True,
                        metavar='mobileconfig', help='iOS mobileconfig file')
parser.add_argument('-o', '--iwd-out', nargs='?', metavar='dir',
                        help='IWD configuration directory (default /var/lib/iwd)')
parser.add_argument('-c', '--cert-out', nargs='?', required=True,
                        metavar='cert', help='File to store new certificate')
parser.add_argument('-u', '--user', action='store_true',
                        help='Store username in provisioning file')
parser.add_argument('-p', '--passwd', action='store_true',
                        help='Store password (plaintext) in provisioning file')
parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')

args = parser.parse_args()

if args.iwd_out:
        iwd_dir = args.iwd_out

cert_path = os.path.abspath(args.cert_out)

with open(os.devnull, 'w') as devnull:
        proc = subprocess.Popen(['openssl', 'cms', '-in', args.input, '-inform',
                                'der', '-verify', '-noverify'],
                                stdout=subprocess.PIPE, stderr=devnull)

xml, err = proc.communicate()

if args.verbose:
        print(xml.decode("utf-8"))

subprocess.call(['openssl', 'cms', '-in', args.input, '-inform', 'der',
                '-outform', 'pem', '-noout', '-cmsout', '-certsout',
                args.cert_out])

xml = xml.decode('utf-8')

root = ElementTree.fromstring(xml)

class Network:
        def __init__(self):
                self.eap_types = []
                self.outer_id = None
                self.inner_eap = None
                self.nai_realms = []
                self.cert_path = None
                self.is_hotspot = False
                self.username = None
                self.password = None
                self.ssid = None

def process_eap_config(eap_conf, network):
        for m in range(len(eap_conf)):
                if eap_conf[m].text == "AcceptEAPTypes":
                        tarray = eap_conf[m + 1]
                        for i in range(len(tarray)):
                                network.eap_types.append(tarray[i].text)

                elif eap_conf[m].text == "TTLSInnerAuthentication":
                        network.inner_eap = eap_conf[m + 1].text
                elif eap_conf[m].text == "OuterIdentity":
                        network.outer_id = eap_conf[m + 1].text
                elif eap_conf[m].text == "UserName" and args.user:
                        network.username =  eap_conf[m + 1].text
                elif eap_conf[m].text == "UserPassword" and args.passwd:
                        network.password =  eap_conf[m + 1].text

def process_payload_array(parray):
        network = Network()

        for l in range(len(parray)):
                if parray[l].text == "NAIRealmNames":
                        nai_array = parray[l + 1]
                        for i in range(len(nai_array)):
                                network.nai_realms.append(nai_array[i].text)
                        continue
                elif parray[l].text == "IsHotspot":
                        if parray[l + 1].text == "True":
                                network.is_hotspot = True
                        else:
                                network.is_hotspot = False
                elif parray[l].text == "SSID_STR":
                        network.ssid = parray[l + 1].text
                elif parray[l].text == "EAPClientConfiguration":
                        process_eap_config(parray[l + 1], network)

        return network

def process_payload(payload):
        networks = []
        for k in range(len(payload)):
                if payload[k].tag != "dict":
                        continue

                n = process_payload_array(payload[k])
                if n:
                        networks.append(n)

        return networks

for i in range(len(root)):
        for j in range(len(root[i])):
                if root[i][j].text != "PayloadContent":
                        continue
                if (root[i][j + 1].tag != "array"):
                        continue

                payload = root[i][j + 1]
                nets = process_payload(payload)

def write_network(network):
        global cert_path
        output = ""
        eap = None

        # TODO: Handle multiple EAP types?
        if len(network.eap_types) < 1:
                print("Not configuring open network %s" % network.ssid)
                return

        if network.eap_types[0] == '21':
                eap = 'TTLS'
        elif network.eap_types[0] == '25':
                eap = 'PEAP'

        if not eap:
                print("TTLS or PEAP config was not found in XML")
                return

        if not network.inner_eap:
                print("No inner EAP method found in XML")
                return

        if network.is_hotspot and len(network.nai_realms) == 0:
                print("No NAI realms found in XML")
                return

        output = "[Security]\n"
        output += "EAP-Method=%s\n" % eap

        if network.outer_id:
                output += "EAP-Identity=%s\n" % network.outer_id

        if cert_path:
                output += "EAP-%s-CACert=%s\n" % (eap, cert_path)

        output += "EAP-%s-Phase2-Method=Tunneled-%s\n" % (eap, network.inner_eap)

        if network.username:
                output += "EAP-%s-Phase2-Identity=%s\n" % (eap, network.username)

        if network.password:
                output += "EAP-%s-Phase2-Password=%s\n" % (eap, network.password)

        if network.is_hotspot:
                conf_file = iwd_dir + '/hotspot/' + os.path.splitext(args.input)[0] + '.conf'
                output += "[Hotspot]\n"
                output += "NAIRealmNames="

                for i in range(len(network.nai_realms)):
                output += network.nai_realms[i]

                if i < len(network.nai_realms) - 1:
                        output += ','
        else:
                conf_file = iwd_dir + '/' + network.ssid + '.8021x'

        output += "\n"

        print("Provisioning network %s\n" % conf_file)

        if args.verbose:
                print(output)

        with open(conf_file, 'w+') as f:
                f.write(output)

for n in nets:
        write_network(n)
