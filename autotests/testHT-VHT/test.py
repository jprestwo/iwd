#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hwsim import Hwsim
from hostapd import HostapdCLI
from wiphy import wiphy_map
import testutil
import os

class Test(unittest.TestCase):
    def test_roam_success(self):
        os.system("iw reg get")
        #os.system("iw reg set US")

        hwsim = Hwsim()
        non_ht_hostapd = None
        ht_hostapd = None
        non_ht_radio = None
        ht_radio = None
        vht_radio = None

        for wname in wiphy_map:
            wiphy = wiphy_map[wname]
            intf = list(wiphy.values())[0]
            print(intf)
            if intf.config and intf.config == 'non-ht-vht.conf':
                non_ht_hostapd = HostapdCLI(intf)

                for path in hwsim.radios:
                    radio = hwsim.radios[path]
                    if radio.name == wname:
                        non_ht_radio = radio

            elif intf.config and intf.config == 'ht.conf':
                ht_hostapd = HostapdCLI(intf)

                for path in hwsim.radios:
                    radio = hwsim.radios[path]
                    if radio.name == wname:
                        ht_radio = radio
            elif intf.config and intf.config == 'vht.conf':
                vht_hostapd = HostapdCLI(intf)

                for path in hwsim.radios:
                    radio = hwsim.radios[path]
                    if radio.name == wname:
                        vht_radio = radio
            else:
                continue


        self.assertIsNotNone(non_ht_hostapd)
        self.assertIsNotNone(ht_hostapd)
        self.assertIsNotNone(vht_hostapd)

        rule0 = hwsim.rules.create()
        rule0.source = vht_radio.addresses[0]
        rule0.bidirectional = True
        rule0.signal = -7100

        wd = IWD()

        psk_agent = PSKAgent("secret123")
        wd.register_psk_agent(psk_agent)

        device = wd.list_devices(1)[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'obj.scanning'
        wd.wait_for_object_condition(device, condition)

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('testSSID')

        self.assertEqual(ordered_network.type, NetworkType.psk)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected()

        self.assertIn(device.address, ht_hostapd.list_sta())

        device.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
