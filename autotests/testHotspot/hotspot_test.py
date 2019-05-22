#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
from hostapd import HostapdCLI
from hwsim import Hwsim
import testutil
import os

class Test(unittest.TestCase):

    def test_connection_success(self):
        hwsim = Hwsim()

        hapd = HostapdCLI(config='ssidHotspot.conf')
        hapd_drop = HostapdCLI(config='ssidHotspotDrop.conf')

        rad0 = hwsim.get_radio('rad1')
        rad1 = hwsim.get_radio('rad2')

        rule0 = hwsim.rules.create()
        rule0.source = rad0.addresses[0]
        rule0.bidirectional = True

        rule1 = hwsim.rules.create()
        rule1.source = rad1.addresses[0]
        rule1.bidirectional = True

        rule0.signal = -2000
        # IWD will first try the broken AP
        rule1.signal = -3000

        wd = IWD()

        psk_agent = PSKAgent('abc', ('domain\\user', 'testpasswd'))
        wd.register_psk_agent(psk_agent)

        devices = wd.list_devices(1)
        device = devices[0]

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        device.scan()

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(device, condition)

        ordered_network = device.get_ordered_network('Hotspot')

        self.assertEqual(ordered_network.type, NetworkType.eap)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        #rule0.drop = True
        #rule1.drop = True

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        testutil.test_iface_operstate()
        testutil.test_ifaces_connected(device.name, hapd.ifname, group=False)

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
