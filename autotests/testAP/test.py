#! /usr/bin/python3

import unittest
import sys, os

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType
import hostapd
import testutil

class Test(unittest.TestCase):

    def client_connect(self, wd, dev):
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev, condition)

        if not dev.get_ordered_networks():
            dev.scan()
            condition = 'obj.scanning'
            wd.wait_for_object_condition(dev, condition)
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(dev, condition)

        ordered_networks = dev.get_ordered_networks()
        self.assertEqual(len(ordered_networks), 1)
        ordered_network = ordered_networks[0]
        self.assertEqual(ordered_network.name, 'TestAP1')
        self.assertEqual(ordered_network.type, NetworkType.psk)

        psk_agent = PSKAgent('Password1')
        wd.register_psk_agent(psk_agent)

        ordered_network.network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        wd.unregister_psk_agent(psk_agent)

        testutil.test_iface_operstate(dev.name)
        testutil.test_ifaces_connected(list(hostapd.hostapd_map.keys())[0],
                                       dev.name)

        self.assertRaises(iwd.dbus.DBusException, dev.start_ap,
                          'TestAP2', 'Password2')

        dev.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def test_connection_success(self):
        wd = IWD()

        dev1, dev2 = wd.list_devices()

        self.client_connect(wd, dev1)

        dev1.start_ap('TestAP2', 'Password2')

        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev2, condition)
        dev2.scan()
        condition = 'obj.scanning'
        wd.wait_for_object_condition(dev2, condition)
        condition = 'not obj.scanning'
        wd.wait_for_object_condition(dev2, condition)

        ordered_networks = dev2.get_ordered_networks()
        self.assertEqual(len(ordered_networks), 2)
        networks = { n.name: n for n in ordered_networks }
        self.assertEqual(networks['TestAP1'].type, NetworkType.psk)
        self.assertEqual(networks['TestAP2'].type, NetworkType.psk)

        psk_agent = PSKAgent('Password2')
        wd.register_psk_agent(psk_agent)

        try:
            dev2.disconnect()
            condition = 'not obj.connected'
            wd.wait_for_object_condition(dev2, condition)
        except:
            pass

        networks['TestAP2'].network_object.connect()

        condition = 'obj.connected'
        wd.wait_for_object_condition(networks['TestAP2'].network_object,
                                     condition)

        # TODO: This is here to work around a race condition where the station
        #       shows connected but the AP has not yet finished adding the new
        #       station yet. This will be fixed once a proper AP interface is
        #       implemented that has some way of notifying when a station has
        #       been added e.g. "ConnectedPeers" property or "PeerAdded" signal.

        retries = 0

        while retries < 3:
            try:
                testutil.test_iface_operstate(dev2.name)
                testutil.test_ifaces_connected(dev1.name, dev2.name)
                break
            except:
                retries += 1
                continue

        wd.unregister_psk_agent(psk_agent)

        dev2.disconnect()

        condition = 'not obj.connected'
        wd.wait_for_object_condition(networks['TestAP2'].network_object,
                                     condition)

        dev1.stop_ap()

        # Finally test dev1 can go to client mode and connect again
        self.client_connect(wd, dev1)

    @classmethod
    def setUpClass(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
