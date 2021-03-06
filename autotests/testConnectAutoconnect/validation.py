#!/usr/bin/python3

import unittest
import sys

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import PSKAgent
from iwd import NetworkType

class TestConnectAutoconnect(unittest.TestCase):

    def check_connect(self, wd, device, ssid, throws):
        wd.wait(3);
        ordered_networks = device.get_ordered_networks()
        ordered_network = None

        for o_n in ordered_networks:
            if o_n.name == ssid:
                ordered_network = o_n
                break

        self.assertEqual(ordered_network.name, ssid)

        condition = 'not obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

        if not throws is None:
            with self.assertRaises(throws):
                ordered_network.network_object.connect()
            return
        else:
            try:
                ordered_network.network_object.connect()
            except:
                del wd
                raise

        condition = 'obj.connected'
        wd.wait_for_object_condition(ordered_network.network_object, condition)

    def check_autoconnect(self, wd, device, ssid, throws):
        wd.wait(3);

        if throws is None:
            condition = 'obj.state == DeviceState.connected'
            wd.wait_for_object_condition(device, condition)

            condition = 'obj.connected_network is not None'
            wd.wait_for_object_condition(device, condition)

            ordered_network = device.get_ordered_networks()[0]

            self.assertIsNotNone(ordered_network)
            self.assertEqual(ordered_network.name, ssid)
            self.assertTrue(ordered_network.network_object.connected)

            device.disconnect()

        condition = 'obj.state == DeviceState.disconnected'
        wd.wait_for_object_condition(device, condition)

    def validate(self, ssid, autoconnect, throws = None, use_agent = False):

        wd = IWD(True)
        wd.wait(1);

        if use_agent:
            psk_agent = PSKAgent("secret123")
            wd.register_psk_agent(psk_agent)

        devices = wd.list_devices();
        self.assertIsNotNone(devices)
        device = devices[0]

        if autoconnect:
            self.check_autoconnect(wd, device, ssid, throws)
        else:
            condition = 'not obj.scanning'
            wd.wait_for_object_condition(device, condition)

            device.scan()

            condition = 'not obj.scanning'
            wd.wait_for_object_condition(device, condition)

            self.check_connect(wd, device, ssid, throws)

        if use_agent:
            wd.unregister_psk_agent(psk_agent)

        del wd
