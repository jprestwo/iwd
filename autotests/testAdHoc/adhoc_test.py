#!/usr/bin/python3

import unittest
import sys
import time

sys.path.append('../util')
import iwd
from iwd import IWD
from iwd import NetworkType
from time import sleep
from wpa_supplicant import WpaSupplicant
from wiphy import wiphy_map
import os

class Test(unittest.TestCase):

    def test_connection_success(self):
        '''
        wpa_s = None

        for wname in wiphy_map:
            wiphy = wiphy_map[wname]
            intf = list(wiphy.values())[0]
            if intf.use == 'wpa_supp':
                wpa_s = WpaSupplicant(intf)
                break

        #wpa_s.get_status()
        '''



        wd = IWD(True)
        wd.wait(2)


        dev1, dev2 = wd.list_devices(True)

        print(str(dev1))
        print(str(dev2))


        self.assertIsNotNone(dev1)
        self.assertIsNotNone(dev2)

        print("Starting adhoc on dev1")
        dev1.start_adhoc("AdHocNetwork", "secret123")
        sleep(1)
        print("Starting adhoc on dev2")
        dev2.start_adhoc("AdHocNetwork", "secret123")

        sleep(30);
        #wpa_s.wait_for_condition("wpa_state", "COMPLETED")

        #wpa_s.get_status()


    @classmethod
    def setUpClass(cls):
        print("setup")

    @classmethod
    def tearDownClass(cls):
        IWD.clear_storage()

if __name__ == '__main__':
    unittest.main(exit=True)
