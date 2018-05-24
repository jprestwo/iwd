#!/usr/bin/python3
import os, os.path
import wiphy
import dbus
from gi.repository import GLib

class WpaSupplicant:
    def __init__(self, interface):
        self.ifname = interface.name
        self._bus = dbus.SystemBus()

        for service in dbus.SystemBus().list_names():
            print(service)

        wpas_obj = self._bus.get_object('fi.w1.wpa_supplicant1', '/fi/w1/wpa_supplicant1/Interfaces/1')
        wpas = dbus.Interface(wpas_obj, 'fi.w1.wpa_supplicant1')

        #path = wpas.GetInterface(self.ifname)

        #if_obj = bus.get_object('fi.w1.wpa_supplicant1', path)

        #iface = dbus.Interface(if_obj, fi.w1.wpa_supplicant1.Interface)

        self._bus.add_signal_receiver(self.PropertiesChanged, dbus_interface='fi.w1.wpa_supplicant1.Interface', signal_name='PropertiesChanged')


        #self._iface.connect_to_signal('PropertiesChanged',
        #                                     self._props_changed)
        #print(str(iface.Introspect()))

        #iface.GetInterface(self.ifname)

        #print(str(iface))
        #interfaces = props_iface.Get('fi.w1.wpa_supplicant1', "Interfaces")

        #print(str(interfaces))
        #self._wpa_iface = dbus.Interface(obj)

        #print(str(obj.Introspect()))

        #print(self._wpa_iface.GetInterface(self.ifname))

        #self.ctrl_interface = interface.ctrl_interface

        #socket_path = os.path.dirname(self.ctrl_interface)

        #self.cmdline = 'wpa_cli -p"' + socket_path + '" -i"' + \
        #        self.ifname + '"'
    def PropertiesChanged(self, args):
        print("\n\nPROPS CHANGED\n\n")

    def _props_changed(self, dict):
        print("\n\n\nCHANGED\n\n\n");
        print(str(dict))

    def get_status(self):
        proc = os.popen(self.cmdline + ' status')
        lines = proc.read()
        proc.close()

        return lines

    def check_status(self, key, cond):
        data = self.get_status().split('\n')
        for elem in data:
            if elem == '':
                continue

            k, value = elem.split('=')

            if k == key and value == cond:
                return True

        return False

    def wait_for_condition(self, key, cond, max_wait = 15):
            mainloop = GLib.MainLoop()

            # Check if condition is already met
            if self.check_status(key, cond) == True:
                    return

            self._wait_timed_out = False
            self._condition_met = False
            def poll_timeout_cb():
                    if self.check_status(key, cond) == True:
                            self._condition_met = True
                            return False
                    return True

            def wait_timeout_cb():
                self._wait_timed_out = True
                return False

            timeout = GLib.timeout_add_seconds(max_wait, wait_timeout_cb)
            poll = GLib.timeout_add_seconds(0.2, poll_timeout_cb)
            context = mainloop.get_context()
            while (not self._condition_met):
                context.iteration(may_block=True)
                if self._wait_timed_out:
                    raise TimeoutError('waiting for %s=%s timed out' % (key, cond))

            GLib.source_remove(timeout)
            GLib.source_remove(poll)
