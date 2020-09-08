#!/usr/bin/python3
import os, os.path
import re
import socket
import select
import time
from gi.repository import GLib
from config import ctx

chan_freq_map = [
    None,
    2412,
    2417,
    2422,
    2427,
    2432,
    2437,
    2442,
    2447,
    2452,
    2457,
    2462,
    2467,
    2472,
    2484
]

ctrl_count = 0
mainloop = GLib.MainLoop()

class HostapdCLI:
    def _init_hostapd(self, config=None):
        global ctrl_count
        interface = None

        if not config and len(ctx.hostapd.instances) > 1:
            raise Exception('config must be provided if more than one hostapd instance exists')

        hapd = ctx.hostapd[config]

        self.interface = hapd.intf
        self.config = hapd.config

        if not self.interface:
            raise Exception('config %s not found' % config)

        self.ifname = self.interface.name
        self.socket_path = os.path.dirname(self.interface.ctrl_interface)

        self.cmdline = ['hostapd_cli', '-p', self.socket_path, '-i', self.ifname]
        #self.cmdline = 'hostapd_cli -p"' + self.socket_path + '" -i"' + \
        #        self.ifname + '"'

        if not hasattr(self, '_hostapd_restarted'):
            self._hostapd_restarted = False

        self.local_ctrl = '/tmp/hostapd_' + str(os.getpid()) + '_' + \
                            str(ctrl_count)
        self.ctrl_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.ctrl_sock.bind(self.local_ctrl)

        self.ctrl_sock.connect(self.socket_path + '/' + self.ifname)

        if 'OK' not in self._ctrl_request('ATTACH'):
            raise Exception('ATTACH failed')

        ctrl_count = ctrl_count + 1

    def __init__(self, config=None):
        self._init_hostapd(config)

    def wait_for_event(self, event, timeout=10):
        global mainloop
        self._wait_timed_out = False

        def wait_timeout_cb():
            self._wait_timed_out = True
            return False

        timeout = GLib.timeout_add_seconds(timeout, wait_timeout_cb)
        context = mainloop.get_context()

        while True:
            context.iteration(may_block=False)

            while self._data_available(0.25):
                data = self.ctrl_sock.recv(4096).decode('utf-8')
                if event in data:
                    GLib.source_remove(timeout)
                    return data

            if self._wait_timed_out:
                raise TimeoutError('waiting for hostapd event timed out')

        return None

    def _data_available(self, timeout=2):
        [r, w, e] = select.select([self.ctrl_sock], [], [], timeout)
        if r:
            return True
        return False

    def _ctrl_request(self, command, timeout=10):
        if type(command) is str:
            command = str.encode(command)

        self.ctrl_sock.send(bytes(command))

        if self._data_available(timeout):
            return self.ctrl_sock.recv(4096).decode('utf-8')

        raise Exception('timeout waiting for control response')

    def _del_hostapd(self, force=False):
        self.ctrl_sock.close()
        os.remove(self.local_ctrl)

        if self._hostapd_restarted:
            ctx.stop_process(ctx.hostapd.process, force)

            self.interface.set_interface_state('down')
            self.interface.set_interface_state('up')

    def __del__(self):
        self._del_hostapd()

    def wps_push_button(self):
        ctx.start_process(self.cmdline + ['wps_pbc'], wait=True)
        #os.system(self.cmdline + ' wps_pbc')

    def wps_pin(self, pin):
        cmd = self.cmdline + ['wps_pin', 'any', pin]
        ctx.start_process(cmd, wait=True)
        #os.system(self.cmdline + ' wps_pin any ' + pin)

    def deauthenticate(self, client_address):
        cmd = self.cmdline + ['deauthenticate', client_address]
        ctx.start_process(cmd, wait=True)
        #os.system(self.cmdline + ' deauthenticate ' + client_address)

    def eapol_reauth(self, client_address):
        cmd = 'IFNAME=' + self.ifname + ' EAPOL_REAUTH ' + client_address
        self.ctrl_sock.sendall(cmd.encode('utf-8'))

    def reload(self):
        # Seemingly all three commands needed for the instance to notice
        # interface's address change
        ctx.start_process(self.cmdline + ['reload'], wait=True)
        ctx.start_process(self.cmdline + ['disable'], wait=True)
        ctx.start_process(self.cmdline + ['enable'], wait=True)
        #cmds = 'reload\ndisable\nenable\n'
        #proc = os.popen(self.cmdline, mode='w')
        #lines = proc.write(cmds)
        #proc.close()

    def list_sta(self):
        proc = ctx.start_process(self.cmdline + ['list_sta'])
        proc.pid.wait()
        lines = proc.pid.stdout.read().decode('utf-8')
        #proc = os.popen(' '.join(self.cmdline) + ' list_sta')
        #lines = proc.read()
        #proc.close()
        #proc.pid.wait()

        return [line for line in lines.split('\n') if line]

    def set_neighbor(self, addr, ssid, nr):
        cmd = self.cmdline + ['set_neighbor', addr, 'ssid=\\""%s"\\"' % ssid, 'nr=%s' % nr]
        ctx.start_process(cmd, wait=True)
        #os.system(self.cmdline + ' set_neighbor ' + addr + ' ssid=\\""' + ssid +
        #            '"\\" nr=' + nr)

    def send_bss_transition(self, device, nr_list):
        # Send a BSS transition to a station (device). nr_list should be an
        # array of tuples containing the BSS address and neighbor report.
        # Parsing the neighbor report is a bit ugly but it makes it more
        # consistent with the set_neighbor() API, i.e. the same neighbor report
        # string could be used in both API's.
        pref = 1
        cmd = self.cmdline + ['bss_tm_req', device]
        #cmd = self.cmdline + ' bss_tm_req ' + device
        for i in nr_list:
            addr = i[0]
            nr = i[1]

            bss_info=str(int(nr[0:8], 16))
            op_class=str(int(nr[8:10], 16))
            chan_num=nr[10:12]
            phy_num=nr[14:16]

            #cmd += ' pref=%s neighbor=%s,%s,%s,%s,%s' % \
            #        (str(pref), addr, bss_info, op_class, chan_num, phy_num)
            cmd += ['pref=%s' % str(pref), 'neighbor=%s,%s,%s,%s,%s' % (addr, bss_info, op_class, chan_num, phy_num)]
            pref += 1

        #os.system(cmd)
        ctx.start_process(cmd, wait=True)

    def get_config_value(self, key):
        # first find the right config file
        with open(self.config, 'r') as f:
            # read in config file and search for key
            cfg = f.read()
            match = re.search(r'%s=.*' % key, cfg)
            if match:
                return match.group(0).split('=')[1]
        return None


    def get_freq(self):
        return chan_freq_map[int(self.get_config_value('channel'))]

    def ungraceful_restart(self):
        '''
            Ungracefully kill and restart hostapd
        '''
        # set flag so hostapd can be killed after the test
        self._hostapd_restarted = True

        self._del_hostapd(force=True)

        ctx.start_hostapd()

        # Give hostapd a second to start and initialize the control interface
        time.sleep(1)

        # New hostapd process, so re-init
        self._init_hostapd(config=self.config)

    def req_beacon(self, addr, request):
        '''
            Send a RRM Beacon request
        '''
        cmd = self.cmdline + ['req_beacon', addr, request]
        ctx.start_process(cmd, wait=True)
        #os.system(self.cmdline + ' req_beacon ' + addr + ' ' + request)
