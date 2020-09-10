#!/bin/python3

import argparse
import os
import shutil
import ctypes
import fcntl
import shlex
import sys
import subprocess
import atexit
import time
import unittest
import importlib
import signal
import pyroute2
import multiprocessing
import re

from configparser import ConfigParser
from prettytable import PrettyTable
from termcolor import colored
from glob import glob
from collections import namedtuple
from time import sleep
import dbus.mainloop.glib
from gi.repository import GLib

libc = ctypes.cdll['libc.so.6']
libc.mount.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, \
			ctypes.c_ulong, ctypes.c_char_p)

# Using ctypes to load the libc library is somewhat low level. Because of this
# we need to define our own flags/options for use with mounting.
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_STRICTATIME = 1 << 24
STDIN_FILENO = 0
TIOCSTTY = 0x540E

config = None
intf_id = 0
rad_id = 0

TEST_MAX_TIMEOUT = 45

dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

def dbg(*s):
	'''
		Allows prints if stdout has been re-directed
	'''
	print(*s, file=sys.__stdout__)

def exit_vm():
	if config:
		for p in config.ctx.processes:
			print("Process %s still running!" % p.name)

	os.sync()

	RB_AUTOBOOT = 0x01234567
	#
	# Calling 'reboot' or 'shutdown' from a shell (e.g. os.system('reboot'))
	# is not the same the POSIX reboot() and will cause a kernel panic since
	# we are the init process. The libc.reboot() allows the VM to exit
	# gracefully.
	#
	libc.reboot(RB_AUTOBOOT)

def path_exists(path):
	'''
		Searches PATH as well as absolute paths.
	'''
	if shutil.which(path):
		return True
	try:
		os.stat(path)
	except:
		return False
	return True

def find_binary(list):
	'''
		Returns a binary from 'list' if its found in PATH or on a
		valid absolute path.
	'''
	for path in list:
		if path_exists(path):
			return path
	return None

def mount(source, target, fs, flags, options=''):
	'''
		Python wrapper for libc mount()
	'''
	ret = libc.mount(source.encode(), target.encode(), fs.encode(), flags,
				options.encode())
	if ret < 0:
		errno = ctypes.get_errno()
		raise Exception("Could not mount %s (%d)" % (target, errno))

MountInfo = namedtuple('MountInfo', 'fstype target options flags')

mount_table = [
	MountInfo('sysfs', '/sys', '', MS_NOSUID|MS_NOEXEC|MS_NODEV),
	MountInfo('proc', '/proc', '', MS_NOSUID|MS_NOEXEC|MS_NODEV),
	MountInfo('devpts', '/dev/pts', 'mode=0620', MS_NOSUID|MS_NOEXEC),
	MountInfo('tmpfs', '/dev/shm', 'mode=1777', MS_NOSUID|MS_NODEV|MS_STRICTATIME),
	MountInfo('tmpfs', '/run', 'mode=0755', MS_NOSUID|MS_NODEV|MS_STRICTATIME),
	MountInfo('tmpfs', '/var/lib/iwd', 'mode=0755', 0),
	MountInfo('tmpfs', '/tmp', '', 0),
	MountInfo('tmpfs', '/usr/share/dbus-1', 'mode=0755', MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME),
	MountInfo('debugfs', '/sys/kernel/debug', '', 0)
]

DevInfo = namedtuple('DevInfo', 'target linkpath')

dev_table = [
	DevInfo('/proc/self/fd', '/dev/fd'),
	DevInfo('/proc/self/fd/0', '/dev/stdin'),
	DevInfo('/proc/self/fd/1', '/dev/stdout'),
	DevInfo('/proc/self/fd/2', '/dev/stderr')
]

dbus_config = '''
<!DOCTYPE busconfig PUBLIC \
"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" \
"http://www.freedesktop.org/standards/dbus/1.0/\
busconfig.dtd\">
<busconfig>
<type>system</type>
<listen>unix:path=/run/dbus/system_bus_socket</listen>
<limit name=\"reply_timeout\">2147483647</limit>
<auth>ANONYMOUS</auth>
<allow_anonymous/>
<policy context=\"default\">
<allow user=\"*\"/>
<allow own=\"*\"/>
<allow send_type=\"method_call\"/>
<allow send_type=\"signal\"/>
<allow send_type=\"method_return\"/>
<allow send_type=\"error\"/>
<allow receive_type=\"method_call\"/>
<allow receive_type=\"signal\"/>
<allow receive_type=\"method_return\"/>
<allow receive_type=\"error\"/>
</policy>
</busconfig>
'''
class Process:
	'''
		Start a process. If 'wait' is True the constructor will start
		the process and wait for it to exit. No PID is tracked in this
		case. If 'multi_test' is True this indicates the process is
		run over the entire test run and will not be killed after each
		test exits.
	'''
	def __init__(self, args, wait=False, multi_test=False, env=None, ctx=None, check=False):
		self.args = args
		self.wait = wait
		self.name = args[0]
		self.multi_test = multi_test
		self.stdout = subprocess.PIPE
		self.stderr = subprocess.PIPE
		self.ret = None
		self.ctx = ctx

		if ctx:
			set_stdout = False

			if ctx.is_verbose(args[0]):
				dbg("Verbose on for %s" % args[0])
				set_stdout = True

			if os.path.basename(args[0]) == ctx.args.gdb:
				self.args = ['gdb', '--args']
				self.args.extend(args)
				set_stdout = True

			# Anything labeled as multi_test isn't important to
			# log. These are processes such as dbus-daemon and
			# haveged.
			if set_stdout:
				if ctx.args.log:
					test = os.path.basename(os.getcwd())
					test_dir = '%s/%s' % (ctx.args.log, test)

					if not path_exists(test_dir):
						os.mkdir(test_dir)
						os.chown(test_dir, int(ctx.args.log_uid), \
								int(ctx.args.log_gid))

					self.stdout = open('%s/%s' % (test_dir, args[0]), 'w')
					self.stderr = open('%s/%s' % (test_dir, args[0]), 'w')
				else:
					self.stdout = sys.__stdout__
					self.stderr = sys.__stderr__

		if not wait and not check:
			self.pid = subprocess.Popen(self.args, stdout=self.stdout, \
							stderr=self.stderr, env=env, \
							cwd=os.getcwd())
			print("Starting process {}".format(self.pid.args))
		else:
			self.ret = subprocess.call(self.args, stdout=self.stdout, \
							stderr=self.stderr)
			print("%s returned %d" % (args[0], self.ret))
			if check and self.ret != 0:
				raise subprocess.CalledProcessError(returncode=self.ret, cmd=self.args)

	def __del__(self):
		print("Del process %s" % self.args)
		if self.ctx and self.ctx.args.log:
			self.stdout.close()
			self.stderr.close()

	def kill(self, force=False):
		print("Killing process %s" % self.args)

		if force:
			os.kill(self.pid.pid, signal.SIGKILL)
		else:
			self.pid.kill()

		self.pid.wait(timeout=15)

	def wait_for_socket(self, socket, wait):
		waited = 0
		while not os.path.exists(socket):
			sleep(0.5)
			waited += 0.5
			if waited > wait:
				raise Exception("Timed out waiting for socket")

class Interface:
	def __init__(self, name, config):
		self.name = name
		self.ctrl_interface = '/var/run/hostapd/' + name
		self.config = config

	def __del__(self):
		Process(['iw', 'dev', self.name, 'del'], True)

	def set_interface_state(self, state):
		Process(['ifconfig', self.name, state], True)

class Radio:
	def __init__(self, name):
		self.name = name
		# hostapd will reset this if this radio is used by it
		self.use = 'iwd'
		self.interface = None

	def __del__(self):
		print("Removing radio %s" % self.name)
		self.interface = None

	def create_interface(self, hapd):
		global intf_id

		ifname = 'wln%s' % intf_id

		intf_id += 1

		self.interface = Interface(ifname, hapd.config)
		# IWD does not use interfaces in test-runner so any created
		# interface is assumed to be used by hostapd.
		self.use = 'hostapd'

		Process(['iw', 'phy', self.name, 'interface', 'add', ifname,
				'type', 'managed'], True)

		return self.interface

	def __str__(self):
		ret = self.name + ':\n'
		ret += '\tUsed By: %s ' % self.use
		if self.interface:
			ret += '(%s)' % self.interface.name

		ret += '\n'

		return ret

class VirtualRadio(Radio):
	'''
		A subclass of 'Radio' specific to mac80211_hwsim radios.

		TODO: Using D-Bus to create and destroy radios is more desireable
		than the command line.
	'''
	def __init__(self, name, config=None):
		global rad_id

		super().__init__(name)

		self.disable_cipher = None
		self.disable_iftype = None

		args = ['hwsim', '--create', '--name', self.name, '--nointerface']

		if config:
			self.disable_iftype = config.get('iftype_disable', False)
			if self.disable_iftype:
				args.append('--iftype-disable')
				args.append(self.disable_iftype)

			self.disable_cipher = config.get('cipher_disable', False)
			if self.disable_cipher:
				args.append('--cipher-disable')
				args.append(self.disable_cipher)

		Process(args, wait=True)

		self.id = rad_id
		rad_id += 1

	def __del__(self):
		super().__del__()

		Process(['hwsim', '--destroy=%s' % self.id])

	def __str__(self):
		ret = super().__str__()

		if self.disable_iftype:
			ret += '\tDisabled interface types: %s\n' % self.disable_iftype

		if self.disable_cipher:
			ret += '\tDisabled ciphers: %s\n' % self.disable_cipher

		ret += '\n'

		return ret

class HostapdInstance:
	'''
		A single instance of hostapd. In reality all hostapd instances
		are started as a single process. This class just makes things
		convenient for communicating with one of the hostapd APs.
	'''
	def __init__(self, config, radio):
		self.radio = radio
		self.config = config

		self.intf = radio.create_interface(self)
		self.intf.set_interface_state('up')

	def __del__(self):
		print("Removing HostapdInstance %s" % self.config)
		self.intf.set_interface_state('down')
		self.radio = None
		self.intf = None

	def __str__(self):
		ret = 'Hostapd (%s)\n' % self.intf.name
		ret += '\tConfig: %s\n' % self.config

		return ret

class Hostapd:
	'''
		A set of running hostapd instances. This is really just a single
		process since hostapd can be started with multiple config files.
	'''
	def __init__(self, ctx, radios, configs, radius):
		if len(configs) != len(radios):
			raise Exception("Config (%d) and radio (%d) list length not equal" % \
						(len(configs), len(radios)))

		print("Initializing hostapd instances")

		self.global_ctrl_iface = '/var/run/hostapd/ctrl'

		self.instances = [HostapdInstance(c, r) for c, r in zip(configs, radios)]

		ifaces = [rad.interface.name for rad in radios]
		ifaces = ','.join(ifaces)

		args = ['hostapd', '-i', ifaces, '-g', self.global_ctrl_iface]

		#
		# Config files should already be present in /tmp. This appends
		# ctrl_interface and does any variable replacement. Currently
		# this is just any $ifaceN occurrences.
		#
		for c in configs:
			full_path = '/tmp/%s' % c
			args.append(full_path)

			self._rewrite_config(full_path)

		if radius:
			args.append(radius)

		if ctx.is_verbose('hostapd'):
			args.append('-d')

		self.process = ctx.start_process(args)

		self.process.wait_for_socket(self.global_ctrl_iface, 30)

	def _rewrite_config(self, config):
		'''
			Replaces any $ifaceN values with the correct interface
			names as well as appends the ctrl_interface path to
			the config file.
		'''
		with open(config, 'r+') as f:
			data = f.read()
			to_replace = []
			for match in re.finditer(r'\$iface[0-9]+', data):
				tag = data[match.start():match.end()]
				idx = tag.split('iface')[1]

				to_replace.append((tag, self.instances[int(idx)].intf.name))

			for r in to_replace:
				data = data.replace(r[0], r[1], 1)

			data += '\nctrl_interface=/var/run/hostapd\n'

			f.write(data)

	def __getitem__(self, config):
		if not config:
			return self.instances[0]

		for hapd in self.instances:
			if hapd.config == config:
				return hapd

		return None

	def __del__(self):
		print("Removing Hostapd")
		try:
			os.remove(self.global_ctrl_iface)
		except:
			dbg("Failed to remove %s" % self.global_ctrl_iface)

		self.instances = None
		self.process.kill()

class TestContext:
	'''
		Contains all information for a given set of tests being run
		such as processes, radios, interfaces and test results.
	'''
	def __init__(self, args):
		self.processes = []
		self.args = args
		self.hw_config = None
		self.hostapd = None
		self.cur_radio_id = 0
		self.cur_iface_id = 0
		self.radios = []
		self.loopback_started = False
		self.iwd_extra_options = None
		self.results = {}
		self.mainloop = GLib.MainLoop()

	def start_process(self, args, wait=False, multi_test=False, env=None, check=False):
		p = Process(args, wait, multi_test, env, ctx=self, check=check)

		if not wait:
			self.processes.append(p)

		return p

	def start_dbus(self):
		with open('/usr/share/dbus-1/system.conf', 'w+') as f:
			f.write(dbus_config)

		os.mkdir('/run/dbus', 755)

		self.start_process(['dbus-daemon', '--system', '--nosyslog'], multi_test=True)

	def start_dbus_monitor(self):
		if not self.is_verbose('dbus-monitor'):
			return

		self.start_process(['dbus-monitor', '--system'])

	def start_haveged(self):
		self.start_process(['haveged'], multi_test=True)

	def create_radios(self):
		setup = self.hw_config['SETUP']
		nradios = int(setup['num_radios'])

		for i in range(nradios):
			name = 'rad%u' % i

			# Get any [radX] sections. These are for configuring
			# any special radios. This no longer requires a
			# radio_conf list, we just assume radios start rad0
			# and increment.
			rad_config = None
			if self.hw_config.has_section(name):
				rad_config = self.hw_config[name]

			self.radios.append(VirtualRadio(name, rad_config))
			self.cur_radio_id += 1

		# register hwsim as medium
		self.start_process(['hwsim'])

	def discover_radios(self):
		phys = []
		iw = pyroute2.iwutil.IW()

		attrs = [phy['attrs'] for phy in iw.list_wiphy()]

		for attr in attrs:
			for key, value in attr:
				if key == 'NL80211_ATTR_WIPHY_NAME':
					if value not in phys:
						phys.append(value)
					break

		print('Discovered radios: %s' % str(phys))
		self.radios = [Radio(name) for name in phys]

	def start_radios(self):
		reg_domain = self.hw_config['SETUP'].get('reg_domain', None)
		if reg_domain:
			Process(['iw', 'reg', 'set', reg_domain], True)

		if self.args.hw:
			self.discover_radios()
		else:
			self.create_radios()

	def start_iwd(self, config_dir = '/tmp'):
		args = []
		iwd_radios = ','.join([r.name for r in self.radios if r.use == 'iwd'])

		if self.args.valgrind:
			args.extend(['valgrind', '--leak-check=full', '--log-file=%s' % \
					'/tmp/valgrind.log'])

		args.extend(['iwd', '-p', iwd_radios])

		if self.is_verbose(args[0]):
			args.append('-d')

		if self.iwd_extra_options:
			args.append(self.iwd_extra_options)

		env = os.environ.copy()
		env['CONFIGURATION_DIRECTORY'] = config_dir
		env['STATE_DIRECTORY'] = '/var/lib/iwd'

		pid = self.start_process(args, env=env)
		return pid

	def start_hostapd(self):
		if not 'HOSTAPD' in self.hw_config:
			return

		settings = self.hw_config['HOSTAPD']

		if self.args.hw:
			# Just grab the first N radios. It gets rather
			# complicated trying to map radX radios specified in
			# hw.conf so any passed through physical adapters are
			# just given to hostapd/IWD as they appear during
			# discovery.
			#
			# TODO: It may be desireable to map PCI/USB adapters to
			#       specific radX radios specified in the config but
			#       there are really 2 separate use cases here.
			#       1. You want to test a *specific* radio with IWD
			#          or hostapd. For this you would want radX
			#          to map to a specific radio
			#       2. You have many adapters in use to run multiple
			#          tests. In this case you would not care what
			#          was using each radio, just that there was
			#          enough to run all tests.
			nradios = 0
			for k, _ in settings.items():
				if k == 'radius_server':
					continue
				nradios += 1

			hapd_radios = self.radios[:nradios]

		else:
			hapd_radios = [rad for rad in self.radios if rad.name in settings]

		hapd_configs = [conf for rad, conf in settings.items() if rad != 'radius_server']

		radius_config = settings.get('radius_server', None)

		self.hostapd = Hostapd(self, hapd_radios, hapd_configs, radius_config)

	def start_ofono(self):
		sim_keys = self.hw_config['SETUP'].get('sim_keys', None)
		if not sim_keys:
			print("Ofono not requred")
			return
		elif sim_keys != 'ofono':
			os.environ['IWD_SIM_KEYS'] = sim_keys
			self.iwd_extra_options = '--plugin=sim_hardcoded'
			return

		if not find_binary(['ofonod']) or not find_binary(['phonesim']):
			print("Ofono or Phonesim not found, skipping test")
			return

		Process(['ifconfig', 'lo', 'up'], wait=True)

		self.iwd_extra_options = '--plugin=ofono'

		os.environ['OFONO_PHONESIM_CONFIG'] = '/tmp/phonesim.conf'

		phonesim_args = ['phonesim', '-p', '12345', '/usr/share/phonesim/default.xml']

		self.start_process(phonesim_args)

		#
		# TODO:
		# Is there something to wait for? Without this phonesim rejects
		# connections on all but the fist test.
		#
		time.sleep(3)

		ofono_args = ['ofonod', '-n', '--plugin=atmodem,phonesim']
		if self.is_verbose('ofonod'):
			ofono_args.append('-d')

		self.start_process(ofono_args)

		print("Ofono started")

	def is_verbose(self, process):
		process = os.path.basename(process)

		if self.args is None:
			return False

		# every process is verbose when logging is enabled
		if self.args.log:
			return True

		if process in self.args.verbose:
			return True

		# Special case here to enable verbose output with valgrind running
		if process == 'valgrind' and 'iwd' in self.args.verbose:
			return True

		# Handle any glob matches
		for item in self.args.verbose:
			if process in glob(item):
				return True

		return False

	def stop_process(self, p, force=False):
		p.kill(force)
		self.processes.remove(p)

	def stop_test_processes(self):
		self.radios = []
		self.hostapd = None
		self.iwd_extra_options = None

		for p in [p for p in self.processes if p.multi_test is False]:
			print("Killing process %s" % p.name)
			self.stop_process(p)

	def is_process_running(self, process):
		for p in self.processes:
			if p.name == process:
				return True
		return False

	def __str__(self):
		ret = 'Arguments:\n'
		for arg in vars(self.args):
			ret += '\t --%s %s\n' % (arg, str(getattr(self.args, arg)))

		ret += 'Processes:\n'
		for p in self.processes:
			ret += '\t%s\n' % str(p.args)

		ret += 'Radios:\n'
		if len(self.radios) > 0:
			for r in self.radios:
				ret += '\t%s\n' % str(r)
		else:
			ret += '\tNo Radios\n'

		ret += 'Hostapd:\n'
		if self.hostapd:
			for h in self.hostapd.instances:
				ret += '\t%s\n' % str(h)
		else:
			ret += '\tNo Hostapd instances\n'

		return ret

def prepare_sandbox():
	print('Preparing sandbox')

	for entry in mount_table:
		try:
			os.lstat(entry.target)
		except:
			os.mkdir(entry.target, 755)

		mount(entry.fstype, entry.target, entry.fstype, entry.flags,
			entry.options)

	for entry in dev_table:
		os.symlink(entry.target, entry.linkpath)

	os.setsid()

	fcntl.ioctl(STDIN_FILENO, TIOCSTTY, 1)

def build_unit_list(args):
	'''
		Build list of unit tests based on passed arguments. This first
		checks for literal names provided in the arguments, then if
		no matches were found, checks for a glob match.
	'''
	tests = []
	test_root = args.testhome + '/unit'

	for unit in args.unit_tests.split(','):
		path = '%s/%s' % (test_root, unit)
		if os.access(unit, os.X_OK):
			tests.append(unit)
		elif os.access(path, os.X_OK):
			tests.append(path)
		else:
			# Full list or glob, first build up valid list of tests
			matches = glob(path)
			if matches == []:
				raise Exception("Could not find test %s" % unit)

			matches = [exe for exe in matches if os.access(exe, os.X_OK)]

			tests.extend(matches)

	return sorted(tests)

def build_test_list(args):
	'''
		Build list of auto test directories based on passed arguments.
		First check for absolute paths, then look in <iwd>/autotests,
		then glob match.
	'''
	tests = []
	test_root = args.testhome + '/autotests'

	# Run all tests
	if not args.auto_tests:
		# --shell with no tests implies 'shell' test
		if args.shell:
			return [test_root + '/shell']

		tests = os.listdir(test_root)
		# Pair down any non-tests and append full path
		tests = [test_root + '/' + t for t in tests if t.startswith('test')]
	else:
		print("Generating partial test list")
		for t in args.auto_tests.split(','):
			path = '%s/%s' % (test_root, t)
			# Full test path specified
			if os.path.exists(t):
				tests.append(t)
			elif os.path.exists(path):
				tests.append(path)
			else:
				matches = glob(path)
				if matches == []:
					raise Exception("Could not find test %s" % t)

				tests.extend(matches)

	return sorted(tests)

SimpleResult = namedtuple('SimpleResult', 'run failures errors skipped time')

def start_test(ctx, subtests, rqueue):
	'''
		Run an individual test. 'subtests' are parsed prior to calling
		but these effectively make up a single test. 'rqueue' is the
		results queue which is required since this is using
		multiprocessing.
	'''
	suite = unittest.TestSuite()

	#
	# Iterate through each individual python test.
	#
	for s in subtests:
		loader = unittest.TestLoader()
		subtest = importlib.import_module(os.path.splitext(s)[0])
		suite.addTests(loader.loadTestsFromModule(subtest))

		# Prevents future test modules with the same name (e.g.
		# connection_test.py) from being loaded from the cache
		sys.modules.pop(subtest.__name__)

	start = time.time()
	runner = unittest.TextTestRunner()
	result = runner.run(suite)
	#
	# The multiprocessing queue is picky with what objects it will serialize
	# and send between processes. Because of this we put the important bits
	# of the result into our own 'SimpleResult' tuple.
	#
	sresult = SimpleResult(run=result.testsRun, failures=len(result.failures),
				errors=len(result.errors), skipped=len(result.skipped),
				time=time.time() - start)
	rqueue.put(sresult)

	# This may not be required since we are manually popping sys.modules
	importlib.invalidate_caches()

def pre_test(ctx, test):
	'''
		Copy test files, start processes, and any other pre test work.
	'''
	os.chdir(test)

	dbg("Starting test %s" % test)
	if not os.path.exists(test + '/hw.conf'):
		print("No hw.conf found for %s" % test)
		exit()

	ctx.hw_config = ConfigParser()
	ctx.hw_config.read(test + '/hw.conf')
	#
	# We have two types of test files: tests and everything else. Rather
	# than require each test to specify the files needing to be copied to
	# /tmp (previously 'tmpfs_extra_stuff'), we just copy everything which
	# isn't a test. There is really no reason not to do this as any file
	# present in a test directory should be needed by the test.
	#
	# All files
	files = os.listdir(test)
	# Tests (starts or ends with 'test')
	subtests = [f for f in files if f.startswith('test') or \
			os.path.splitext(f)[0].endswith('test')]
	# Everything else (except .py files)
	to_copy = [f for f in list(set(files) - set(subtests)) if not f.endswith('.py')]
	for f in to_copy:
		if os.path.isdir(f):
			shutil.copytree(f, '/tmp/' + f)
		else:
			shutil.copy(f, '/tmp')

	ctx.start_dbus_monitor()
	ctx.start_radios()
	ctx.start_hostapd()
	ctx.start_ofono()

	if ctx.hw_config.has_option('SETUP', 'start_iwd'):
		start = ctx.hw_config.getboolean('SETUP', 'start_iwd')
	else:
		start = True

	if start:
		ctx.start_iwd()
	else:
		print("Not starting IWD from test-runner")

	print(ctx)

	sys.path.insert(1, test)

	return (to_copy, sorted(subtests))

def post_test(ctx, to_copy):
	'''
		Remove copied files, and stop test processes.
	'''
	for f in to_copy:
		if os.path.isdir('/tmp/' + f):
			shutil.rmtree('/tmp/' + f)
		else:
			os.remove('/tmp/' + f)

	Process(['ifconfig', 'lo', 'down'], wait=True)

	ctx.stop_test_processes()
	if ctx.args.valgrind:
		with open('/tmp/valgrind.log', 'r') as f:
				dbg(f.read())
		dbg("\n")

def print_results(results):
	table = PrettyTable(['Test', colored('Passed', 'green'), colored('Failed', 'red'), \
				colored('Skipped', 'cyan'), colored('Time', 'yellow')])

	total_pass = 0
	total_fail = 0
	total_skip = 0
	total_time = 0

	for test, result in results.items():
		if result.time != TEST_MAX_TIMEOUT:
			failed = result.failures + result.errors
			passed = result.run - failed

			total_pass += passed
			total_fail += failed
			total_skip += result.skipped
		else:
			failed = "Timed out"
			passed = "Timed out"

		total_time += result.time

		time = '%.2f' % result.time

		table.add_row([test, colored(passed, 'green'), colored(failed, 'red'), \
				colored(result.skipped, 'cyan'), colored(time, 'yellow')])

	total_time = '%.2f' % total_time

	table.add_row(['Total', colored(total_pass, 'green'), colored(total_fail, 'red'), \
			colored(total_skip, 'cyan'), colored(total_time, 'yellow')])

	dbg(table)

def run_auto_tests(ctx, args):
	tests = build_test_list(args)

	ctx.start_dbus()
	ctx.start_haveged()

	# Copy autotests/misc/{certs,secrets,phonesim} so any test can refer to them
	shutil.copytree(args.testhome + '/autotests/misc/certs', '/tmp/certs')
	shutil.copytree(args.testhome + '/autotests/misc/secrets', '/tmp/secrets')
	shutil.copy(args.testhome + '/autotests/misc/phonesim/phonesim.conf', '/tmp')

	if args.shell:
		#
		# Shell really isn't meant to be used with multiple tests. If
		# a set of tests was passed in just start out in the first.
		#
		os.chdir(tests[0])
		os.system('/bin/bash')
		exit()

	for test in tests:
		copied, subtests = pre_test(ctx, test)

		rqueue = multiprocessing.Queue()
		p = multiprocessing.Process(target=start_test, args=(ctx, subtests, rqueue))
		p.start()
		# Rather than time each subtest we just time the total but
		# mutiply the default time by the number of tests being run.
		p.join(TEST_MAX_TIMEOUT * len(subtests))

		if p.is_alive():
			# Timeout
			p.terminate()

			ctx.results[os.path.basename(test)] = SimpleResult(run=0,
								failures=0, errors=0,
								skipped=0, time=TEST_MAX_TIMEOUT)
		else:
			ctx.results[os.path.basename(test)] = rqueue.get()

		post_test(ctx, copied)

	# Write out kernel log
	if ctx.args.log:
		Process(["dmesg"], ctx=ctx, wait=True)

	print_results(ctx.results)

def run_unit_tests(ctx, args):
	os.chdir(args.testhome + '/unit')
	units = build_unit_list(args)

	for u in units:
		if ctx.start_process([u], wait=True).ret != 0:
			dbg("Unit test %s failed" % os.path.basename(u))
		else:
			dbg("Unit test %s passed" % os.path.basename(u))

def run_tests():
	global config

	with open('/proc/cmdline', 'r') as f:
		cmdline = f.read()

	start = cmdline.find('--testhome')

	options = shlex.split(cmdline[start:])

	parser = argparse.ArgumentParser()
	parser.add_argument('--testhome')
	parser.add_argument('--auto_tests')
	parser.add_argument('--unit_tests')
	parser.add_argument('--verbose', default=[])
	parser.add_argument('--debug')
	parser.add_argument('--path')
	parser.add_argument('--valgrind')
	parser.add_argument('--gdb')
	parser.add_argument('--shell')
	parser.add_argument('--log')
	parser.add_argument('--log-gid')
	parser.add_argument('--log-uid')
	parser.add_argument('--hw')

	args = parser.parse_args(options)

	#
	# This prevents any print() calls in this script from printing unless
	# --debug is passed. For an 'always print' option use dbg()
	#
	if not args.debug:
		sys.stdout = open(os.devnull, 'w')

	os.environ['PATH'] = args.path
	os.environ['PATH'] += ':' + args.testhome + '/src'

	sys.path.append(args.testhome + '/autotests/util')

	#
	# This allows all autotest utils (iwd/hostapd/etc) to access the
	# TestContext. Any other module or script (in the same interpreter) can
	# simply import config.ctx and access all live test information,
	# start/stop processes, see active radios etc.
	#
	config = importlib.import_module('config')
	config.ctx = TestContext(args)

	if args.log:
		mount('logdir', args.log, '9p', 0, 'trans=virtio,version=9p2000.L')

	if config.ctx.args.unit_tests is None:
		run_auto_tests(config.ctx, args)
	else:
		run_unit_tests(config.ctx, args)

class Main:
	def __init__(self):
		self.parser = argparse.ArgumentParser(
				description='IWD Test Runner')

		self.parser.add_argument('--qemu', '-q',
				metavar='<QEMU binary>', type=str,
				help='QEMU binary to use',
				dest='qemu')
		self.parser.add_argument('--kernel', '-k', metavar='<kernel>',
				type=str,
				help='Path to kernel image',
				dest='kernel')
		self.parser.add_argument('--verbose', '-v', metavar='<list>',
				type=str,
				help='Comma separated list of applications',
				dest='verbose',
				default=[])
		self.parser.add_argument('--debug', '-d',
				action='store_true',
				help='Enable test-runner debugging',
				dest='debug')
		self.parser.add_argument('--shell', '-s', action='store_true',
				help='Boot into shell', dest='shell')
		self.parser.add_argument('--log', '-l', type=str,
				help='Directory for log files')
		self.parser.add_argument('--hw', '-w', type=str, nargs=1,
				help='Use physical adapters for tests (passthrough)')

		# Prevent --autotest/--unittest from being used together
		auto_unit_group = self.parser.add_mutually_exclusive_group()
		auto_unit_group.add_argument('--auto-tests', '-A',
				metavar='<tests>', type=str, nargs=1,
				help='List of tests to run',
				default=None,
				dest='auto_tests')
		auto_unit_group.add_argument('--unit-tests', '-U',
				metavar='<tests>', type=str, nargs='?',
				const='*',
				help='List of unit tests to run',
				dest='unit_tests')

		# Prevent --valgrind/--gdb from being used together
		valgrind_gdb_group = self.parser.add_mutually_exclusive_group()
		valgrind_gdb_group.add_argument('--gdb', '-g', metavar='<exec>',
				type=str, nargs=1,
				help='Run gdb on specified executable',
				dest='gdb')
		valgrind_gdb_group.add_argument('--valgrind', '-V', action='store_true',
				help='Run valgrind on IWD', dest='valgrind')

		self.args = self.parser.parse_args()

		print(self.args)

		if self.args.log and self.args.unit_tests:
			dbg("Cannot use --log with --unit-tests")
			quit()

	def start(self):
		usb_adapters = None

		qemu_table = [
			'qemu-system-x86_64',
			'/usr/bin/qemu-system-x86_64'
		]

		kernel_table = [
			'bzImage',
			'arch/x86/boot/bzImage',
			'vmlinux',
			'arch/x86/boot/vmlinux'
		]

		if self.args.qemu is None:
			qemu_binary = find_binary(qemu_table)
		else:
			if path_exists(self.args.qemu):
				qemu_binary = self.args.qemu
			else:
				print("QEMU binary %s does not exist" % \
						self.args.qemu)
				quit()

		if self.args.kernel is None:
			kernel_binary = find_binary(kernel_table)
		else:
			if path_exists(self.args.kernel):
				kernel_binary = self.args.kernel
			else:
				print("Kernel image %s does not exist" % \
						self.args.kernel)
				quit()

		if self.args.hw:
			hw_conf = ConfigParser()
			hw_conf.read(self.args.hw)
			# TODO: Parse PCI adapters
			if hw_conf.has_section('USBAdapters'):
				# The actual key name of the adapter
				# doesn't matter since all we need is the
				# bus/address. This gets named by the kernel
				# anyways once in the VM.
				usb_adapters = [v for v in hw_conf['USBAdapters'].values()]

		#
		# Additional arguments not provided to test-runner which are
		# needed once booted into the kernel.
		#
		options = 'init=%s' % os.path.realpath(sys.argv[0])

		# Support running from top level as well as tools
		if os.getcwd().endswith('tools'):
			options += ' --testhome %s/../' % os.getcwd()
		else:
			options += ' --testhome %s' % os.getcwd()

		options += ' --path "%s"' % os.environ['PATH']

		if self.args.auto_tests:
			options += ' --auto_tests %s' % ','.join(self.args.auto_tests)

		if self.args.log:
			if os.environ.get('SUDO_GID', None) is None:
				print("--log can only be used as root user")
				quit()

			self.args.log = os.path.abspath(self.args.log)
			uid = int(os.environ['SUDO_UID'])
			gid = int(os.environ['SUDO_GID'])

			if not path_exists(self.args.log):
				os.mkdir(self.args.log)
				os.chown(self.args.log, uid, gid)

			options += ' --log-gid %u' % gid
			options += ' --log-uid %u' % uid

		denylist = [
			'auto_tests',
			'qemu',
			'kernel'
		]

		#
		# This passes through most of the command line options to
		# the kernel command line. Some are not relevant (e.g. qemu)
		# so similar options are added in the denylist above. This excludes
		# any unset options which are assumed to be None or False. This
		# is done so default arguments can be filled once in the VM. If
		# we pass and basic types (None, False etc.) they are turned into
		# a string representation ('None', 'False', etc.) which is not
		# desirable.
		#
		for arg in vars(self.args):
			if arg in denylist or getattr(self.args, arg) in [None, False, []]:
				continue
			options += ' --%s %s' % (arg, str(getattr(self.args, arg)))

		kern_log = "ignore_loglevel" if "kernel" in self.args.verbose else "quiet"

		qemu_cmdline = [
			qemu_binary,
			'-machine', 'type=q35,accel=kvm:tcg',
			'-nodefaults', '-no-user-config', '-monitor', 'none',
			'-display', 'none', '-m', '192M', '-nographic', '-vga',
			'none', '-net', 'none', '-no-acpi', '-no-hpet',
			'-no-reboot', '-fsdev',
			'local,id=fsdev-root,path=/,readonly,security_model=none',
			'-device',
			'virtio-9p-pci,fsdev=fsdev-root,mount_tag=/dev/root',
			'-chardev', 'stdio,id=chardev-serial0,signal=off',
			'-device', 'pci-serial,chardev=chardev-serial0',
			'-device', 'virtio-rng-pci',
			'-kernel',
			kernel_binary,
			'-append',
			'console=ttyS0,115200n8 earlyprintk=serial \
				rootfstype=9p root=/dev/root \
				rootflags=trans=virtio,version=9p2000.u \
				acpi=off pci=noacpi %s ro \
				mac80211_hwsim.radios=0 %s' % (kern_log, options),
			'-cpu', 'host'
		]

		if usb_adapters:
			for bus, addr in [s.split(',') for s in usb_adapters]:
				qemu_cmdline.extend(['-usb',
							'-device',
							'usb-host,hostbus=%s,hostaddr=%s' % \
							(bus, addr)])
		if self.args.log:
			#
			# Creates a virtfs device that can be mounted. This mount
			# will point back to the provided log directory and is
			# writable unlike the rest of the mounted file system.
			#
			qemu_cmdline.extend([
				'-virtfs',
				'local,path=%s,mount_tag=logdir,security_model=passthrough,id=logdir' \
						% self.args.log
			])

		os.execlp(qemu_cmdline[0], *qemu_cmdline)

if __name__ == '__main__':
	if os.getpid() == 1 and os.getppid() == 0:
		atexit.register(exit_vm)
		prepare_sandbox()
		run_tests()

		exit()

	main = Main()
	main.start()
