import os
import tempfile
import configparser

from .phone import Phone


BTSTACK_CONFIG_FILE = 'bt_stack.conf'
# Needs to always be in UNIX format, hence no os.path.join
BTSTACK_CONFIG_PATH = '/etc/bluetooth/' + BTSTACK_CONFIG_FILE

BTSNOOP_FALLBACK_FILE = 'btsnoop_hci.log'
# Needs to always be in UNIX format, hence no os.path.join
BTSNOOP_FALLBACK_PATH = '/sdcard/' + BTSNOOP_FALLBACK_FILE


class SnoopPhone(Phone):
    prefix = "SnoopPhone::"

    def __init__(self, serial=None, verbose=False):
        super(SnoopPhone, self).__init__(serial=serial)
        self._tmp_dir = tempfile.mkdtemp() # create tmp dir on host

        self.verbose = verbose
        if self.verbose:
            print(f"{self.prefix}_tmp_dir: {self._tmp_dir}")

    def pull_btsnoop(self, dst=None, a_mode=True):
        btsnoop_path, btsnoop_file = self._locate_btsnoop()
        if self.verbose:
            print(f"{self.prefix}dst set: {dst}")
            print(f"{self.prefix}btsnoop_path: {btsnoop_path}")
            print(f"{self.prefix}btsnoop_file: {btsnoop_file}")

        # store file in tmp location if no dst is explicitly set
        if not dst:
            dst = os.path.join(self._tmp_dir, btsnoop_file)
            if self.verbose:
                print(f"{self.prefix}dst wasn't set; set dst = {dst}")

        ret = super(SnoopPhone, self).pull(btsnoop_path, dst, a_mode, verbose=self.verbose)
        if ret[0] == 0: #SUCCESS
            if self.verbose:
                print(f"{self.prefix}{ret[1].decode('utf-8')} -> {dst}")
            return dst
        else:
            return None

    def _locate_btsnoop(self):
        tmp_config_path = self._pull_btconfig()
        config = self._parse_btconfig(tmp_config_path)
        try:
            btsnoop_path = config['btsnoopfilename']
            return btsnoop_path, os.path.basename(btsnoop_path)
        except:
            return BTSNOOP_FALLBACK_PATH, BTSNOOP_FALLBACK_FILE

    def _parse_btconfig(self, path):
        if not os.path.exists(path):
            raise ValueError("_parse_btconfig(): Failed to read bt_stack.conf (" + str(path) + ")")

        # Parse key/values
        # bt_stack.conf does not have valid ConfigParser format; write '[Default]' header in, THEN try to parse.
        parser = configparser.ConfigParser()
        with open(path, 'r') as original: data = original.read()
        with open(path, 'w') as modified: modified.write("[Default]\n" + data)
        with open(path, 'r') as f:
            parser.readfp(f)
            return dict(parser.items('Default'))

    def _pull_btconfig(self):
        dst = os.path.join(self._tmp_dir, BTSTACK_CONFIG_FILE)
        retcode, out = super(SnoopPhone, self).pull(BTSTACK_CONFIG_PATH, dst, verbose=self.verbose)
        if retcode == 0:
            return dst
        else:
            raise ValueError("_pull_btconfig(): Failed to pull bt_stack.conf")

def _pull_log():
	"""
	Pull the btsnoop log from a connected phone
	"""
	phone = SnoopPhone(verbose=True)
	return phone.pull_btsnoop()
