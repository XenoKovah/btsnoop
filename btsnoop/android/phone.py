from __future__ import unicode_literals
from .executor import Executor

class Phone(object):
    """
    https://developer.android.com/studio/command-line/adb
    """

    def __init__(self, serial=None):
        self.serial = serial

    def shell(self, cmd):
        cmd = "adb shell " + cmd
        ret, out = Executor(cmd).execute()
        if ret != 0:
            raise ValueError("Could not execute adb shell " + cmd)
        return out

    def pull(self, src, dst, a_mode=False, verbose=False):
        """
        pull [-a] REMOTE... LOCAL
            copy files/dirs from device
            -a: preserve file timestamp and mode
        """
        a = "-a" if a_mode else ""
        cmd = f"adb pull {a} " + src + " " + dst
        if verbose: print(f"[adb] ==> {cmd}")
        return Executor(cmd).execute()

    def push(self, src, dst):
        cmd = "adb push " + src + " " + dst
        return Executor(cmd).execute()

    def ls(self, path):
        out = self.shell("ls " + path)
        return out.splitlines()

    def start_app(self, pkg_name):
        cmd = 'monkey -p ' + pkg_name + ' -c android.intent.category.LAUNCHER 1'
        self.shell(cmd)
