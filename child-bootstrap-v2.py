#!/usr/bin/env python3
"""Fresh child bootstrap only. Never a Popen preexec hook; no import-time effect."""
import os
import resource
import sys


def main(args):
    if len(args)<2 or args[0]!='--' or not os.path.isabs(args[1]):
        raise RuntimeError('fixed_absolute_command_required')
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    os.execve(args[1],args[1:],os.environ)


if __name__=='__main__':main(sys.argv[1:])
