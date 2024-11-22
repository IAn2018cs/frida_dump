import os
from argparse import ArgumentParser

from core import Callback


class HookSomeFuncCallback(Callback):

    def __init__(self, package_name: str, out_dir: str, func_addr_offset: str):
        super().__init__('hook_cardface.js', package_name, out_dir,
                         func_addr_offset=func_addr_offset)

    def get_run_command(self, **kwargs):
        func_addr_offset = kwargs.get('func_addr_offset')
        return f'hook("{func_addr_offset}")'


NOW_PATH = os.path.dirname(os.path.abspath(__file__))

if __name__ == '__main__':
    p = ArgumentParser()
    p.add_argument('-p', '--package', help='android package name')
    p.add_argument('-a', '--addr', help='function addr offset, e.g. 0xCB90B0')

    args = p.parse_args()

    callback = HookSomeFuncCallback(args.package, NOW_PATH, args.addr)
    callback.start()
