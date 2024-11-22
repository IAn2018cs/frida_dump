from argparse import ArgumentParser

from core import Callback


class HookCardFaceFuncCallback(Callback):

    def __init__(self, package_name: str):
        super().__init__('hook_cardface.js', package_name, 'temp')

    def get_run_command(self, **kwargs):
        return f'hook()'


if __name__ == '__main__':
    p = ArgumentParser()
    p.add_argument('-p', '--package', help='android package name')

    args = p.parse_args()

    callback = HookCardFaceFuncCallback(args.package)
    callback.start()
