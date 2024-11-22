import os
from argparse import ArgumentParser
from pathlib import Path

from core import Callback


def fix_so(package: str, out_dir: str, arch: str, dump_so_path: str, base):
    print(f"arch: {arch}")
    if arch == "arm":
        os.system("adb push android/SoFixer32 /data/local/tmp/SoFixer")
    elif arch == "arm64":
        os.system("adb push android/SoFixer64 /data/local/tmp/SoFixer")
    os.system("adb shell chmod +x /data/local/tmp/SoFixer")

    so_name = Path(dump_so_path).name.removesuffix(".so")
    os.system(f"adb push {dump_so_path} /data/local/tmp/{so_name}.so")

    so_fix_command = f"adb shell /data/local/tmp/SoFixer -m {base} -s /data/local/tmp/{so_name}.so -o /data/local/tmp/{so_name}.fix.so"
    print(so_fix_command)
    os.system(so_fix_command)

    pull_path = f"{out_dir}/{package}/{so_name}.fix.so"
    os.system(f"adb pull /data/local/tmp/{so_name}.fix.so {pull_path}")
    os.system(f"adb shell rm /data/local/tmp/{so_name}.so")
    os.system(f"adb shell rm /data/local/tmp/{so_name}.fix.so")
    os.system("adb shell rm /data/local/tmp/SoFixer")


class SoCallback(Callback):

    def __init__(self, package_name: str, out_dir: str, so_name: str):
        super().__init__('dump_so.js', package_name, out_dir, so_name=so_name)

    def get_run_command(self, **kwargs):
        so_name = kwargs.get('so_name')
        return f'hook("{so_name}")'


NOW_PATH = os.path.dirname(os.path.abspath(__file__))

if __name__ == '__main__':
    p = ArgumentParser(description='dump any Unity app so file')
    p.add_argument('-p', '--package', help='android package name')
    p.add_argument('-s', '--so', help='so name e.g. libil2cpp.so', default='libil2cpp.so')
    p.add_argument('-o', '--output', help='output directory (default: current directory), e.g. "*/{packageName}"',
                   default=NOW_PATH)

    args = p.parse_args()

    callback = SoCallback(args.package, args.output, args.so)
    result = callback.start()
    fix_so(args.package, args.output, callback.arch, result.output_path, result.base)
