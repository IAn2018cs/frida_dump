import os
from argparse import ArgumentParser

from core import Callback


class MetadataCallback(Callback):

    def __init__(self, package_name: str, out_dir: str, load_metadata_addr_offset: str):
        super().__init__('dump_metadata.js', package_name, out_dir,
                         load_metadata_addr_offset=load_metadata_addr_offset)

    def get_run_command(self, **kwargs):
        load_metadata_addr_offset = kwargs.get('load_metadata_addr_offset')
        return f'hook("{load_metadata_addr_offset}");'


NOW_PATH = os.path.dirname(os.path.abspath(__file__))

if __name__ == '__main__':
    p = ArgumentParser(description='dump Unity app metadata file')
    p.add_argument('-p', '--package', help='android package name')
    p.add_argument('-a', '--addr', help='LoadMetadataFile function addr offset, e.g. 0xCB90B0')
    p.add_argument('-o', '--output', help='output directory (default: current directory), e.g. "*/{packageName}"',
                   default=NOW_PATH)

    args = p.parse_args()

    callback = MetadataCallback(args.package, args.output, args.addr)
    callback.start()
