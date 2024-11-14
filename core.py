import pathlib
import shutil
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

import frida


class StatusEnum(Enum):
    callback = 'callback'
    done = 'done'


class CallbackResult:
    base: Any
    filename: str

    def __init__(self, base: Any, filename: str):
        self.base = base
        self.filename = filename


class StartResult:
    base: Any
    output_path: str

    def __init__(self, base: Any, output_path: str):
        self.base = base
        self.output_path = output_path


class ReceiveMessage:
    """
    {'type': 'send', 'payload': {'status': 'done', 'msg': 'detect the cocos2d-js script lazy loaded, auto stop the script.'}}
    {'type': 'send', 'payload': {'status': 'callback', 'callback': {'scripts': 'ADNativeBridage.SignnBlockUser(2101)', 'size': 4294967295, 'filename': None}}}
    """

    def __init__(self, message: dict):
        if message.get('type') == 'error':
            raise Exception(message.get('stack', 'unknown error'))
        self.payload = message.get('payload', {})
        if not self.payload:
            raise Exception('receive message payload is empty')

    @property
    def status(self) -> StatusEnum:
        return StatusEnum(self.payload["status"])

    @property
    def is_callback(self) -> bool:
        return self.status == StatusEnum.callback

    @property
    def is_done(self) -> bool:
        return self.status == StatusEnum.done

    @property
    def message(self) -> str:
        return self.payload["msg"] if "msg" in self.payload else 'no message'

    @property
    def callback(self) -> CallbackResult | None:
        if self.is_callback or self.is_done:
            return CallbackResult(**self.payload["callback"])
        else:
            return None


class Callback(ABC):
    out_dir: pathlib.Path

    session: frida.core.Session
    script: frida.core.Script
    stop: bool = False

    arch: str

    result: StartResult

    def __init__(self, script_name: str, package_name: str, out_dir: str, **kwargs):
        device = frida.get_usb_device()
        pid = device.spawn([package_name])
        self.session = device.attach(pid)
        device.resume(pid)

        self.out_dir = pathlib.Path(out_dir) / package_name
        script = """
rpc.exports = {
    arch: function() {
        return Process.arch;
    }
}

"""
        script += open(pathlib.Path(__file__).parent / 'scripts' / script_name, 'r').read()
        script += f'\n{self.get_run_command(**kwargs)}'
        self.script = self.session.create_script(script)

    @abstractmethod
    def get_run_command(self, **kwargs):
        pass

    def _callback(self, message, data):
        msg = ReceiveMessage(message)

        if msg.is_done:
            self.stop = True
            print(f"done, {msg.message}")
            return

        if msg.is_callback:
            callback = msg.callback
            filename = callback.filename
            fpath = pathlib.Path(filename)
            pathlib.Path(self.out_dir / fpath.parent).mkdir(parents=True, exist_ok=True)
            output_path = self.out_dir / filename
            with open(output_path, 'wb') as f:
                f.write(data)
            self.result = StartResult(
                base=callback.base,
                output_path=str(output_path)
            )
            print(f'Save file: {filename}')

    def start(self) -> StartResult:
        self.out_dir.mkdir(parents=True, exist_ok=True)

        self.script.on('message', self._callback)
        self.script.load()

        self.arch = self.script.exports.arch()
        while not self.stop:
            pass
        self.script.unload()
        self.session.detach()
        return self.result
