import sys

import frida

IS_END = False


def read_frida_js_source():
    with open("global-metadata-finder.js", "r") as f:
        return f.read()


def on_message(message, data):
    if message.get('type') == 'error':
        raise Exception(message.get('stack', 'unknown error'))
    payload = message.get('payload', {})
    if not payload:
        raise Exception('receive message payload is empty')
    if payload.get('status') == 'end':
        global IS_END
        IS_END = True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print('need pkg and global-metadata.dat offset addr')
    else:
        pkg = sys.argv[1]
        offset = sys.argv[2]

        device = frida.get_usb_device()
        pid = device.spawn([pkg])
        session = device.attach(pid)
        device.resume(pid)

        dump_script = read_frida_js_source()
        dump_script += f'\nhook({offset});'
        script = session.create_script(dump_script)
        script.on('message', on_message)
        script.load()
        while not IS_END:
            pass
        script.unload()
        session.detach()
