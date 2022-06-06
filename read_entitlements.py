import threading
import argparse
import sys
import os

import frida

__JS_SCRIPT = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'read_entitlements.js')

def get_usb_iphone():
    Type = 'usb'
    if int(frida.__version__.split('.')[0]) < 12:
        Type = 'tether'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device

def get_applications(device):
    applications = device.enumerate_applications()
    return applications


def list_applications(device):
    applications = get_applications(device)

    if len(applications) > 0:
        pid_column_width = max(map(lambda app: len('{}'.format(app.pid)), applications))
        name_column_width = max(map(lambda app: len(app.name), applications))
        identifier_column_width = max(map(lambda app: len(app.identifier), applications))
    else:
        pid_column_width = 0
        name_column_width = 0
        identifier_column_width = 0

    header_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    print(header_format % ('PID', 'Name', 'Identifier'))
    print('%s  %s  %s' % (pid_column_width * '-', name_column_width * '-', identifier_column_width * '-'))
    line_format = '%' + str(pid_column_width) + 's  ' + '%-' + str(name_column_width) + 's  ' + '%-' + str(
        identifier_column_width) + 's'
    
    applications = sorted(applications, key=lambda app: (app.pid == 0, app.name))
    for application in applications:
        if application.pid == 0:
            print(line_format % ('-', application.name, application.identifier))
        else:
            print(line_format % (application.pid, application.name, application.identifier))

def open_target_app(device, name_or_bundleid):
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    if not pid:
        pid = device.spawn([bundle_identifier])
        session = device.attach(pid)
        device.resume(pid)
    else:
        session = device.attach(pid)

    return session, display_name, bundle_identifier

def get_entitlements(session, display_name):
    print(f'Get entitlements for {display_name}')

    source = ''
    with open(__JS_SCRIPT) as f:
        source = f.read()
    script = session.create_script(source)

    result = {}
    is_done = threading.Event()

    def on_message(message, data):
        nonlocal result
        result = message
        is_done.set()

    script.on('message', on_message)
    script.load()
    is_done.wait()

    if result['type'] != 'send':
        raise ValueError(f"Unexpected messange from frida script with type: '{result['type']}' and payload: '{result['payload']}'")
    return result['payload']
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='frida-entitlements-dump ')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps')
    args = parser.parse_args()

    device = get_usb_iphone()

    if args.list_applications:
        try:
            list_applications(device)
        except Exception as e:
            sys.exit('Failed to enumerate applications: %s' % e)
        sys.exit(0)

    name_or_bundleid = args.target
    if not name_or_bundleid:
        print("Enter bundle identifier or display name. \nSee help for more information")
        sys.exit(0)

    try:
        (session, display_name, bundle_identifier) = open_target_app(device, name_or_bundleid)
    except Exception as e:
        sys.exit(f'Failed to attach to app {name_or_bundleid} with error: {e}')

    try:
        entitlements = get_entitlements(session, display_name)
    except Exception as e:
        sys.exit(f"Failed to get entitlements from app with error: {e}")

    for ent in entitlements:    
        print(ent)

    sys.exit(0)