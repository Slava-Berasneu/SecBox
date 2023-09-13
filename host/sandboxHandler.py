import socketio
import subprocess
from multiprocessing import Process
from controller import Controller
from monitors import performanceMonitor
from monitors import networkMonitor
from monitors import systemCallMonitor
from time import sleep

sandboxes = {}


def start_sandbox(json):
    sandbox_id = json['ID']
    mw_hash = json['SHA256']
    os = json['OS']
    sandbox = Sandbox(mw_hash, os, sandbox_id)
    sandboxes[sandbox_id] = sandbox


def find_by_id(sandbox_id):
    try:
        return sandboxes[sandbox_id]
    except:
        print('Invalid Sanbox ID: ' + str(sandbox_id))


def stop_sandbox(json):
    print(json)
    sandbox = find_by_id(json['ID'])
    print(sandbox)
    sandbox.stop()
    sandboxes[json['ID']] = None


def stop_all():
    for sandbox in sandboxes.values():
        sandbox.stopped = True
    sandbox.stop()


def parallel_command(json):
    expected_json = {
        'ID': 123,
        'CMD': 'apt-get update'
    }
    sandbox = find_by_id(json['ID'])
    command = json['CMD']
    sandbox.controller.execute_command(command)


def infected_command(json):
    expected_json = {
        'ID': 123,
        'CMD': 'sudo apt-get update'
    }
    sandbox = find_by_id(json['ID'])
    command = json['CMD']
    sandbox.controller.infectedInstance.execute_command(command)


def healthy_command(json):
    expected_json = {
        'ID': 123,
        'CMD': 'sudo apt-get update'
    }
    sandbox = find_by_id(json['ID'])
    command = json['CMD']
    sandbox.controller.healthyInstance.execute_command(command)


class Sandbox:
    def __init__(self, mw_hash, os, sandbox_id) -> None:
        self.client = socketio.Client()
        self.client.connect('http://localhost:5000', namespaces=['/sandbox'])

        self.sandbox_id = sandbox_id

        self.mw_hash = mw_hash
        self.os = os

        self.syscallMonitor = systemCallMonitor.systemCallMonitor(
            self.sandbox_id)
        self.syscallMonitor.start()
        self.controller = Controller(self.mw_hash, self.os, self.sandbox_id)

        self.perfMonitor = performanceMonitor.performanceMonitor(
            self.sandbox_id, self.controller)
        self.netMonitor = networkMonitor.networkMonitor(
            self.sandbox_id, self.controller)
        '''
        print("Downloading test files. Expect a long delay... This behavior can be changed in sandboxHandler.py")
        self.execute_command("wget https://digitalcorpora.s3.amazonaws.com/corpora/files/govdocs1/zipfiles/026.zip")
        print("Unzipping test files...")
        self.execute_command("apt-get install unzip")
        self.execute_command("unzip 026.zip -d /etc")
        print("Cloning test files...")
        self.execute_command("cp -r /etc/026 /etc/027")
        self.execute_command("cp -r /etc/026 /etc/028")
        self.execute_command("cp -r /etc/026 /etc/029")
        self.execute_command("cp -r /etc/026 /etc/030")
        self.execute_command("cp -r /etc/026 /etc/031")
        self.execute_command("cp -r /etc/026 /etc/032")
        self.execute_command("cp -r /etc/026 /etc/033")
        self.execute_command("cp -r /etc/026 /etc/034")
        self.execute_command("cp -r /etc/026 /etc/035")
        self.execute_command("cp -r /etc/026 /etc/036")
        self.execute_command("cp -r /etc/026 /etc/037")
        self.execute_command("cp -r /etc/026 /etc/038")
        print("Finished setting up test files in /etc/")
        '''
        self.stopped = False
        self.process = Process(target=self.run)
        self.process.start()

    def execute_command(self, command):
        self.controller.execute_command(command)

    def run(self):
        self.perfMonitor.run()
        self.netMonitor.run()
        self.client.emit('sandboxReady', "ready!", namespace='/sandbox')

    def stop(self):
        self.syscallMonitor.stop()
        self.perfMonitor.stop()
        self.netMonitor.stop()
        self.controller.stop_instances()
        self.process.terminate()
        print("Waiting for terminated process to terminate")
        self.process.join()
        print("Closing terminated process")
        self.process.close()
        print("process killed")
        self.syscallMonitor = None
        self.controller = None
        self.perfMonitor = None
        self.netMonitor = None
        self.stopped = True
        print("Sandbox stopped, processes joined")
        return 1
