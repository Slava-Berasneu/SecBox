import os
from subprocess import Popen, PIPE, STDOUT
from multiprocessing import Process
import json
import time
import socketio
import platform
import json
import requests
import sys
import os
import struct
import system_calls

from dotenv import load_dotenv
from socket import socket, SOCK_SEQPACKET, AF_UNIX

import protos.common_pb2 as common_pb2
import protos.syscall_pb2 as syscall_pb2

load_dotenv()

base_command = "bazel run examples/seccheck:server_cc"


class systemCallMonitor:
    def __init__(self, sandbox_id) -> None:
        self.base_command = base_command
        self.sandbox_id = sandbox_id
        self.client = None
        self.ps = []
        self.arch = platform.processor()
        self.bitness = 64 if sys.maxsize > 2**32 else 32
        self.syscalls = system_calls.syscalls()
        self.stopped = False

    def run(self):
        p = Process(target=self.runInParallel, args=(
            self.monitoring_process, self.monitoring_process, "healthy", "infected"))
        p.start()
        self.ps.append(p)

    def start(self):
        self.run()
        return self

    def stop(self):
        healthy_logfile = "healthy" + "/" + self.sandbox_id + "_syscalls"
        infected_logfile = "infected" + "/" + self.sandbox_id + "_syscalls"

        healthy_logstring = ""
        infected_logstring = ""

        self.stopped = True

        for p in self.ps:
            p.terminate()
        for p in self.ps:
            print("Waiting for terminated syscall monitor process to terminate")
            p.join()
            print("Closing terminated process")
            p.close()

        with open(healthy_logfile, "r") as h:
            healthy_logstring = h.read()

        with open(infected_logfile, "r") as i:
            infected_logstring = i.read()

        message = {
                "ID": self.sandbox_id,
                "architecture": self.arch,
                "sysCalls": {
                    "healthy": healthy_logstring,
                    "infected": infected_logstring
                },
                "lastMessage": 1
            }
        requests.post(str(os.getenv('BE_IP_PORT')) + "/syscall", json=json.dumps(message))
        print("Syscall Logs emitted")
        time.sleep(10)
        os.remove("infected" + "/" + self.sandbox_id + "_syscalls")
        os.remove("healthy" + "/" + self.sandbox_id + "_syscalls")
        return 0

    def handshake(self, conn):
        bytes = conn.recv(10240)
        handshake_pb = common_pb2.Handshake()
        if not handshake_pb.ParseFromString(bytes):
            print("Error Parsing message from bytes")
            return False
        if handshake_pb.version > 1:
            print("Unsupported Version")
            return False
        handshake_out = common_pb2.Handshake()
        handshake_out.version = 1
        conn.sendall(handshake_out.SerializeToString())
        return True

    def get_name_from_no(self, sysno, architecture):
        names = list(self.syscalls.syscalls["archs"][architecture].keys())
        index = list(
            self.syscalls.syscalls["archs"][architecture].values()).index(sysno)
        return names[index]

    def monitoring_process(self, infected_status):
        self.client = socketio.Client()
        self.client.connect(os.getenv('BE_IP_PORT'), namespaces=['/live'])
        print("syscall monitor started")
        socket_addr = "/tmp/" + \
            infected_status + "_" + \
            str(self.sandbox_id) + "_gvisor_events.sock"
        try:
            os.remove(socket_addr)
        except OSError:
            pass
        with socket(AF_UNIX, SOCK_SEQPACKET) as sock:
            sock.bind(socket_addr)
            sock.listen(1)
            conn, adr = sock.accept()
            print("Connection Accepted")
            if not self.handshake(conn):
                conn.close()
            print("Handshake Successful")
            write_counter = 0
            with open(infected_status + "/" + self.sandbox_id + "_syscalls", "w+") as logfile:
                while not self.stopped:
                    data = conn.recv(10240)
                    if len(data) > 1:
                        message_type = struct.unpack("<h", data[2:4])[0]
                        if message_type == 6:
                            pb_syscall = syscall_pb2.Syscall()
                            pb_syscall.ParseFromString(data[8:])
                            pb_context_data = pb_syscall.context_data

                            sysno = pb_syscall.sysno
                            args = [pb_syscall.arg1, pb_syscall.arg2, pb_syscall.arg3, pb_syscall.arg4, pb_syscall.arg5, pb_syscall.arg6]
                            syscall = {
                                "time_ns": int(pb_context_data.time_ns),
                                "thread_id": int(pb_context_data.thread_id),
                                "sysno": sysno,
                                "sysname": self.get_name_from_no(sysno, self.arch),
                                "container_id": pb_context_data.container_id,
                                "cwd": pb_context_data.cwd,
                                "credentials": str(pb_context_data.credentials),
                                "args": str(args).replace(",", ";")
                            }
                            #send each syscall to malware analyzer
                            self.client.emit('syscalls', [syscall['time_ns'], syscall['sysname']], namespace='/live')
                            logfile.write(json.dumps(syscall)+"\n")
                            write_counter += 1
                        if write_counter>=10000:
                            message = {
                                "ID": self.sandbox_id,
                                "architecture": self.arch,
                                "sysCalls": {
                                    infected_status: logfile.read()
                                },
                                "lastMessage": 0
                            }
                            requests.post(str(os.getenv('BE_IP_PORT')) + "/syscall", json=json.dumps(message))
                            logfile.truncate()
                            write_counter = 0
                    else:
                        print("No more syscalls to receive, closing server")
                        break

    def runInParallel(self, fn1, fn2, arg1, arg2):
        fns = [fn1, fn2]
        args = [arg1, arg2]
        for index in range(len(fns)):
            p = Process(target=fns[index], args=(args[index],))
            p.start()
            self.ps.append(p)
