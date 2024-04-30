#!/usr/bin/env python3

import os
from argparse import ArgumentParser
import subprocess

def get_args():
    parser = ArgumentParser(description="Run a command and monitor its system calls")
    mex_group = parser.add_argument_group('Process or Command','You can run a command or give it a process name to monitor')
    mexclusive_group = mex_group.add_mutually_exclusive_group(required=True)
    mexclusive_group.add_argument("-p", "--process", help="Process to monitor/trace")
    mexclusive_group.add_argument("-c", "--command", help="Command to trace")
    parser.add_argument("-o", "--csv-output", required=False, help="CSV file to write to")
    parser.add_argument("-u", "--user", required=True, help="User to run the command as", default="root")
    return parser.parse_args()

# def run_command(command):
#     # Run the command in the background using subprocess
#     process = subprocess.Popen(command, shell=True)
#     process.send_signal(subprocess.signal.SIGSTOP)
#     return process

def run_trace(pid, process_name, output, **kwargs):
    print("Monitoring process %d (%s) ..." % (pid, process_name))
    if kwargs.get("process") is not None:
        process = kwargs.get("process")
    exe_path = os.readlink(f"/proc/{pid}/exe")
    print(f"Executable path: {exe_path}")
    bpf_command = f"python3 {os.path.dirname(os.path.abspath(__file__))}/main.py --data {output} --pid {pid}"
    bpf_trace = subprocess.Popen(bpf_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    #Resume the process
    # if kwargs.get("process") is not None:
    #     kwargs.get("process").send_signal(subprocess.signal.SIGCONT)
    stdout, stderr = bpf_trace.communicate()
    print(stdout.decode("utf-8"))
    print(stderr.decode("utf-8"))
    

    return bpf_trace

def main():
    args = get_args()
    if args.command is not None: 
        process = subprocess.Popen(args.command, shell=True)
        pid = process.pid
        # process.send_signal(subprocess.signal.SIGSTOP)
        process_name = args.command.split()[0]
        
    else:
        process_name = args.process
        pid = subprocess.check_output(["pidof",process_name])
    bpf_trace = run_trace(pid, process_name, args.csv_output, process=process)
        
    
    try:
        while True:
            if not os.path.exists(f"/proc/{str(pid)}"):
                print("Process is no longer active")
                bpf_trace.kill()
                exit()
            pass
    except KeyboardInterrupt:
        # Kill the process and the bpftrace script
        os.system(f"kill {pid}")
        bpf_trace.kill()
        print("Exiting...")
        exit()


if __name__ == "__main__":
    if os.getuid() != 0:
        print("This script must be run as root. Please use sudo.")
        exit(1)
    main()