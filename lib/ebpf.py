# 
# Copyleft Simone 'evilsocket' Margaritelli
# 
# This program is free software: you can redistribute it and/or modify  
# it under the terms of the GNU General Public License as published by  
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but 
# WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#
from bcc import BPF

from lib import MAX_SYSCALLS, comm_for_pid


class Probe(object):
    def __init__(self, target_pid, max_syscalls=MAX_SYSCALLS):
        self.target_pid = target_pid
        self.comm = comm_for_pid(self.target_pid)
        if self.comm is None:
            print("can't find comm for pid %d" % self.target_pid)
            quit()

        self.max_syscalls = max_syscalls
        self.code = """
            BPF_PERCPU_ARRAY(histogram, u32, MAX_SYSCALLS);

            TRACEPOINT_PROBE(raw_syscalls, sys_enter)
            {
                // filter by target pid
                u64 pid = bpf_get_current_pid_tgid() >> 32;
                if(pid != TARGET_PID) {
                    return 0;
                }

                // populate histogram
                u32 key = (u32)args->id;
                u32 value = 0, *pval = NULL;
                pval = histogram.lookup_or_try_init(&key, &value);
                if(pval) {
                    *pval += 1;
                }

                return 0;
            }
        """.replace('TARGET_PID', str(self.target_pid)).replace('MAX_SYSCALLS', str(self.max_syscalls))

    def start(self):
        probe = BPF(text=self.code)
        return probe.get_table('histogram', reducer=lambda x, y: x + y)


class ProbeChild(object):
    def __init__(self, target_pid, max_syscalls=MAX_SYSCALLS):
        self.target_pid = target_pid
        self.comm = comm_for_pid(self.target_pid)
        if self.comm is None:
            print("can't find comm for pid %d" % self.target_pid)
            quit()

        self.max_syscalls = max_syscalls
        self.code = """
            #include <linux/sched.h>

            struct pid_entry {
                u32 pid;
            };

            BPF_PERCPU_ARRAY(histogram, u32, MAX_SYSCALLS);
            BPF_HASH(pid_set, u32, struct pid_entry);

            TRACEPOINT_PROBE(sched, sched_process_fork)
            {
                u32 parent_pid = args->parent_pid;
                u32 child_pid = args->child_pid;

                if (parent_pid == TARGET_PID) {
                    struct pid_entry entry = {.pid = child_pid};
                    pid_set.update(&child_pid, &entry);
                }

                return 0;
            }

            TRACEPOINT_PROBE(raw_syscalls, sys_enter)
            {
                u32 pid = bpf_get_current_pid_tgid() >> 32;

                if (pid == TARGET_PID || pid_set.lookup(&pid)) {
                    u32 key = (u32)args->id;
                    u32 value = 0, *pval = NULL;
                    pval = histogram.lookup_or_try_init(&key, &value);
                    if (pval) {
                        *pval += 1;
                    }
                }

                return 0;
            }
        """.replace('TARGET_PID', str(self.target_pid)).replace('MAX_SYSCALLS', str(self.max_syscalls))

    def start(self):
        probe = BPF(text=self.code)
        return probe.get_table('histogram', reducer=lambda x, y: x + y)
    
class ProbeAll(object):
    def __init__(self, target_pid, max_syscalls=MAX_SYSCALLS):
        self.target_pid = target_pid
        self.comm = comm_for_pid(self.target_pid)
        if self.comm is None:
            print("can't find comm for pid %d" % self.target_pid)
            quit()

        self.max_syscalls = max_syscalls
        self.code = """
            BPF_PERCPU_ARRAY(histogram, u32, MAX_SYSCALLS);

            TRACEPOINT_PROBE(raw_syscalls, sys_enter)
            {
                // filter by target pid
                u64 pid = bpf_get_current_pid_tgid() >> 32;

                // populate histogram
                u32 key = (u32)args->id;
                u32 value = 0, *pval = NULL;
                pval = histogram.lookup_or_try_init(&key, &value);
                if(pval) {
                    *pval += 1;
                }

                return 0;
            }
        """.replace('TARGET_PID', str(self.target_pid)).replace('MAX_SYSCALLS', str(self.max_syscalls))

    def start(self):
        probe = BPF(text=self.code)
        return probe.get_table('histogram', reducer=lambda x, y: x + y)

