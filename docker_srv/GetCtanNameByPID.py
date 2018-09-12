import os
import sys, re
from collections import OrderedDict
import docker

class GetCtanNameByPID(object):
    def __init__(self):
        self.proc = "/proc"
        self.debugEnabled = True
        self.pid = None

    def __chk_pid_legal(self):
        if str(self.pid).isdigit() and (int(self.pid) >= 0 or int(self.pid) <= 32768):
            return True
        else:
            raise RuntimeError('Pid input should be an integer, and should be 0~32768. Aborted!')

    def __chk_pid_existed(self):
        if os.path.exists(os.path.join(self.proc, str(self.pid), 'cmdline')) and os.path.exists(
                os.path.join(self.proc, str(self.pid), 'status')):
            return True
        else:
            raise RuntimeError('pid is NOT exist! Aborted! ')

    def __getCurrentAllPids(self):
        return [int(name) for name in os.listdir(self.proc) if name.isdigit()]

    def __getPPid(self):
        status = self.__getProcessStatus()
        if len(status) == 0:
            raise KeyError("getStatus(Type: OrderedDict) returns None, this always means pid is NOT exist! Aborted!")
        return int(status['PPid'])

    def __getProcessStatus(self):
        status = OrderedDict()
        pidDir = None
        if self.pid in self.__getCurrentAllPids():
            pidDir = os.path.join(self.proc, str(self.pid))
        if not os.path.exists(pidDir):
            raise RuntimeError('pid is not exist!')

        try:
            with open(os.path.join(pidDir, "status"), 'r') as f:
                content = f.read().strip().split("\n")
                for item in content:
                    kv = item.replace('\t', ' ').split(":")
                    status[kv[0].strip()] = kv[1].strip()
        except IOError:
            raise RuntimeError('pid is not exist!')

        return dict(status)

    def __getCmdline(self):
        if int(self.pid) == 0:
            return None

        if self.pid in self.__getCurrentAllPids():
            pidDir = os.path.join(self.proc, str(self.pid))
        else:
            raise RuntimeError('pid not exist')

        if os.path.exists(pidDir):
            pass
        else:
            raise RuntimeError('cmdline is None or "", this always means pid is NOT exist! Aborted! ')

        with open(os.path.join(pidDir, "cmdline"), 'r') as f:
            cmdline = f.read().strip().replace('\x00', ' ').strip()
            if cmdline is None or cmdline == '':
                raise RuntimeError("cmdline is None or '', this always means pid is NOT exist! Aborted! ")

        return str(cmdline)

    def __getPidChain(self):
        maxPidChain = 1024
        pidChain = list()
        pidChain.append(self.pid)
        oldPid = self.pid
        for i in range(maxPidChain - 1):
            pidItem = self.__getPPid()
            if pidItem != 0:
                pidChain.append(pidItem)
                self.pid = pidItem
            else:
                pidChain.append(0)
                break
        self.pid = oldPid
        return pidChain

    def __getCmdlineChain(self):
        pidChain = self.__getPidChain()
        pidCmdlineChain = []
        oldPid = self.pid
        for pid in pidChain:
            self.pid = pid
            pidCmdlineChain.append((pid, self.__getCmdline()))
        self.pid = oldPid
        return pidCmdlineChain

    def __isDockerRelatedProcess(self):
        string = str(self.__getCmdlineChain())
        import re
        match = re.findall(r'docker', string)
        if match:
            return True
        else:
            return False

    def get_ctan_name_by_pid(self, pid):
        self.pid = pid
        self.__chk_pid_legal()
        self.__chk_pid_existed()

        if not self.__isDockerRelatedProcess():
            # raise RuntimeError("pid(%s) is not a docker related process's, aborted!" % self.pid)
            return None
        cmd_chian_ls = self.__getCmdlineChain()

        # Docker Server Version >= 1.11 is required!
        # match = re.findall(r'(?<=docker-containerd-shim )\S+', string)
        ctan_name = None
        for (pid, cmd) in cmd_chian_ls:
            if re.match(r'.*workdir.*', cmd) is not None:
                cmd_spilt = cmd.split(' ')
                cmd_4 = cmd_spilt[4]
                ctan_id = os.path.split(cmd_4)[1]
                ctan = docker.from_env().containers.get(ctan_id)
                ctan_name = ctan.name
                break
        assert ctan_name is not None, "not supported docker version or a bug otherwise, aborted! "
        return ctan_name

if __name__ == '__main__':
    d = GetCtanNameByPID()
    print(d.get_ctan_name_by_pid(24187))
