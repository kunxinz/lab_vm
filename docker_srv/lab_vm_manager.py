#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@author: kun
"""
__author__ = "kunxinz"
__email__ = "kunxinz@qq.com"

import bcrypt
from datetime import datetime
import threading
import docker
import os
import shutil
import traceback
import dill
import time
import socket
import paramiko
from Crypto.Cipher import AES
from multiprocessing import cpu_count
import GetCtanNameByPID as GCNBP
from collections import defaultdict
import nvidia_smi as nv
from pf_tm import PF_TM
import psutil

pf_tm = PF_TM(False)  # debug to print time
gcnmp = GCNBP.GetCtanNameByPID()  # class to get container name from process pid


def get_Um(conf_dir, usr_data_dir, host_public_dir, crypt_key, init_port_base, port_num=10):
    try:
        u = __Um(conf_dir, usr_data_dir, host_public_dir, crypt_key, init_port_base, port_num)
    except Exception:
        traceback.print_exc()
        return False
    if not u.check_pass:
        return False
    return u


def fix_Um(conf_dir, usr_data_dir, host_public_dir, crypt_key, init_port_base, port_num=10):
    u = __Um(conf_dir, usr_data_dir, host_public_dir, crypt_key, init_port_base, port_num)
    u.fix()


class __Um(object):
    def __init__(self, conf_dir, usr_data_dir, host_public_dir, crypt_key, init_port_base=9000, port_num=10):
        # get the containers
        self.api_client = docker.APIClient()
        self.client = docker.from_env()
        self.containers = self.client.containers
        # dir path
        self.public_dir = host_public_dir
        self.user_data_dir = usr_data_dir
        self.conf_dir = conf_dir
        # get the data dict
        self.data_path = os.path.join(self.conf_dir, 'data_dt')
        self.init_port_base = init_port_base
        self.port_num = port_num
        # data
        self.data_dt = {}
        self.user_port_dt = {}
        self.user_mail_dt = {}
        self.all_port_ls = []
        self.user_ls = []
        self.user_starttime_dt = {}

        self.idx_user = 0
        self.idx_passwd = 1
        self.idx_mail = 2
        self.idx_starttime = 3

        # init the ciper
        self.__ciper = None
        self.init_ciper(key=crypt_key)
        del crypt_key

        # read the data dict
        if (not os.path.exists(self.data_path)) or os.path.getsize(self.data_path) == 0:
            self.data_dt = {str(self.init_port_base): None}
            self.save_data()
        else:
            self.load_data()

        # mail flag
        self.mail_send_flag_ls = []

        # cpu and gpu status
        nv.nvmlInit()
        self.user_stats_stream = {}
        self.pre_cpu_stats = defaultdict(lambda: [None, None])

        self.res_info = {}
        self.gpu_info = self.__get_gpu_info()

        # self check
        self.check_pass = True
        self.check_err_port = []
        self.init_check()

        self.creating_ctan_stats = {}

        # check the container running time
        self.timer = threading.Timer(5, self.fun_timer_func)
        self.timer.start()

        self.chk_stats_timer = threading.Timer(1, self.chk_stats_timer_func)
        self.chk_stats_timer.start()

    def fix(self):
        print('fix start')
        for port in self.check_err_port:
            self.data_dt[port] = None
        self.save_data()
        print('fix done')

    def init_check(self):
        for port, val in self.data_dt.items():
            if val is None:
                continue
            user = val[0]
            try:
                self.containers.get(user)  # whether the containers exist
                port22 = self.get_ctan_port_base(user, 22)  # whether the port is right
                if str(port) != str(port22):
                    raise Exception
            except:
                self.check_pass = False
                print('There have a bad container: {}, its ssh port is {}'.format(user, port))
                self.check_err_port.append(str(port))
        return

    # get a container's base port
    def get_ctan_port_base(self, user_name, port, proto='tcp'):
        rawInfo = self.api_client.inspect_container(user_name)
        return rawInfo['HostConfig']['PortBindings'][str(port) + '/' + proto][0]['HostPort']

    # get a container's ip
    def get_ctan_ip(self, user_name):
        rawInfo = self.api_client.inspect_container(user_name)
        return rawInfo['NetworkSettings']['IPAddress']

    # get the container's name from process pid
    @staticmethod
    def get_ctan_name_by_pid(pid):
        try:
            ctan_name = gcnmp.get_ctan_name_by_pid(pid)
        except Exception:
            traceback.print_exc()
            ctan_name = None
        # 如果找不到容器名，就当为服务器名处理
        if ctan_name is None:
            ctan_name = 'server'
        return ctan_name

    # get the container's up time
    def get_ctan_up_time(self, user_name):
        starttime_stamp = self.user_starttime_dt[user_name]
        nowtime_stamp = time.time()
        sec_int = int(nowtime_stamp - starttime_stamp)
        all_m, s = divmod(sec_int, 60)
        h, m = divmod(all_m, 60)
        str_uptime = '{:d}:{:0>2d}:{:0>2d}'.format(h, m, s)
        return str_uptime, h, m, s

    # reset a container's start time
    def reset_starttime(self, username):
        p = self.user_port_dt[username]
        newtime_stamp = int(time.time())
        self.data_dt[p][self.idx_starttime] = newtime_stamp
        self.save_data()
        return True

    # change password
    def change_ctan_passwd(self, user_name, new_passwd):
        self.load_data()
        port = self.user_port_dt[user_name]
        new_hashed_pw = bcrypt.hashpw(new_passwd.encode(), bcrypt.gensalt(10))
        self.data_dt[port][self.idx_passwd] = new_hashed_pw
        self.save_data()
        return True

    # change mail
    def change_mail(self, user_name, new_mail):
        p = self.user_port_dt[user_name]
        self.data_dt[p][self.idx_mail] = new_mail
        self.save_data()
        return True

    # get info about all containers
    def get_all_ctans(self):
        # print('get_all_ctans')
        res = {}
        # 读取本地文件刷新
        self.load_data()

        user_port_dt = self.user_port_dt
        for name in user_port_dt:
            try:
                res[name] = []
                res[name].append(name)
                res[name].append(user_port_dt[name] + "~" + str(int(user_port_dt[name]) + 9))
                if self.containers.get(name).status == "running":
                    res[name].append("RUNNING")
                    IP = self.get_ctan_ip(name)
                    res[name].append(IP)
                    duration_str = (self.get_ctan_up_time(name))[0]
                    res[name].append(duration_str)
                else:
                    res[name].append("STOPED")
                    res[name].append("NONE")
                    res[name].append("00:00:00")
            except KeyError:
                print("[Manager]: Data file error with " + name)
        return res

    # get the container's simple status, running or stoped
    def get_ctans_status(self):
        self.load_data()
        user_port_dt = self.user_port_dt
        ret = {'running': [], 'stoped': []}
        for name in user_port_dt:
            if self.containers.get(name).status == 'running':
                ret['running'].append(name)
            else:
                ret['stoped'].append(name)
        return ret

    # verify password
    def valid_user_passwd(self, user_name, passwd, admin=False):
        if admin:  # check the admin passwd
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            validiflag = True
            try:
                ssh.connect('127.0.0.1', 22, user_name, passwd)
                print('admin true')
            except:
                validiflag = False
                print('admin false')
            finally:
                ssh.close()
            return validiflag

        port = self.user_port_dt[user_name]
        hashed_pw = self.data_dt[port][self.idx_passwd]
        return bcrypt.checkpw(passwd.encode(), hashed_pw)

    def generate_new_port_base(self):
        self.load_data()
        new_port = None

        def is_idle(port, ctnu=1):
            idle_flag = True
            for i in range(0, 0 + ctnu):
                sTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sUDP = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sTCP.bind(('', int(port) + i))
                    sTCP.listen(1)
                    sUDP.bind(('', int(port) + i))
                except:
                    traceback.print_exc()
                    idle_flag = False
                finally:
                    sTCP.close()
                    sUDP.close()
                    if not idle_flag:
                        break
            return idle_flag

        try:
            new_port_ls = [port for port, val in self.data_dt.items() if val is None]
            for new_port in new_port_ls:
                if is_idle(new_port, self.port_num):
                    return int(new_port)
            new_port = None  # if the port is not idle, that set new_port to be None
        except Exception:
            pass
        finally:
            if new_port is None:  # it means that all ports is used or the port is not idle
                port_num_ls = [int(x) for x in self.all_port_ls]
                new_port = max(port_num_ls) + self.port_num
                while not is_idle(new_port, self.port_num):
                    new_port = new_port + self.port_num
        return int(new_port)

    def create_user(self, user_name, passwd, mail=None):
        self.creating_ctan_stats[user_name] = 'creating'
        try:
            # 检查名字是否重合和密码是否小于6位
            assert user_name not in self.user_port_dt.keys(), 'user name already exist'
            assert len(passwd) >= 6, 'passwd len is smaller than 6'
            # 获得镜像
            img = "kunxinz/lab-vm:xfce_cuda8.0"
            # 获得端口映射
            port_base = self.generate_new_port_base()
            hport = list(range(int(port_base), int(port_base) + int(self.port_num)))
            cport = list(range(8080, 8080 + int(self.port_num) - 2))
            cport = [22, 5901] + cport  # ssh vnc 8080 8081 ... 8087
            port_map = dict(zip(cport, hport))

            # generate the volume map, create the home and back dir
            host_public_dir = self.public_dir
            ctan_public_dir = '/data/PUBLIC'

            host_user_home = os.path.join(self.user_data_dir, user_name, 'home')
            ctan_user_home = os.path.join('/home', user_name)

            # 清除原先的目录
            if os.path.exists(host_user_home):
                print('old user {} home existed'.format(user_name))
                # shutil.rmtree(host_user_home)  # remove the old home dir
            os.makedirs(host_public_dir, exist_ok=True)
            os.makedirs(host_user_home, exist_ok=True)

            # base mount
            public_mount = docker.types.Mount(target=ctan_public_dir,
                                              source=host_public_dir,
                                              type='bind',
                                              read_only=True,
                                              propagation='rslave'
                                              )

            # user mount
            user_vol_map = {host_user_home: {'bind': ctan_user_home, 'mode': 'rw'}
                            }

            # 合并
            vol_map = user_vol_map

            total_mem = psutil.virtual_memory().total
            limit_mem = '{:d}g'.format(int(total_mem * 0.8 / 1024 / 1024 / 1024))
            limit_sh_mem = '{:d}g'.format(int(total_mem * 0.5 / 1024 / 1024 / 1024))

            # 生成容器
            self.containers.run(img,
                                # 命令
                                command='/root/heart.sh',
                                # 后台
                                detach=True,
                                # 主机名字
                                hostname=user_name + 'VM',
                                # 容器名字
                                name=user_name,
                                # 工作目录
                                working_dir=os.path.join('/home', user_name),
                                # 端口
                                ports=port_map,
                                # 内存限制
                                mem_limit=limit_mem,
                                memswap_limit=limit_mem,
                                # 超级权限
                                # privileged = True , \
                                # 精细化特权,允许加载网络端口和重启
                                cap_add=['NET_ADMIN'],
                                # 允许使用的CPU范围，最后一个保留
                                cpuset_cpus='0-{:d}'.format(cpu_count() - 2),
                                # 共享内存大小
                                shm_size=limit_sh_mem,
                                # 挂在卷
                                volumes=vol_map,
                                # more detail mount
                                mounts=[public_mount],
                                # 运行环境
                                runtime='nvidia',
                                # NVIDIA 环境变量
                                environment=["NVIDIA_DRIVER_CAPABILITIES=all"]
                                )
            time.sleep(1)

            ctan = self.containers.get(user_name)
            # 复制初始化文件到用户home文件夹下
            cmd = 'cp -r {} {}'.format(self.conf_dir, host_user_home)
            os.system(cmd)
            # 生成初始化脚本
            sh_path = os.path.join('/home', user_name, os.path.split(self.conf_dir)[1], 'createUser.sh')
            init_str = "/bin/bash -c \"echo '{} {}' | {}\"".format(user_name, passwd, sh_path)
            # 执行初始化脚本
            ctan.exec_run(init_str)
            ctan.exec_run('/bin/bash /etc/rc.local')
            # remove the conf dir
            shutil.rmtree(os.path.join(host_user_home, os.path.split(self.conf_dir)[1]))
            # 成功后更新存储表
            start_time = int(time.time())

            hash_pw = bcrypt.hashpw(passwd.encode('utf_8'), bcrypt.gensalt(10))
            self.data_dt[str(port_base)] = [user_name, hash_pw, mail, start_time]
            self.save_data()
            return True
        except Exception as ex:
            traceback.print_exc()
            self.creating_ctan_stats[user_name] = 'error'
            print('return False')
            return False


    def get_creating_ctan_stats(self, user_name):
        return self.creating_ctan_stats[user_name]

    def start(self, user_name):
        try:
            ctan = self.containers.get(user_name)

            p = self.user_port_dt[user_name]
            self.data_dt[p][self.idx_starttime] = int(datetime.now().timestamp())
            self.save_data()
            # 需要在启动前写入文件，否则容易启动中时数据还没有更新完毕导致时间错误
            ctan.start()
            # exec the rc.local shell
            ctan.exec_run('/bin/bash /etc/rc.local')

        except Exception as ex:
            print(ex)
            return False
        return True

    def stop(self, user_name):
        try:
            ctan = self.containers.get(user_name)
            ctan.exec_run('/bin/bash /etc/rc.preShutdown')
            ctan.stop()
            # self.lvm_mount.umount_by_name(user_name)
        except Exception as ex:
            print(ex)
            return False
        return True

    def remove(self, user_name):
        try:
            ctan = self.containers.get(user_name)
            ctan.stop()
            ctan.remove()
            # write the None into file
            port = self.user_port_dt[user_name]
            self.data_dt[port] = None
            self.save_data()

            # remove the umount point
            # self.lvm_mount.umount_by_name(user_name)
        except:
            traceback.print_exc()
            return False
        return True

    def init_ciper(self, key):
        # pad up with 0, the key len must be 16, 24, 32 byes long
        length = 16
        count = len(key)
        add = length - (count % length)
        key = key + ('\0' * add)
        self.__ciper = AES.new(key)
        del key

    def save_data(self):
        # print('save data start')
        # data_byte = bytes(json.dumps(self.data_dt), encoding='utf8')
        data_byte = dill.dumps(self.data_dt)
        # ctypt the data
        length = 16
        count = len(data_byte)
        add = length - (count % length)
        data_byte = data_byte + (b'\0' * add)
        if self.__ciper is not None:
            wri_byte = self.__ciper.encrypt(data_byte)
        else:
            wri_byte = data_byte
        # save it
        with open(self.data_path, 'wb') as f:
            dill.dump(wri_byte, f)  # convert to hex format and save it
        # refresh the data
        self.data_dt = dill.loads(data_byte)
        self.all_port_ls = list(self.data_dt.keys())
        self.user_mail_dt = {val[self.idx_user]: (val[self.idx_mail] if len(val) >= 3 else None) for val in
                             self.data_dt.values() if val is not None}
        self.user_port_dt = {val[self.idx_user]: port for port, val in self.data_dt.items() if val is not None}
        self.user_starttime_dt = {val[self.idx_user]: val[self.idx_starttime] for val in self.data_dt.values() if
                                  val is not None}
        # print('save date end')

    def load_data(self):
        # print('load data start')
        with open(self.data_path, 'rb') as f:
            rd_byte = dill.load(f)
        data_byte = self.__ciper.decrypt(rd_byte)
        data_byte = data_byte.rstrip(b'\0')
        self.data_dt = dill.loads(data_byte)
        # 兼容旧数据
        for key, val in self.data_dt.items():
            if val is not None and len(val) == 2:
                self.data_dt[key] = list(val) + [None, int(time.time())]
        self.all_port_ls = list(self.data_dt.keys())
        self.user_mail_dt = {val[self.idx_user]: val[self.idx_mail] for val in self.data_dt.values() if val is not None}
        self.user_port_dt = {val[self.idx_user]: port for port, val in self.data_dt.items() if val is not None}
        self.user_starttime_dt = {val[self.idx_user]: val[self.idx_starttime] for val in self.data_dt.values() if
                                  val is not None}
        # print('load data end')

    def send_mail(self, mail_addr):
        mail_subject = '服务器倒计时关闭通知'
        mail_txt = '你好，服务器还有12小时即将关闭，如果需要继续工作，请前往服务器主界面重置计时器'
        cmd = 'echo {} | mail -s {} {}'.format(mail_txt, mail_subject, mail_addr)
        os.system(cmd)

    # 对容器运行时间检查
    def fun_timer_func(self):
        self.check_ctan_run_time()
        self.timer = threading.Timer(5, self.fun_timer_func)
        self.timer.start()

    def chk_stats_timer_func(self):
        # 获得运行容器的状态
        # print('chk')
        try:
            ctans_dt = self.get_ctans_status()
            userList = ctans_dt['running']
            for name in userList:
                self.res_info[name] = self.__get_ctan_verbose_stats(name)

            self.gpu_info = self.__get_gpu_info()
        except:
            traceback.print_exc()

        self.chk_stats_timer = threading.Timer(1, self.chk_stats_timer_func)
        self.chk_stats_timer.start()

    def get_ctan_verbose_stats(self, name):
        if name in self.res_info:
            return self.res_info[name]
        else:
            return None

    def get_gpu_info(self):
        return self.gpu_info

    # 返回容器的资源信息
    def __get_ctan_verbose_stats(self, name):
        # 连续获得参数
        def graceful_chain_get(d, *args, default=None):
            t = d
            for a in args:
                try:
                    t = t[a]
                except (KeyError, ValueError, TypeError, AttributeError):
                    return default
            return t

        # 计算cpu使用占比
        def calculate_cpu_percent2(d, previous_cpu_total=None, previous_cpu_system=None):
            cpu_percent = 0.0
            cpu_total = float(d["cpu_stats"]["cpu_usage"]["total_usage"])
            if previous_cpu_total is None:
                previous_cpu_total = cpu_total
            cpu_delta = cpu_total - previous_cpu_total
            cpu_system = float(d["cpu_stats"]["system_cpu_usage"])
            if previous_cpu_system is None:
                previous_cpu_system = cpu_system
            system_delta = cpu_system - previous_cpu_system
            online_cpus = d["cpu_stats"].get("online_cpus", len(d["cpu_stats"]["cpu_usage"]["percpu_usage"]))
            if system_delta > 0.0:
                cpu_percent = (cpu_delta / system_delta) * online_cpus * 100.0
            return cpu_percent, cpu_total, cpu_system

        # 计算IO
        def calculate_blkio_bytes(d):
            """
            :param d:
            :return: (read_bytes, wrote_bytes), ints
            """
            bytes_stats = graceful_chain_get(d, "blkio_stats", "io_service_bytes_recursive")
            if not bytes_stats:
                return 0, 0
            r = 0
            w = 0
            for s in bytes_stats:
                if s["op"] == "Read":
                    r += s["value"]
                elif s["op"] == "Write":
                    w += s["value"]
            return r, w

        # 计算网络
        def calculate_network_bytes(d):
            """
            :param d:
            :return: (received_bytes, transceived_bytes), ints
            """
            networks = graceful_chain_get(d, "networks")
            if not networks:
                return 0, 0
            r = 0
            t = 0
            for if_name, data in networks.items():
                r += data["rx_bytes"]
                t += data["tx_bytes"]
            return r, t

        def calculate_mem_bytes(d):
            mem_limit = d['memory_stats']['limit']
            mem_usage = d['memory_stats']['usage']
            return mem_usage, mem_limit

        def parse_unit(val, scale=1000):
            unit_ls = ['B', 'KB', 'MB', 'GB']
            unit_lv = 0
            while val >= scale:
                val /= scale
                unit_lv += 1
                if unit_lv == len(unit_ls) - 1:
                    break
            return '{:.2f} {}'.format(val, unit_ls[unit_lv])

        if name not in self.user_stats_stream:
            # print('add {} into user_stats_stream'.format(name))
            ctan = self.containers.get(name)
            self.user_stats_stream[name] = ctan.stats(decode=True)

        # print(name)
        pf_tm.tic()
        # 通过数据流获取信息
        raw_stats = self.user_stats_stream[name].__next__()
        pre_cpu_stats = self.pre_cpu_stats[name]
        # pf_tm.toc('get stream')
        # cpu
        cpu_percent, cpu_total, cpu_system = calculate_cpu_percent2(raw_stats, pre_cpu_stats[0], pre_cpu_stats[1])
        self.pre_cpu_stats[name] = [cpu_total, cpu_system]  # 更新usage
        # blk
        read_blk, write_blk = calculate_blkio_bytes(raw_stats)
        # net
        read_net, write_net = calculate_network_bytes(raw_stats)
        # mem
        mem_usage, mem_limit = calculate_mem_bytes(raw_stats)

        # pf_tm.toc('get cpu')

        # user gpu
        gpu_all_mem, gpu_used_mem, gpu_used_pcnt = 0, 0, 0
        gpu_num = nv.nvmlDeviceGetCount()
        for gpu_idx in range(gpu_num):
            h = nv.nvmlDeviceGetHandleByIndex(gpu_idx)
            running_process_obj_ls = nv.nvmlDeviceGetComputeRunningProcesses(h)
            for obj in running_process_obj_ls:
                process_pid = obj.pid
                process_raw_gpu_mem = obj.usedGpuMemory
                ctan_name = self.get_ctan_name_by_pid(process_pid)
                if ctan_name == name:
                    gpu_used_mem += process_raw_gpu_mem

            gpu_all_mem += nv.nvmlDeviceGetMemoryInfo(h).total
            # print('{} {}'.format(each_gpu_allmem, gpu_all_mem))

        # pf_tm.toc('get gpu')

        ret_dt = {}
        ret_dt['id'] = raw_stats['id']
        ret_dt['pid'] = str(raw_stats['pids_stats']['current'])

        ret_dt['cpu_percent'] = '{:.2f}'.format(cpu_percent)
        ret_dt['read_blk'] = parse_unit(read_blk)
        ret_dt['write_blk'] = parse_unit(write_blk)
        ret_dt['read_net'] = parse_unit(read_net)
        ret_dt['write_net'] = parse_unit(write_net)
        ret_dt['mem_usage'] = parse_unit(mem_usage, scale=1024)
        ret_dt['mem_limit'] = parse_unit(mem_limit, scale=1024)

        ret_dt['mem_usage_pcnt'] = '{:.2f}'.format(mem_usage / mem_limit * 100)

        ret_dt['gpu_mem_usage'] = parse_unit(gpu_used_mem, 1024)
        ret_dt['gpu_mem_limit'] = parse_unit(gpu_all_mem, 1024)
        ret_dt['gpu_mem_usage_pcnt'] = '{:.2f}'.format(gpu_used_mem / gpu_all_mem * 100)

        return ret_dt

    def __get_gpu_info(self):
        def parse_unit(val, scale=1000):
            unit_ls = ['B', 'KB', 'MB', 'GB']
            unit_lv = 0
            while val >= scale:
                val /= scale
                unit_lv += 1
                if unit_lv == len(unit_ls) - 1:
                    break
            return '{:.2f} {}'.format(val, unit_ls[unit_lv])

        sum_info = []
        process_ls = []

        nv.nvmlInit()
        gpu_num = nv.nvmlDeviceGetCount()
        # 遍历每块卡
        for gpu_idx in range(gpu_num):
            h = nv.nvmlDeviceGetHandleByIndex(gpu_idx)
            dev_name = nv.nvmlDeviceGetName(h).decode()
            raw_total_mem = nv.nvmlDeviceGetMemoryInfo(h).total
            total_mem = parse_unit(raw_total_mem, 1024)
            raw_used_mem = nv.nvmlDeviceGetMemoryInfo(h).used
            used_mem = parse_unit(raw_used_mem, 1024)
            gpu_util = '{:.2f}'.format(nv.nvmlDeviceGetUtilizationRates(h).gpu)
            gpu_mem_util = '{:.2f}'.format(raw_used_mem * 100 / raw_total_mem)
            tmp = {}
            tmp['gpu_idx'] = str(gpu_idx)
            tmp['dev_name'] = dev_name
            tmp['total_mem'] = total_mem
            tmp['used_mem'] = used_mem
            tmp['gpu_util'] = gpu_util
            tmp['gpu_mem_util'] = gpu_mem_util
            sum_info.append(tmp)

            running_process_obj_ls = nv.nvmlDeviceGetComputeRunningProcesses(h)
            for obj in running_process_obj_ls:
                process_pid = obj.pid
                process_type = 'C'
                process_raw_gpu_mem = obj.usedGpuMemory
                process_name = nv.nvmlSystemGetProcessName(process_pid).decode()
                ctan_name = self.get_ctan_name_by_pid(process_pid)

                tmp = {}
                tmp['gpu_idx'] = str(gpu_idx)
                tmp['dev_name'] = dev_name
                tmp['process_pid'] = str(process_pid)
                tmp['process_type'] = process_type
                tmp['process_name'] = process_name
                tmp['process_gpu_mem'] = parse_unit(process_raw_gpu_mem, 1024)
                tmp['ctan_name'] = ctan_name
                process_ls.append(tmp)

            running_process_obj_ls = nv.nvmlDeviceGetGraphicsRunningProcesses(h)
            for obj in running_process_obj_ls:
                process_pid = obj.pid
                process_type = 'G'
                process_raw_gpu_mem = obj.usedGpuMemory
                process_name = nv.nvmlSystemGetProcessName(process_pid).decode()
                ctan_name = self.get_ctan_name_by_pid(process_pid)

                tmp = {}
                tmp['gpu_idx'] = str(gpu_idx)
                tmp['dev_name'] = dev_name
                tmp['process_pid'] = str(process_pid)
                tmp['process_type'] = process_type
                tmp['process_name'] = process_name
                tmp['process_gpu_mem'] = parse_unit(process_raw_gpu_mem, 1024)
                tmp['ctan_name'] = ctan_name
                process_ls.append(tmp)
        return sum_info, process_ls

    def check_ctan_run_time(self):
        # 读取本地文件刷新
        # print('check run time')
        self.load_data()
        user_port_dt = self.user_port_dt
        for name in user_port_dt:
            try:
                if self.containers.get(name).status == "running":
                    up_time = self.get_ctan_up_time(name)
                    # print('{} run time is {}'.format(name, up_time))
                    up_hour = up_time[1]

                    # print('{} is running {} hours'.format(name, up_hour))
                    if 60 < up_hour < 72:
                        # send emil
                        mail_addr = self.user_mail_dt[name]
                        if mail_addr is not None and name not in self.mail_send_flag_ls:
                            print('send mail {}'.format(mail_addr))
                            self.send_mail(mail_addr)
                            self.mail_send_flag_ls.append(name)
                    elif up_hour >= 72:
                        print('stop {}'.format(name))
                        # 这里有可能直接一启动就已经超时，所以需要处理
                        if name in self.mail_send_flag_ls:
                            self.mail_send_flag_ls.remove(name)
                        self.stop(name)
                        pass
                    elif up_hour < 60:
                        pass

            except KeyError:
                print("[Manager]: Data file error with " + name)


def main():
    # srv_host_name = 'cmax'
    docker_conf_dir = '/home/server03/docker_for_git/docker_conf_dir'
    docker_user_dir = '/home/server03/docker_for_git/docker_user_dir'
    docker_public_dir = '/home/server03/docker_for_git/docker_public_dir'
    passwd = '1234567890'

    u = get_Um(docker_conf_dir, docker_user_dir, docker_public_dir, passwd, 29000)

    # print(os.path.realpath(__file__))

if __name__ == '__main__':
    main()
