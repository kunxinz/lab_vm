#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
@author: kun
"""
__author__ = "kunxinz"
__email__ = "kunxinz@qq.com"

from datetime import datetime
import threading
import os, shutil, traceback
import time
import socket
import paramiko
from collections import defaultdict
import configparser, copy

# venv
import psutil
import bcrypt
import nvidia_smi as nv
import docker
import dill
from Crypto.Cipher import AES
import GetCtanNameByPID as GCNBP

# mail
from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr


gcnmp = GCNBP.GetCtanNameByPID()  # class to get container name from process pid

def get_Um(conf_dir, crypt_key):
    try:
        u = __Um(conf_dir, crypt_key)
    except Exception:
        traceback.print_exc()
        return False
    if not u.check_pass:
        return False
    return u

class __Um(object):
    def __init__(self, conf_path, crypt_key):
        def init_check():
            # 返回端口基地址
            def get_ctan_port_base(user_name, port, proto='tcp'):
                rawInfo = self.api_client.inspect_container(user_name)
                return rawInfo['HostConfig']['PortBindings'][str(port) + '/' + proto][0]['HostPort']

            for port, val in self.port_data_ls_dt.items():
                if val is None:
                    continue
                user = val[0]
                try:
                    self.containers.get(user)  # 容器是否存在
                    port22 = get_ctan_port_base(user, 22)  # 容器端口是否和数据对应
                    if str(port) != str(port22):
                        raise Exception
                except:
                    self.check_pass = False
                    print('There is a bad container: {}, the ssh port is {}'.format(user, port))
                    self.check_err_port.append(str(port))
            return

        def init_ciper(key):
            # pad up with 0, the key len must be 16, 24, 32 byes long
            length = 16
            count = len(key)
            add = length - (count % length)
            key = key + ('\0' * add)
            self.__ciper = AES.new(key)
            del key

        # 配置参数默认文件
        conf = configparser.ConfigParser(allow_no_value=True)
        conf.read(conf_path)

        # dir path
        file_dir = os.path.dirname(__file__)  # 当前文件夹

        tmp = conf.get('lab_vm', 'docker_conf_dir')
        self.docker_conf_dir = os.path.join(file_dir, 'docker_conf_dir') if tmp == "" else tmp
        tmp = conf.get('lab_vm', 'docker_user_dir')
        self.docker_user_dir = os.path.join(file_dir, 'docker_user_dir') if tmp == "" else tmp
        tmp = conf.get('lab_vm', 'docker_public_dir')
        self.docker_public_dir = os.path.join(file_dir, 'docker_public_dir') if tmp == "" else tmp

        # 镜像名
        self.df_img = conf.get('ctan_default_args', 'img_name')

        # 额外挂载目录
        tmp = conf.get('ctan_default_args', 'extra_normal_static_vol')
        self.ex_nm_st_vol_str = '' if tmp == "" else tmp

        # 内存百分比和绝对值限制
        self.df_mem_pcnt = float(conf.get('ctan_default_args', 'mem_limit_pcnt'))
        self.df_mem_abs = conf.get('ctan_default_args', 'mem_limit_abs')
        assert 0 < self.df_mem_pcnt <= 1, 'mem_limit_pcnt value error'

        # 共享内存百分比和绝对值限制
        self.df_shm_pcnt = float(conf.get('ctan_default_args', 'shm_limit_pcnt'))
        self.df_shm_abs = conf.get('ctan_default_args', 'shm_limit_abs')
        assert 0 < self.df_shm_pcnt <= 1, 'shm_pcnt value error'

        # cpu主机保留核心数
        self.df_cpu_rest_core_num = int(conf.get('ctan_default_args', 'cpu_rest_core_num'))

        # port args
        self.port_start = int(conf.get('lab_vm', 'docker_port_start'))
        self.port_step = int(conf.get('lab_vm', 'docker_port_step'))
        assert self.port_step >=4, 'port_step is less than 4'
        self.port_stop = int(conf.get('lab_vm', 'docker_port_stop'))

        assert isinstance(self.df_cpu_rest_core_num, int), 'cpu_rest_core_num value error'

        # get the data dict
        self.data_path = os.path.join(self.docker_conf_dir, 'data_dt')

        # get the containers
        self.api_client = docker.APIClient()
        self.client = docker.from_env()
        self.containers = self.client.containers

        # data
        self.port_data_ls_dt = {}
        self.avail_port_st = set()
        self.used_port_st = set()
        self.stand_port_st = set(range(self.port_start, self.port_stop))
        self.user_port_dt = {}
        self.user_mail_dt = {}
        self.user_ls = []
        self.user_starttime_dt = {}

        self.idx_user = 0
        self.idx_passwd = 1
        self.idx_mail = 2
        self.idx_starttime = 3
        self.idx_remark = 4
        self.idx_phone = 5

        # init the ciper
        self.__ciper = None
        init_ciper(key=crypt_key)
        del crypt_key

        # read the data dict
        if (not os.path.exists(self.data_path)) or os.path.getsize(self.data_path) == 0 :
            self.port_data_ls_dt = {str(self.port_start): None}
            self.avail_port_st = set(range(self.port_start, self.port_stop))
            self.save_data()
        else:
            self.load_data()

        # cpu 统计变量
        self.user_stats_stream = {}
        self.pre_cpu_stats = defaultdict(lambda : [None, None])

        # 自检
        self.check_pass = True
        self.check_err_port = []
        init_check()

        # nvidia
        nv.nvmlInit()
        self.res_info = {}
        self.gpu_info = self.__get_gpu_info()

        # 定期检查容器的运行时间，周期1min
        self.time_check_flag = conf.get('ctan_default_args', 'time_check_flag') == str(True)
        self.checkTimePeriod = 60
        self.timer = threading.Timer(self.checkTimePeriod, self.fun_timer_func)
        self.timer.start()
        self.mail_send_flag_ls = []
        self.time_send_mail = int(conf.get('ctan_default_args', 'time_send_mail'))
        self.time_stop_ctan = int(conf.get('ctan_default_args', 'time_stop_ctan'))

        # 定期检查资源状态，周期2s
        self.updateStatusPeriod = 2
        self.chk_stats_timer = threading.Timer(self.updateStatusPeriod, self.chk_stats_timer_func)
        self.chk_stats_timer.start()

    # 容器基本操作
    def create_user(self, user_name, passwd, mail=None, remark='无', phone='0'):
        # 寻找一个新端口给容器使用
        def generate_new_start_port():
            self.load_data()
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
                        idle_flag = False
                    finally:
                        sTCP.close()
                        sUDP.close()
                        if not idle_flag:
                            break
                return idle_flag

            tmp_avail_port_st = copy.deepcopy(self.avail_port_st)
            while True:
                assert tmp_avail_port_st != set(), 'there is no available port'
                tmp_min_port = min(tmp_avail_port_st)
                tmp_ready_port_st = set(range(tmp_min_port, tmp_min_port+self.port_step))  # 准备申请连续的端口集
                if not tmp_ready_port_st.issubset(self.avail_port_st):  # 没有连续的可用端口集
                    tmp_avail_port_st = tmp_avail_port_st.difference(tmp_ready_port_st)  # 去除这些连续端口集
                    continue
                else:
                    # 找到一个可用连续端口集，检测是否被占用
                    if not is_idle(tmp_min_port, self.port_step):
                        tmp_avail_port_st = tmp_avail_port_st.difference(tmp_ready_port_st)
                        continue
                    else:
                        return int(tmp_min_port)

        try:
            # 检查名字是否重合和密码是否小于6位
            assert user_name not in self.user_port_dt.keys(), 'user name already exist'
            assert len(passwd) >= 6, 'passwd len is smaller than 6'
            # 获得镜像
            img = self.df_img
            # 获得端口映射
            start_port = generate_new_start_port()
            hport = list(range(int(start_port), int(start_port) + self.port_step))
            cport = list(range(8080, 8080 + self.port_step - 2))
            cport = [22, 5901] + cport  # ssh vnc 8080 8081 ... 8087
            port_map = dict(zip(cport, hport))

            # generate the volume map, create the home and back dir
            host_public_dir = self.docker_public_dir
            ctan_public_dir = '/data/PUBLIC'

            host_user_home = os.path.join(self.docker_user_dir, user_name, 'home')
            ctan_user_home = os.path.join('/home', user_name)

            # 清除原先的目录
            # if os.path.exists(host_user_home):
            #     shutil.rmtree(host_user_home)  # remove the old home dir
            os.makedirs(host_public_dir, exist_ok=True)
            os.makedirs(host_user_home, exist_ok=True)

            # 挂载额外的常规静态目录
            ex_sa_vol_dt = {}
            ex_vol_ls = self.ex_nm_st_vol_str.split(';')
            for ex_vol in ex_vol_ls:
                ex_vol = ex_vol.strip()  # 去除空格
                if ex_vol == '' or ex_vol is None:
                    continue
                vol_ls = ex_vol.split(':')  # host：bind：ctan：mode
                ex_sa_vol_dt.update({vol_ls[0]: {vol_ls[1]: vol_ls[2], 'mode': vol_ls[3]}})

            # 挂载动态home目录
            user_vol_dt = {host_user_home: {'bind': ctan_user_home, 'mode': 'rw'}}

            # 合并常规目录
            vol_map = dict(ex_sa_vol_dt, **user_vol_dt)

            # 挂载动态公共只读目录
            public_mount = docker.types.Mount(target=ctan_public_dir,
                                              source=host_public_dir,
                                              type='bind',
                                              read_only=True,
                                              propagation='rslave'
                                              )

            # 内存限制参数设置
            total_mem = psutil.virtual_memory().total
            limit_mem = '{:d}g'.format(int(total_mem * float(self.df_mem_pcnt) / (1024*3))) \
                if self.df_mem_abs == '' else self.df_mem_abs
            limit_sh_mem = '{:d}g'.format(int(total_mem * float(self.df_shm_pcnt) / (1024*3))) \
                if self.df_shm_abs == '' else self.df_shm_abs

            # CPU剩余参数设置
            if self.df_cpu_rest_core_num >= psutil.cpu_count():
                print('warning, cpu reset core if larger than real count')
                cpuset_cpus = '0-{:d}'.format(psutil.cpu_count() - 1)
            else:
                cpuset_cpus = '0-{:d}'.format(psutil.cpu_count() - 1 - self.df_cpu_rest_core_num)

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
                                # 精细化特权,允许加载网络端口和重启
                                cap_add=['NET_ADMIN'],
                                # 允许使用的CPU范围，最后一个保留
                                cpuset_cpus=cpuset_cpus,
                                # 共享内存大小
                                shm_size=limit_sh_mem,
                                # 挂在卷
                                volumes=vol_map,
                                # more detail mount
                                mounts=[public_mount],
                                # 运行环境
                                runtime='nvidia',
                                # NVIDIA 环境变量
                                environment=["NVIDIA_DRIVER_CAPABILITIES=all"],
                                # 超级权限
                                # privileged = True , \
                                )

            time.sleep(1)

            ctan = self.containers.get(user_name)
            # 复制初始化文件到用户home文件夹下
            os.system('cp -r ' + self.docker_conf_dir + ' ' + host_user_home)
            # 生成初始化脚本
            init_str = '/bin/bash -c \"echo ' \
                       + "'" + user_name + " " + passwd + "'" \
                       + ' | ' + os.path.join('/home', user_name, os.path.split(self.docker_conf_dir)[1], 'createUser.sh') \
                       + '\" '
            # 执行初始化脚本
            ctan.exec_run(init_str)
            ctan.exec_run('/bin/bash /etc/rc.local')
            # remove the conf dir
            shutil.rmtree(os.path.join(host_user_home, os.path.split(self.docker_conf_dir)[1]))

            # 成功后更新存储表
            start_time = int(time.time())

            hash_pw = bcrypt.hashpw(passwd.encode('utf_8'), bcrypt.gensalt(10))
            self.port_data_ls_dt[str(start_port)] = [user_name, hash_pw, mail, start_time, remark, phone]
            self.avail_port_st = self.avail_port_st.difference(set(range(start_port, start_port+self.port_step)))
            self.save_data()
            return True
        except Exception:
            traceback.print_exc()
            return False

    def start(self, user_name):
        try:
            ctan = self.containers.get(user_name)

            p = self.user_port_dt[user_name]
            self.port_data_ls_dt[p][self.idx_starttime] = int(datetime.now().timestamp())
            self.save_data()
            # 需要在启动前写入文件，否则容易启动中时数据还没有更新完毕导致时间错误
            ctan.start()
            # exec the rc.local shell
            ctan.exec_run('/bin/bash /etc/rc.local')

            # self.lvm_mount.mount_by_name(user_name)
        except:
            traceback.print_exc()
            return False
        return True

    def stop(self, user_name):
        try:
            ctan = self.containers.get(user_name)
            ctan.exec_run('/bin/bash /etc/rc.preShutdown')
            ctan.stop()
            # self.lvm_mount.umount_by_name(user_name)
        except:
            traceback.print_exc()
            return False
        return True

    def remove(self, user_name):
        try:
            ctan = self.containers.get(user_name)
            ctan.stop()
            ctan.remove()
            # write the None into file
            port = self.user_port_dt[user_name]
            self.avail_port_st.update(set(range(port, port+self.port_step)))
            self.save_data()

            # remove the umount point
            # self.lvm_mount.umount_by_name(user_name)
        except:
            traceback.print_exc()
            return False
        return True

    def reset_startime(self, username):
        p = self.user_port_dt[username]
        newtime_stamp = int(time.time())
        self.port_data_ls_dt[p][self.idx_starttime] = newtime_stamp
        self.save_data()
        return True


    # 功能
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
        hashed_pw = self.port_data_ls_dt[port][self.idx_passwd]
        return bcrypt.checkpw(passwd.encode(), hashed_pw)

    def save_data(self):
        save_data_ls = [self.port_data_ls_dt, self.used_port_st]
        data_byte = dill.dumps(save_data_ls)
        # ctypt the data
        length = 16
        count = len(data_byte)
        add = length - (count % length)
        data_byte = data_byte + (b'\0' * add)
        if self.__ciper is not None:
            wri_byte = self.__ciper.encrypt(data_byte)
        else:
            wri_byte = data_byte
        with open(self.data_path, 'wb') as f:
            dill.dump(wri_byte, f)  # convert to hex format and save it

        # refresh the data
        load_data_ls = dill.loads(data_byte)
        self.port_data_ls_dt = load_data_ls[0]
        self.used_port_st = load_data_ls[1]
        self.refresh_data()

    def load_data(self):
        with open(self.data_path, 'rb') as f:
            rd_byte = dill.load(f)
        data_byte = self.__ciper.decrypt(rd_byte)
        data_byte = data_byte.rstrip(b'\0')

        # refresh the data
        load_data_ls = dill.loads(data_byte)
        self.port_data_ls_dt = load_data_ls[0]
        self.used_port_st = load_data_ls[1]
        self.refresh_data()

    def refresh_data(self):
        self.avail_port_st = self.stand_port_st.difference(self.used_port_st)
        self.user_mail_dt = {val[self.idx_user]: val[self.idx_mail] for val in self.port_data_ls_dt.values()}
        self.user_port_dt = {val[self.idx_user]: port for port, val in self.port_data_ls_dt.items()}
        self.user_starttime_dt = {val[self.idx_user]: val[self.idx_starttime] for val in self.port_data_ls_dt.values()}


    # 容器高级操作（需要密码执行）
    def change_ctan_passwd(self, user_name, new_passwd):
        self.load_data()
        p = self.user_port_dt[user_name]
        new_hashed_pw = bcrypt.hashpw(new_passwd.encode(), bcrypt.gensalt(10))
        self.port_data_ls_dt[p][self.idx_passwd] = new_hashed_pw
        self.save_data()
        return True

    def change_mail(self, user_name, new_mail):
        self.load_data()
        p = self.user_port_dt[user_name]
        self.port_data_ls_dt[p][self.idx_mail] = new_mail
        self.save_data()
        return True

    def change_remark(self, user_name, new_mark):
        self.load_data()
        p = self.user_port_dt[user_name]
        self.port_data_ls_dt[p][self.idx_remark] = new_mark
        self.save_data()
        return True

    def change_phone(self, user_name, new_phone):
        self.load_data()
        p = self.user_port_dt[user_name]
        self.port_data_ls_dt[p][self.idx_phone] = new_phone
        self.save_data()
        return True

    def get_user_privacy(self, user_name):
        p = self.user_port_dt[user_name]
        phone = self.port_data_ls_dt[p][self.idx_phone]
        mail = self.port_data_ls_dt[p][self.idx_mail]
        ret = '{}, phone is {}, mail is {}'.format(user_name, phone, mail)
        return ret


    # 获取所有容器静态信息
    def get_all_ctans_status(self):
        def get_ctan_ip(user_name):
            rawInfo = self.api_client.inspect_container(user_name)
            return rawInfo['NetworkSettings']['IPAddress']

        res = {}
        # 读取本地文件刷新
        self.load_data()

        user_port_dt = self.user_port_dt
        for name in user_port_dt:
            res[name] = []
            res[name].append(name)
            res[name].append(user_port_dt[name] + "~" + str(int(user_port_dt[name]) + 9))
            if self.containers.get(name).status == "running":
                res[name].append("RUNNING")
                IP = get_ctan_ip(name)
                res[name].append(IP)
                duration_str = (self.get_ctan_up_time(name))[0]
                res[name].append(duration_str)
            else:
                res[name].append("STOPED")
                res[name].append("NONE")
                res[name].append("00:00:00")
            p = self.user_port_dt[name]
            remark = self.port_data_ls_dt[p][self.idx_remark]
            res[name].append(remark)
        return res

    def get_ctan_up_time(self, user_name):
        starttime_stamp = self.user_starttime_dt[user_name]
        nowtime_stamp = time.time()
        sec_int = int(nowtime_stamp - starttime_stamp)
        all_m, s = divmod(sec_int, 60)
        h, m = divmod(all_m, 60)
        str_uptime = '{:d}:{:0>2d}:{:0>2d}'.format(h, m, s)
        return str_uptime, h, m, s

    def get_running_ctans_ls(self):
        self.load_data()
        user_port_dt = self.user_port_dt
        ret = []
        for name in user_port_dt:
            if self.containers.get(name).status == 'running':
                ret.append(name)
        return ret


    # 监控容器运行时间
    def fun_timer_func(self):
        def send_mail( mail_dst_addr):
            mail_subject = '服务器倒计时关闭通知'
            mail_txt = '你好，服务器还有12小时即将关闭，如果需要继续工作，请前往服务器主界面重置计时器'
            # def _format_addr(s):
            #     name, addr = parseaddr(s)
            #     return formataddr((Header(name, 'utf-8').encode(), addr))
            # from_addr = 'a207_srv@163.com'
            # password = 'server010203'
            # to_addr = mail_addr
            # smtp_server = 'smtp.163.com'
            # msg = MIMEText(mail_txt, 'plain', 'utf-8')
            # msg['From'] = _format_addr('Python爱好者 <%s>' % from_addr)
            # msg['To'] = _format_addr('管理员 <%s>' % to_addr)
            # msg['Subject'] = Header(mail_subject, 'utf-8').encode()
            #
            # server = smtplib.SMTP(smtp_server, 25)
            # # server.set_debuglevel(1)
            # server.login(from_addr, password)
            # server.sendmail(from_addr, [to_addr], msg.as_string())
            # server.quit()
            cmd = 'echo {} | mail -s {} {}'.format(mail_txt, mail_subject, mail_dst_addr)
            os.system(cmd)
        if self.time_check_flag:
            self.load_data()
            user_port_dt = self.user_port_dt
            for name in user_port_dt:
                if self.containers.get(name).status == "running":
                    up_time = self.get_ctan_up_time(name)
                    up_hour = up_time[1]

                    if self.time_send_mail < up_hour < self.time_stop_ctan:
                        # send emil
                        mail_addr = self.user_mail_dt[name]
                        if mail_addr is not None and name not in self.mail_send_flag_ls:
                            # print('send mail {}'.format(mail_addr))
                            send_mail(mail_addr)
                            self.mail_send_flag_ls.append(name)
                    elif up_hour >= self.time_stop_ctan:
                        print('stop {}'.format(name))
                        # 这里有可能直接一启动就已经超时，所以需要处理
                        if name in self.mail_send_flag_ls:
                            self.mail_send_flag_ls.remove(name)
                        self.stop(name)

        self.timer = threading.Timer(self.checkTimePeriod, self.fun_timer_func)
        self.timer.start()


    # 监控容器资源
    def chk_stats_timer_func(self):
        try:
            running_ctans_ls = self.get_running_ctans_ls()
            for name in running_ctans_ls:
                self.res_info[name] = self.__get_ctan_verbose_stats(name)
            self.gpu_info = self.__get_gpu_info()
        except Exception:
            traceback.print_exc()

        self.chk_stats_timer = threading.Timer(self.updateStatusPeriod, self.chk_stats_timer_func)
        self.chk_stats_timer.start()

    @staticmethod
    def get_ctan_name_by_pid(pid):
        try:
            ctan_name = gcnmp.get_ctan_name_by_pid(pid)
        except Exception:
            ctan_name = 'none'
        return ctan_name

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
                if unit_lv == len(unit_ls)-1:
                    break
            return '{:.2f} {}'.format(val, unit_ls[unit_lv])

        if name not in self.user_stats_stream:
            # print('add {} into user_stats_stream'.format(name))
            ctan = self.containers.get(name)
            self.user_stats_stream[name] = ctan.stats(decode=True)

        # 通过数据流获取信息
        if self.containers.get(name).status == 'running':
            raw_stats = self.user_stats_stream[name].__next__()
            pre_cpu_stats = self.pre_cpu_stats[name]
        else:
            return None

        # cpu
        cpu_percent, cpu_total, cpu_system = calculate_cpu_percent2(raw_stats, pre_cpu_stats[0], pre_cpu_stats[1])
        self.pre_cpu_stats[name] = [cpu_total, cpu_system] # 更新usage
        # blk
        read_blk, write_blk = calculate_blkio_bytes(raw_stats)
        # net
        read_net, write_net = calculate_network_bytes(raw_stats)
        # mem
        mem_usage, mem_limit = calculate_mem_bytes(raw_stats)

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

        ret_dt = {'id': raw_stats['id'],
                  'pid': str(raw_stats['pids_stats']['current']),
                  'cpu_percent': '{:.2f}'.format(cpu_percent),
                  'read_blk': parse_unit(read_blk),
                  'write_blk': parse_unit(write_blk),
                  'read_net': parse_unit(read_net),
                  'write_net': parse_unit(write_net),
                  'mem_usage': parse_unit(mem_usage, scale=1024),
                  'mem_limit': parse_unit(mem_limit, scale=1024),
                  'mem_usage_pcnt': '{:.2f}'.format(mem_usage / mem_limit * 100),
                  'gpu_mem_usage': parse_unit(gpu_used_mem, 1024), 'gpu_mem_limit': parse_unit(gpu_all_mem, 1024),
                  'gpu_mem_usage_pcnt': '{:.2f}'.format(gpu_used_mem / gpu_all_mem * 100)
                  }

        return ret_dt

    def __get_gpu_info(self):
        def parse_unit(val, scale=1000):
            unit_ls = ['B', 'KB', 'MB', 'GB']
            unit_lv = 0
            while val >= scale:
                val /= scale
                unit_lv += 1
                if unit_lv == len(unit_ls)-1:
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

    def get_ctan_verbose_stats(self, name):
        if name in self.res_info:
            return self.res_info[name]
        else:
            return None

    def get_gpu_info(self):
        return self.gpu_info


def main():
    pass

if __name__ == '__main__':
    main()
