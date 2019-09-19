# -*- coding:utf-8 -*-
import configparser
import tornado.ioloop
import tornado.web
import tornado.httpserver
import os.path
import os, sys, getopt, psutil
import traceback
import lab_vm_manager as UM
import re

# settings
settings = {
    "static_path": os.path.join(os.path.dirname(__file__), "www/dist"),
    "debug": True,
}


# Deal with CORS problem
class BaseHandler(tornado.web.RequestHandler):
    def set_default_headers(self):
        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', ' PUT, DELETE, OPTIONS')

    def options(self):
        # no body
        self.set_status(204)
        self.finish()



# Index Page: Query all users states
class MainHandler(BaseHandler):
    def get(self):
        global um
        print("[Server] Query Request: ")
        items = {}
        try:
            items = um.get_all_ctans_status()
        except Exception:
            print("[Server] Query Error!")
            traceback.print_exc()
        self.render("./www/index.html", items=items)


# Register Page:
class RegisterHandler(BaseHandler):
    def get(self):
        self.render("./www/register.html")


class startHandler(BaseHandler):
    def get(self, username):
        global um
        res = "failed"
        if um.start(username):
            res = "succeed"
        print("[Server] Start Request: " + username + ": " + res)
        self.write(res)


class stopHandler(BaseHandler):
    def get(self, username):
        global um
        res = "failed"
        if um.stop(username):
            res = "succeed"
        print("[Server] Stop Request: " + username + ": " + res)
        self.write(res)


# add a new user
class addUserHandler(BaseHandler):
    def get(self, username, remark, passwd, mail, phone, managerPasswd):
        global um
        print("[Server] Register Request: " + username + ": dealing...")
        res = "failed"
        # 验证管理员密码
        if not um.valid_user_passwd(host_name, managerPasswd, admin=True):
            self.write("invManagePass")
            return
        if um.create_user(username, passwd, mail, remark=remark, phone=phone):
            res = "succeed"
        else:
            res = "failed"
        print("[Server] Register Done: " + username + ": " + res)
        self.write(res)


# delete a user
class deleteUserHandler(BaseHandler):
    def get(self, username):
        res = "failed"
        global um
        if um.remove(username):
            res = "succeed"
        print("[Server] Delete Request: " + username + ": " + res)
        self.write(res)


class verifyPasswordHandler(BaseHandler):
    def get(self, username, passwd):
        global um
        # print('valid passwd {}'.format(passwd))
        res = "failed"
        try:
            if um.valid_user_passwd(username, passwd):
                res = "succeed"
            elif um.valid_user_passwd(host_name, passwd, admin=True):
                res = "succeed"
        except Exception:
            traceback.print_exc()
        self.write(res)

    def post(self):
        global um
        username = self.get_argument('name')
        passwd = self.get_argument('passwd')

        res = "Wrong"
        try:
            if um.valid_user_passwd(username, passwd):
                res = "Right"
            if um.valid_user_passwd(host_name, passwd, admin=True):
                res = "Right"
        except Exception:
            traceback.print_exc()
        self.write(res)


class updateGPUStatusHandler(BaseHandler):
    def get(self):
        global um
        print('update gpu')
        status = os.popen('nvidia-smi').readlines()

        res = '<br /><br />'
        for line in status:
            match = re.match(r'^\| *(\d+) *(\d+) *.*(\d+)MiB *\|$', line)
            name = ''
            if match:
                pid = match.group(2)
                ctan_name = um.get_ctan_name_by_pid(int(pid))
                if ctan_name == 'none':
                    ctan_name = 'server'
                name = '%12s |' % ctan_name
            res += '<br>' + line.strip().replace(' ', '&nbsp;') + name.replace(' ', '&nbsp;') + '</br>'
        return self.write(res)


class GPUStatusHandler(BaseHandler):
    def get(self):
        self.render("./www/gpu_status.html")


class updateREStatusHandler(BaseHandler):
    def get(self):
        global um
        # print('update cpu')
        # CPU 和 内存
        column_width = 300  # 表格没列宽度
        res = ''

        # GPU 总的使用情况
        # print(um)
        gpu_sum, gpu_process_ls = um.get_gpu_info()
        # GPU总表格
        res += '<h3>GPU信息</h3>'
        res += '<table align="center">' \
               '<tr>' \
               '<th class="user_info_columnStyle">GPU_id</th>' \
               '<th class="user_info_columnStyle">GPU_name</th>' \
               '<th class="user_info_columnStyle">GPU_mem</th>' \
               '<th class="user_info_columnStyle">GPU_util</th>' \
               '</tr>'
        for i in range(len(gpu_sum)):
            res += '<tr>' \
                   '<td class=\"user_info_columnStyle_s\">' + gpu_sum[i]["gpu_idx"] + '</td>' \
                                                                                      '<td class=\"user_info_columnStyle_s\">' + \
                   gpu_sum[i]["dev_name"] + '</td>'
            res += '<td class=\"user_info_columnStyle_s\">'
            # gpu_perc
            gpu_m_usage = gpu_sum[i]['used_mem']
            gpu_m_limit = gpu_sum[i]['total_mem']
            gpu_m_perc = float(gpu_sum[i]['gpu_mem_util'])
            mem_color = ''
            if gpu_m_perc >= 80:
                mem_color = '#ff0000'
            else:
                mem_color = '#00ff00'
            width_gpu = gpu_m_perc if gpu_m_perc > 2 else 2
            res += '<span style=\"text-align:center;background-color:' + mem_color
            res += ';display:-moz-inline-box;display:inline-block;white-space:nowrap;width:'
            res += str(width_gpu / 100 * column_width)
            res += 'px\">'
            res += gpu_m_usage + ' / ' + gpu_m_limit
            res += '</span>'
            res += '</td>'
            res += '<td class=\"user_info_columnStyle_s\">' + gpu_sum[i]["gpu_util"] + '%</td>'

        res += '</table><br><br>'
        # gpu process表格
        res += '<h3>GPU process信息</h3>'
        res += '<table align="center">' \
               '<tr>' \
               '<th class="user_info_columnStyle">process_type</th>' \
               '<th class="user_info_columnStyle">gpu_idx</th>' \
               '<th class="user_info_columnStyle">process_pid</th>' \
               '<th class="user_info_columnStyle">process_name</th>' \
               '<th class="user_info_columnStyle">dev_name</th>' \
               '<th class="user_info_columnStyle">process_gpu_mem</th>' \
               '<th class="user_info_columnStyle">user_name</th>' \
               '</tr>'
        for i in range(len(gpu_process_ls)):
            res += '<tr>' \
                   '<td class=\"user_info_columnStyle_s\">' + gpu_process_ls[i]["process_type"] + '</td>' \
                                                                                                  '<td class=\"user_info_columnStyle_s\">' + \
                   gpu_process_ls[i]["gpu_idx"] + '</td>' \
                                                  '<td class=\"user_info_columnStyle_s\">' + gpu_process_ls[i][
                       "process_pid"] + '</td>'
            lenOfProcessName = len(gpu_process_ls[i]["process_name"])
            if lenOfProcessName > 20:
                res += '<td class=\"user_info_columnStyle_s\" title=\"'
                res += gpu_process_ls[i]["process_name"]
                res += '\">'
                res += gpu_process_ls[i]["process_name"][:20] + '...'
            else:
                res += '<td class=\"user_info_columnStyle_s\">' + gpu_process_ls[i]["process_name"] + '</td>'
            res += '</td>' \
                   '<td class=\"user_info_columnStyle_s\">' + gpu_process_ls[i]["dev_name"] + '</td>' \
                                                                                              '<td class=\"user_info_columnStyle_s\">' + \
                   gpu_process_ls[i]["process_gpu_mem"] + '</td>' \
                                                          '<td class=\"user_info_columnStyle_s\">' + gpu_process_ls[i][
                       "ctan_name"] + '</td>'

        res += '</table><br><br>'

        # 用户的资源
        res += '<h3>用户资源信息</h3>'
        res_infos = {}
        userList = um.get_running_ctans_ls()
        res += '<table align="center">' \
               '<tr>' \
               '<th class="user_info_columnStyle">Name</th>' \
               '<th class="user_info_columnStyle">CPU</th>' \
               '<th class="user_info_columnStyle">MEM</th>' \
               '<th class="user_info_columnStyle">IO R/W</th>' \
               '<th class="user_info_columnStyle">NET R/W</th>' \
               '<th class="user_info_columnStyle">GPU_MEM</th>' \
               '</tr>'
        for name in userList:
            res_infos[name] = um.get_ctan_verbose_stats(name)
            if res_infos[name] is None:
                continue
            thisLine = '<tr>'
            # column 1: name
            thisLine += '<td class=\"user_info_columnStyle_s\">' + name + '</td>'
            # column 2: cpu
            cpu_perc = float(res_infos[name]['cpu_percent'])
            cpu_color = '#00ff00'
            if cpu_perc >= 2400 * 0.8:
                cpu_color = '#ff0000'
            else:
                cpu_color = '#00ff00'
            thisLine += '<td class=\"user_info_columnStyle_s\">'
            thisLine += '<span style=\"text-align:center;background-color:' + cpu_color
            thisLine += ';display:-moz-inline-box;display:inline-block;white-space:nowrap;width:'
            width_ps = str(cpu_perc / 2400 * column_width) if cpu_perc / 12 > 2 else str(2)
            thisLine += width_ps
            thisLine += 'px\">'
            thisLine += str(cpu_perc)
            thisLine += '%</span>'
            thisLine += '</td>'
            # column 3: mem
            m_usage = res_infos[name]['mem_usage']
            m_limit = res_infos[name]['mem_limit']
            m_perc = float(res_infos[name]['mem_usage_pcnt'])
            mem_color = ''
            if m_perc >= 80:
                mem_color = '#ff0000'
            else:
                mem_color = '#00ff00'
            thisLine += '<td class=\"user_info_columnStyle_s\">'
            thisLine += '<span style=\"text-align:center;background-color:' + mem_color
            thisLine += ';display:-moz-inline-box;display:inline-block;white-space:nowrap;width:'
            width_ps = str(m_perc / 100 * column_width) if m_perc > 2 else str(2)
            thisLine += width_ps
            thisLine += 'px\">'
            thisLine += m_usage + ' / ' + m_limit
            thisLine += '</span>'
            thisLine += '</td>'
            # column 4:
            thisLine += '<td class=\"user_info_columnStyle_s\">' + res_infos[name]['read_net'] + ' / ' + \
                        res_infos[name]['write_net'] + '</td>'
            # column 5:
            thisLine += '<td class=\"user_info_columnStyle_s\">' + res_infos[name]['read_blk'] + ' / ' + \
                        res_infos[name]['write_blk'] + '</td>'

            gpu_m_usage = res_infos[name]['gpu_mem_usage']
            gpu_m_limit = res_infos[name]['gpu_mem_limit']
            gpu_m_perc = float(res_infos[name]['gpu_mem_usage_pcnt'])
            mem_color = ''
            if gpu_m_perc >= 80:
                mem_color = '#ff0000'
            else:
                mem_color = '#00ff00'
            thisLine += '<td class=\"user_info_columnStyle_s\">'
            thisLine += '<span style=\"text-align:center;background-color:' + mem_color
            thisLine += ';display:-moz-inline-box;display:inline-block;white-space:nowrap;width:'
            width_ps = str(gpu_m_perc / 100 * column_width) if gpu_m_perc > 2 else str(2)
            thisLine += width_ps
            thisLine += 'px\">'
            thisLine += gpu_m_usage + ' / ' + gpu_m_limit
            thisLine += '</span>'
            thisLine += '</td>'

            # sum
            res += thisLine
        res += '</table>'
        # print(res)
        return self.write(res)


class REStatusHandler(BaseHandler):
    def get(self):
        self.render("./www/cpu_status.html")

# 新:CPU饼图更新函数

class cpuUtils_MainHandler(BaseHandler):
    def get(self):
        self.render("./www/cpu_status.html")


class cpuUtils_AjaxHandler(BaseHandler):
    def post(self):
        cpu_util = psutil.cpu_percent(None)
        mem_util = psutil.virtual_memory().percent
        import datetime
        time_obj = datetime.datetime.now()
        time_str = datetime.datetime.strftime(time_obj, '%Y-%m-%d %H:%M:%S')
        _time = time_str
        dict = {"c": cpu_util, "m": mem_util, "time": _time}
        self.write(dict)


# 更新用户隐私信息
class updatePrivacyHandler(BaseHandler):
    def get(self, username, new_mail, new_addition, new_phone):
        res = "failed"
        try:
            global um
            if (new_mail != "NotModified"):
                print('change {} mail'.format(username))
                um.change_mail(username, new_mail)
                print('mail of {} is changed'.format(username))
            if (new_addition != "NotModified"):
                print('change {} addition'.format(username))
                um.change_remark(username, new_addition)
                print('mark of {} is changed'.format(username))
            if (new_phone != "NotModified"):
                print('change {} phone'.format(username))
                um.change_phone(username, new_phone)
                print('phone of {} is changed'.format(username))
            res = "succeed"
        except Exception:
            traceback.print_exc()
        self.write(res)


class updatePasswdHandler(BaseHandler):
    def get(self, username, new_passwd):
        global um
        res = "failed"
        try:
            print('change {} passwd'.format(username))
            if new_passwd!="":
                um.change_ctan_passwd(username, new_passwd)
                res = "succeed"
            else:
                print("new password is empty")
        except Exception as e:
            traceback.print_exc()
        self.write(res)


class resetTimeHandler(BaseHandler):
    def get(self, username):
        res = "failed"
        try:
            global um
            print('reset {} start time'.format(username))
            um.reset_startime(username)
            res = "succeed"
        except Exception:
            traceback.print_exc()
        self.write(res)


# 查看用户隐私信息
class privacyInfoHandler(BaseHandler):
    def get(self, username):
        res = ""
        try:
            global um
            print('get privacy info for {}'.format(username))
            # 提取用户隐私信息并赋值给res
            res = um.get_user_privacy(username)
        except Exception:
            traceback.print_exc()
        self.write(res)


# 获取左上角信息
class initHandler(BaseHandler):
    def get(self, info_type):
        res = ""
        try:
            if info_type == "get_server_name":
                # 获取服务器名字显示在左上角
                res = machine_name
            elif info_type == "get_attention":
                # 获取用户须知
                # res = "<strong>1.我是用户须知</strong>\n2."
                res = ""
            elif info_type == "modify_title":
                # 修改页面标题（在标签里）
                res = machine_name
        except Exception:
            traceback.print_exc()
        self.write(res)


host_name = None
um = None
machine_name = None

def main():
    global um, host_name, machine_name
    opts, args = getopt.getopt(sys.argv[1:], "hc:")
    conf_path = None
    for op, value in opts:
        if op == "-c":
            conf_path = value
        if op == "-h":
            help_str = 'python -c conf_path Server.py \n' \
                       ' conf_path is the path to config file, default is lab_vm.conf'
            print(help_str)
            return

    if conf_path is None:
        conf_path = 'lab_vm.conf'
    conf = configparser.ConfigParser(allow_no_value=True)
    conf.read(conf_path)

    machine_name = conf.get('machine', 'machine_name')
    host_name = conf.get('machine', 'host_name')
    ls_port = conf.get('web', 'web_listen_port')

    um = UM.get_Um(conf_dir=conf_path, crypt_key='1234567890')

    application = tornado.web.Application([
        (r"/", MainHandler),
        (r"/register/", RegisterHandler),
        (r"/start/(\w+)", startHandler),
        (r"/stop/(\w+)", stopHandler),
        (r"/delete/(\w+)", deleteUserHandler),
        (r"/add/(\w+)/(.*)/(.*)/(.*)/(.*)/(.*)", addUserHandler),
        (r"/verify/(\w+)/(.*)", verifyPasswordHandler),
        # gpu
        (r"/status/", GPUStatusHandler),
        (r"/update_status/", updateGPUStatusHandler),
        # res
        (r"/status_cpu/", REStatusHandler),
        (r"/update_status_cpu/", updateREStatusHandler),
        (r"/cpuUtils_main", cpuUtils_MainHandler),
        (r"/cpuUtils_ajax", cpuUtils_AjaxHandler),
        # update data
        (r"/update_mail/(\w+)/(.*)/(.*)/(.*)", updatePrivacyHandler),
        (r"/update_passwd/(\w+)/(.*)", updatePasswdHandler),
        (r"/time_reset/(\w+)", resetTimeHandler),
        (r"/privacy_info/(\w+)", privacyInfoHandler),
        (r"/init/(.*)", initHandler),

    ], **settings)

    application.listen(ls_port)

    print("[Server] Start on %s" % ls_port)
    tornado.ioloop.IOLoop.instance().start()



if __name__ == '__main__':
    main()
