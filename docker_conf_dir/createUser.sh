#!/bin/bash
#标准输出，错误输出 定向到/tmp/create.log
set -x
exec 1>/tmp/create.log 2>&1
#读取数据，实际操作： echo "user1 123456" | createUser.sh
read User Passwd
#显示文件夹权限
ls -l /home
#配置文件夹
SOURCE="$0"
while [ -h "$SOURCE"  ]; do # resolve $SOURCE until the file is no longer a symlink
    DIR="$( cd -P "$( dirname "$SOURCE"  )" && pwd  )"
    SOURCE="$(readlink "$SOURCE")"
    # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
    [[ $SOURCE != /*  ]] && SOURCE="$DIR/$SOURCE" 
done
DIR_PATH="$( cd -P "$( dirname "$SOURCE"  )" && pwd  )"

#创建用户
useradd -d /home/$User -s /bin/bash $User
#更改密码
echo "$User:$Passwd" | chpasswd
#添加到sudoers
echo "$User ALL=(ALL) ALL" | tee -a /etc/sudoers

#create vnc
su $User -c " echo -e '$Passwd\n$Passwd'  | vncpasswd "
if [ ! -x "/home/$User/.config" ];then
	su $User -c "mkdir /home/$User/.config"
fi
cp $DIR_PATH/xstartup   /home/$User/.vnc/xstartup

#热键修复
su $User -c "cp -r $DIR_PATH/xfce4 /home/$User/.config/xfce4"
#关闭屏保
cp $DIR_PATH/xscreensaver /home/$User/.xscreensaver

#非超级权限下的脚本
cp $DIR_PATH/rc.local /etc/rc.local
cp $DIR_PATH/rc.preShutdown /etc/rc.preShutdown
sed -i  "s/^User=.*/User=$User /g"  /etc/rc.local
sed -i  "s/^User=.*/User=$User /g"  /etc/rc.preShutdown

# 生成骨架文件
VNC_RESOLUTION=1920x1080
DISPLAY=1
vncserver -kill :$DISPLAY || rm -rfv /tmp/.X*-lock /tmp/.X11-unix 
# 开启了vnc桌面后，主文件骨架才生成
su $User -c "vncserver :$DISPLAY -geometry $VNC_RESOLUTION"
sleep 1
su ${User} -c "/usr/bin/vncserver -kill :${DISPLAY}"

#连接matlab
ln -s /usr/local/MATLAB/R2017a/bin/matlab /usr/local/bin/matlab
ls /home/$User
if [ -d "/home/$User/桌面" ];then
	echo "桌面"
	cp $DIR_PATH/Matlab.desktop /home/$User/桌面/Matlab.desktop
fi
if [ -d "/home/$User/Desktop" ];then
	echo "Desktop"
	cp $DIR_PATH/Matlab.desktop /home/$User/Desktop/Matlab.desktop
fi

#打上时间戳
#cp $DIR_PATH/backUp.sh  /root/backUp.sh
#cp $DIR_PATH/restore.sh  /root/restore.sh
#sed -i  "s/^User=.*/User=$User /g"  /root/backUp.sh
#touch /root/timeTag

#删除文件配置文件夹,慎用！！还是通过python来删除比较稳妥
#rm -rf $DIR_PATH

