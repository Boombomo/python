import os
import yaml
import paramiko
import logging
import logging.handlers
import time
import re
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor # 实现多线程并发执行任务

# 日志相关配置,记录备份过程中的详细信息
LOG_FILE = "network_backup.log"
MAX_BYTES = 5 * 1024 * 1024 # 单个日志文件最大5MB
BACKUP_COUNT = 5 # 最多保留5个旧日志文件

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=MAX_BYTES, backupCount=BACKUP_COUNT),
        logging.StreamHandler()
    ]
)

class NetworkBackup:
    @staticmethod
    def clean_config_output(config, commands):
        """
        去除登录欢迎信息、命令回显,只保留配置内容
        作用:让备份文件只保留真正的设备配置,去掉命令提示符、欢迎语等杂项
        """
        if isinstance(commands, list):  # 判断命令是列表还是字符串
            pattern = '|'.join(re.escape(cmd) for cmd in commands)  # 多条命令用 | 连接
        else:
            pattern = re.escape(commands)  # 单条命令直接转义
        match = re.search(pattern, config)  # 查找命令回显在输出中的位置
        if match:  # 如果找到了命令回显
            return config[match.end():].lstrip()  # 只保留命令回显之后的内容
        return config  # 如果没找到,原样返回

    def fortinet_api_backup(self, device):
        """
        通过 FortiGate API 方式导出完整配置
        """
        hostip = device['hostip']
        api_key = device.get('api_key') or self.config['credentials'].get('api_key')
        api_port = device.get('api_port', 443)  # 优先用设备自定义端口，否则443
        if not api_key:
            logging.error(f"{hostip} 未配置 Fortinet API 密钥,无法API备份")
            return False

        url = f"https://{hostip}:{api_port}/api/v2/monitor/system/config/backup?scope=global"
        headers = {"Authorization": f"Bearer {api_key}"}
        try:
            requests.packages.urllib3.disable_warnings()
            resp = requests.get(url, headers=headers, verify=False, timeout=30)
            if resp.status_code == 200:
                date_str = datetime.now().strftime("%Y%m%d_%H%M")
                filename = f"{device['name']}_{hostip.replace('.','_')}_{date_str}.conf"
                filepath = os.path.join("backup", device['groups'], filename)
                os.makedirs(os.path.dirname(filepath), exist_ok=True)
                with open(filepath, "wb") as f:
                    f.write(resp.content)
                logging.info(f"[SUCCESS] {hostip} API备份成功 -> {filepath}")
                return True
            else:
                logging.error(f"[FAILED] {hostip} API备份失败: {resp.status_code} {resp.text}")
                return False
        except Exception as e:
            logging.error(f"[FAILED] {hostip} API备份异常: {str(e)}")
            return False

    def __init__(self):
        """
        初始化方法
        1. 加载设备清单配置
        2. 定义不同厂商/平台的备份命令
        """
        self.config = self.load_config()
        self.backup_commands = {
            'juniper_qfx': 'show configuration | display set | no-more',
            'juniper_srx': 'show configuration | display set | no-more',
            'cisco_ios': 'show running-config',
            'cisco_asa': ['terminal pager 0', 'show running-config'],
            'cisco_wlc': ['show running-config'],
            'huawei': 'display current-configuration',
            'h3c': ['screen-length disable', 'display current-configuration'],
            'h3c_core': ['screen-length disable', 'display current-configuration'],
            'fortinet': 'show',
            'hillstone': 'show running-config',
        }

    def load_config(self):
        """
        加载设备配置清单 device_list.yaml
        返回:YAML 文件内容(字典)
        """
        config_path = os.path.join(os.path.dirname(__file__), 'device_list.yaml')
        with open(config_path) as f:
            return yaml.safe_load(f)

    def connect_device(self, hostip):
        """
        建立SSH连接
        参数:hostip - 设备IP地址
        返回:paramiko SSHClient 对象,连接失败返回 None
        """
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:  # 尝试连接设备
            client.connect(
                hostname=hostip,
                username=self.config['credentials']['username'],
                password=self.config['credentials']['password'],
                timeout=30,
                banner_timeout=30,
                auth_timeout=30,
                allow_agent=False,
                look_for_keys=False
            )
            client.get_transport().set_keepalive(10)
            return client  # 连接成功返回client对象
        except Exception as e:  # 连接失败
            logging.error(f"{hostip} 连接失败: {str(e)}")
            return None  # 返回None

    def execute_commands(self, client, commands):
        """
        依次执行多条命令并返回合并结果
        适用于需要先执行关闭分页命令再执行配置命令的设备
        """
        output = ''
        for i, cmd in enumerate(commands):  # 遍历每条命令
            try:
                logging.info(f"发送命令: {cmd}")
                stdin, stdout, stderr = client.exec_command(cmd + '\n', timeout=10)
                chunk = stdout.read(1024)
                while chunk:  # 循环读取输出内容
                    output += chunk.decode('utf-8', 'ignore')
                    chunk = stdout.read(1024)
                if stdout:
                    stdout.channel.close()
                if stdin:
                    stdin.close()
                if i < len(commands) - 1:  # 如果不是最后一条命令,等待1秒
                    time.sleep(1)
            except Exception as e:  # 命令执行失败
                logging.error(f"执行命令失败: {cmd} - {str(e)}")
                return ''
        return output.strip()  # 返回所有命令的输出
    def wlc_shell_login(self, shell):
        """
        处理WLC shell登录交互(用户名/密码)
        """
        username = self.config['credentials']['username']
        password = self.config['credentials']['password']
        buff = ""
        # 等待用户名提示
        while True:
            if shell.recv_ready():
                buff += shell.recv(1024).decode('utf-8', 'ignore')
                if "User:" in buff:
                    shell.send(username + '\n')
                    buff = ""
                    break
            time.sleep(0.2)
        # 等待密码提示
        while True:
            if shell.recv_ready():
                buff += shell.recv(1024).decode('utf-8', 'ignore')
                if "Password:" in buff:
                    shell.send(password + '\n')
                    break
            time.sleep(0.2)
        time.sleep(2)  # 等待登录完成
    def get_backup(self, client, platform):
        """
        获取设备配置
        根据平台类型选择命令,自动处理特殊设备(如ASA/WLC需用shell)
        """
        try:  # 捕获所有异常,保证流程不中断
            command = self.backup_commands[platform]
            logging.info(f"设备 {platform} 使用命令: {command}")
            
            if platform in ['h3c', 'h3c_core']: # h3c设备处理
                shell = client.invoke_shell()
                time.sleep(1)
                shell.send('screen-length disable\n')# 关闭分页
                time.sleep(1)
                shell.send('display current-configuration\n')
                time.sleep(2)
                output = ""
                while True:
                    if shell.recv_ready():
                        data = shell.recv(65535).decode('utf-8', 'ignore')
                        output += data
                        # 检查命令提示符（如<Core>），可根据实际设备调整
                        if re.search(r'<.*?>\s*$', data):
                            break
                    else:
                        time.sleep(1)
                shell.close()
                return output

            
            if platform == 'cisco_wlc':    # WLC设备处理
                shell = client.invoke_shell()
                time.sleep(1)
                self.wlc_shell_login(shell)
                shell.send('config paging disable\n')  # 关闭分页
                time.sleep(1)
                shell.send('show run-config\n')
                time.sleep(2)
                output = ""
                more_flag = 'Press Enter to continue'           # 分页符，遇到这个说明输出未完，需要发送空格继续
                end_flag = '(Cisco Controller) >?'  # 结束标志，遇到这个说明输出已到结尾
                enter_flag = 'Press Enter to continue' # 提示符，遇到这个说明需要发送回车
                while True:
                    if shell.recv_ready():
                        data = shell.recv(65535).decode('utf-8', 'ignore')
                        output += data
                        if enter_flag in data:
                            shell.send('\n')  # 检测到提示，自动发送回车
                        if more_flag in data:
                            shell.send(' ')      # 遇到分页符，自动发送空格获取下一页内容
                        if end_flag in data and more_flag not in data:
                            break               # 如果遇到结束标志且没有分页符，说明输出结束，跳出循环
                    else:
                        time.sleep(1)
                shell.close()
                return output
            
            if platform == 'cisco_asa': # ASA处理逻辑
                shell = client.invoke_shell()
                time.sleep(1)
                output = ""
                for cmd in command:  # 依次发送命令
                    shell.send(cmd + '\n')
                    time.sleep(2)
                time.sleep(2)
                while shell.recv_ready():  # 循环读取shell输出
                    output += shell.recv(65535).decode('utf-8', 'ignore')
                shell.close()
                return output  # 返回shell输出
            
            if isinstance(command, list):  # 如果是命令列表
                config = self.execute_commands(client, command)
            elif isinstance(command, str):  # 如果是单条命令
                stdin, stdout, stderr = client.exec_command(command)
                config = stdout.read().decode('utf-8', 'ignore')
            else:  # 命令格式不支持
                raise TypeError(f"不支持的命令格式: {type(command)}")
            return config  # 返回命令输出
        except KeyError:  # 平台类型不支持
            logging.error(f"不支持的平台类型: {platform}")
            return None
        except Exception as e:  # 其他异常
            logging.error(f"命令执行失败: {str(e)}")
            return None

    def save_config(self, config, hostip, name, group, commands=None):
        """
        保存配置文件到本地
        自动创建目录,文件名包含IP和时间
        保存前会清理掉无关内容
        """
        if not config:  # 如果没有内容,不保存
            return False
        if commands:  # 有命令时,先清理无关内容
            config = self.clean_config_output(config, commands)
        date_str = datetime.now().strftime("%Y%m%d_%H%M")

        filename = f"{name}_{hostip.replace('.','_')}_{date_str}.cfg"

        # 修改为当前目录下的 backup 文件夹，实际上传服务器这个字段为"/usr/Gitlab/network_backup"
        filepath = os.path.join("backup", group, filename)

        os.makedirs(os.path.dirname(filepath), exist_ok=True)  # 自动创建目录
        try:
            with open(filepath, 'w') as f:
                f.write(config)
            logging.info(f"[SUCCESS] {hostip} 备份成功 -> {filepath}")
            return True  # 保存成功
        except Exception as e:  # 保存失败
            logging.error(f"[FAILED] {hostip} 文件保存失败: {str(e)}")
            return False

    def backup_device(self, device):
        """
        单台设备的完整备份流程
        1. 建立SSH连接
        2. 获取配置
        3. 保存配置
        """
        if device['platform'] == 'fortinet':
            # 优先用API方式备份
            return self.fortinet_api_backup(device)

        client = self.connect_device(device['hostip'])  # 连接设备
        if not client:  # 连接失败
            return False
        config = self.get_backup(client, device['platform'])  # 获取配置
        client.close()  # 关闭连接
        if not config:  # 获取失败
            return False
        return self.save_config(
            config,
            device['hostip'],
            device['name'],      # 设备名
            device['groups'],    # 分组
            self.backup_commands[device['platform']]
    )

    def run_backup(self):
        """
        批量并发执行所有设备的备份任务
        统计成功数量并输出日志
        """
        with ThreadPoolExecutor(max_workers=8) as executor:  # 创建线程池
            futures = []
            for device in self.config['devices']:  # 遍历所有设备
                future = executor.submit(self.backup_device, device)  # 提交任务
                futures.append(future)
            success = sum(f.result() for f in futures if f.result())  # 统计成功数量
            total = len(futures)
            logging.info(f"\n备份完成: 成功 {success}/{total}")  # 输出统计结果

if __name__ == "__main__":
    # 执行备份任务
    backup = NetworkBackup()
    backup.run_backup()