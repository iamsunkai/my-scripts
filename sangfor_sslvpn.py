# coding:utf-8
# 20210713
# 深信服SSLVPN后台管理
import requests
import hashlib
import json
import random


class SangforSSLVPN(object):
    def __init__(self, host, username, password):
        self.host = host
        self.base_url = f'https://{self.host}:4430'
        self.handler_url = f"{self.base_url}/cgi-bin/php-cgi/html/delegatemodule/HttpHandler.php"

        def hash_sha1(s):
            sha = hashlib.sha1()
            sha.update(s.encode())
            result = sha.hexdigest()
            return result

        try:
            requests.packages.urllib3.disable_warnings()
            pre_request = requests.get(
                url=f'{self.base_url}/cgi-bin/login.cgi?requestname=2&cmd=0',
                verify=False,
                timeout=3)
            pre_session_id = pre_request.headers['Set-Cookie'].split(';')[0].split('=')[1]
            sec_pwd = hash_sha1(str(password + pre_session_id))
            payload = {
                "user": username,
                "password": sec_pwd,
                "logintime": "1",
                "program": "3",
                "language": "zh_CN",
                "privacy": "1"
            }

            header = {'Cookie': f'sinfor_session_id={pre_session_id}'}
            r = requests.post(
                url=f'{self.base_url}/cgi-bin/login.cgi',
                data=payload,
                headers=header,
                verify=False,
                timeout=3)
            if 'err_info' in r.text:
                print("登陆失败，用户名或密码不正确!")
                raise
            sinfor_session_id = r.headers['Set-Cookie'].split(';')[0].split('=')[1]

            r = requests.get(
                url=f"{self.base_url}/cgi-bin/php-cgi/html/redirect.php?modname=RunState&rnd={random.random()}",
                cookies={"sinfor_session_id": sinfor_session_id, "language": "zh_CN"},
                verify=False,
                timeout=3)
            php_session_id = r.headers['Set-Cookie'].split(';')[0].split('=')[1]

            self.token = hash_sha1(sinfor_session_id)
            self.cookies = {
                'language': 'zh_CN',
                'sinfor_session_id': sinfor_session_id,
                'PHPSESSID': php_session_id
            }

        except Exception as e:
            print(e)

    def get_vip(self):
        """
            获取用户动态地址池中的可用虚拟ip
            返回IP字符串
        """
        uri = 'controler=User&action=GetUseableVip'
        data = self.__request(uri, 'GET')
        if data['code'] != 0:
            print("数据获取错误", data['message'])
            return False
        return data['result']['ip']

    def add_user(self, username, desc, group_name, password='pw@com', vip=0):
        """
            添加用户需制定用户名和用户描述，一般的username为汉语全拼，描述为中文名字
            用户的默认密码为pw@com
            vip如果为1则会设置vip为固定，默认不设置
            用户默认继承组的策略和角色
        """
        if vip == 0:
            is_Autoip = 1
            allocateip = ''
        else:
            allocateip = self.get_vip()
            is_Autoip = 0

        # 首先通过query_info的模糊查询获得所有组信息，判断提供的group_name是否存在
        group_info = self.query_info(name='', object_type='group', mh=1)
        if not group_info:
            return False

        if_next = None
        grp_id = None
        for x in group_info:
            grp_name = x['name']
            grp_id = x['_id']
            if grp_name == group_name:
                if_next = True
                break
        if not if_next:
            print(f"指定的组 {group_name} 不存在")
            return False

        payload = {
            "name": username,  # 用户名称
            "note": desc,  # 用户中文名
            "passwd": password,  # 用密码
            "passwd2": password,  # 确认用户密码
            "phone": "",
            "grpid": grp_id,  # 组ID
            "grptext": "",
            "selectAll": "1",  # 继承所属组认证选项和策略组
            "b_inherit_auth": "1",  # 继承所属组认证选项
            "b_inherit_grpolicy": "1",  # 继承所属组接入策略组
            "is_Autoip": is_Autoip,  # VIP自动获得
            "allocateip": allocateip,  # 手动设置VIP
            "gqsj": "1",  # 过期时间1为永不过期
            "ex_time": "",
            "is_enable": "1",  # 账户状态
            "is_public": "0",  # 账户类型，共有/私有
            "is_pwd": "1",  # 是否密码验证
            "ext_auth_id": "",  # 外部认证方式id
            "auth_type": "0",
            "token_svr_id": "",
            "grpolicy_id": "0",  # 关联策略ID
            "grpolicytext": "",  # 策略显示名称
            "roleid": "",  # 关联角色ID
            "roletext": "",  # 关联角色显示名称
            "year": "",
            "month": "",
            "day": "",
            "isBindKey": "",
            "userid": "0",
            "crypto_key": "",
            "szcername": "",
            "caid": "-1",
            "certOpt": "0",
            "create_time": "",
            "sec_key": ""
        }
        data = self.__request(
            uri='controler=User&action=AddUser',
            method="POST",
            payload=payload,
            save=1
        )
        if data['code'] != 0:
            print("添加用户失败", data['message'])
            return False
        return data

    def del_user(self, username):
        # 首先通过查询方法获取用户的ID信息
        user_info = self.query_info(name=username, object_type='user')
        if not user_info:
            return False
        user_id = user_info[0]['_id']

        payload = {
            "grpid": 1,
            "recflag": 1,
            "user_ids": user_id,
            "group_ids": "",
            "is_user_exclude": 0,
            "is_group_exclude": 0,
            "is_dev_del": 0
        }
        data = self.__request(
            uri='controler=Group&action=DelAllPageGroupAndUser',
            method="POST",
            payload=payload,
            save=1
        )
        if data['code'] != 0:
            print("删除用户失败", data['message'])
            return False
        return data

    def edit_user(self, username, password='pw@com'):
        """
            目前只开发了用户密码修改功能，这个也是比较常用的
            深信服sslvpn管理员给用户修改了密码之后，用户第一次登陆会强制要求再修改密码的
            如果不提供密码，默认需改密码为pw@com
            {
                "name":"test",
                "note":"测试2",
                "passwd":"123123",
                "passwd2":"123123",
                "phone":"",
                "grpid":"40",
                "grptext":"/test",
                "selectAll":"1",
                "b_inherit_auth":"1",
                "b_inherit_grpolicy":"1",
                "is_Autoip":"0",
                "allocateip":"172.16.14.16",
                "gqsj":"1",
                "ex_time":"2026-07-14",
                "is_enable":"1",
                "is_public":"0",
                "is_pwd":"1",
                "ext_auth_id":"",
                "auth_type":"0",
                "token_svr_id":"",
                "grpolicy_id":"24",
                "grpolicytext":"管理员",
                "roleid":"32",
                "roletext":"公共组件",
                "year":"",
                "month":"",
                "day":"",
                "isBindKey":"",
                "userid":"2551",
                "crypto_key":"zFLQhqDXfCUsJl9q",
                "szcername":"",
                "caid":"-1",
                "certOpt":"0",
                "create_time":"",
                "sec_key":""
            }
        """

        # 用户名、组ID、用户ID为必须参数，所以需要先通过查询方法获取用户的组ID和用户ID
        user_info = self.query_info(name=username, object_type='user')
        if not user_info:
            return False
        user_id = user_info[0]['_id']
        group_id = user_info[0]['parent']
        desc = user_info[0]['note']
        allocateip = user_info[0]['allocateip']
        is_Autoip = "0"
        if allocateip == "自动分配":  # 判断是否为该用户指定了VIP，如果指定则用指定的IP
            allocateip = ""
            is_Autoip = "1"

        payload = {
            "name": username,
            "passwd": password,
            "passwd2": password,
            "grpid": group_id,
            "userid": user_id,
            "note": desc,
            "is_enable": "1",
            "is_Autoip": is_Autoip,
            "allocateip": allocateip,
            "b_inherit_auth": "1",  # 继承认证方式
            "b_inherit_grpolicy": "1"  # 继承策略组
        }
        data = self.__request(
            uri='controler=User&action=UpdateUser',
            payload=payload,
            method="POST",
            save=1
        )
        if data['code'] != 0:
            print("用户修改失败!", data['message'])
            return False
        return data

    def add_group(self):
        pass

    def del_group(self):
        pass

    def get_alrm(self, limit=10):
        """
            获取控制台中告警信息
            返回列表[{'id': '548', 'type': 0, 'module': 2, 'time': '2021-07-13 13:40:41', 'msg': 'xxyxyx，现已被系统锁定'}]
        """
        payload = {
            "start": 0,
            "limit": limit,
            "r": ""
        }
        uri = 'controler=State&action=GetAlarmList'
        data = self.__request(uri, "POST", payload)
        if data['code'] != 0:
            print(data['message'])
            return False
        total_count = data['result']['totalCount']
        print(f"共有告警 {total_count} 条，当前显示 {limit} 条")
        return data['result']['data']

    def query_info(self, name, object_type='user', mh=0):
        """
            object_type可以接受用户user和组group
            mh为是否开启模糊查询，默认不开启
            返回列表
        """
        area = '1'  # 设置默认值
        if object_type == 'user':
            area = '1'
        if object_type == 'group':
            area = '2'
        payload = {
            'start': '0',
            'limit': '666',
            'sort': 'name',
            'dir': 'ASC',
            'grpid': '-100',
            'recflag': '1',
            'filter': '0',
            'keystr': name,
            'keytype': '1',
            'area': area,
            'authtype': '0',
            'exp_day': '',
            'not_login_time': '',
            'operator': '3',
            'isnever_exp': '0',
            'exp_operator': '1',
            'caid': '0'
        }
        data = self.__request(
            uri='controler=Group&action=GetSearchData',
            method="POST",
            payload=payload
        )
        if data['code'] != 0:
            print("查询信息失败!", data['message'])
            return False
        if data['result']['totalCount'] == '0':
            print(f"{name} 查询结果为空")
            return False
        if mh == 0:
            for x in data['result']['data']:
                if name == x['name']:
                    return [x]
            print(f"{name} 查询结果为空")
            return False  # 没有找到该用户
        if mh == 1:
            return data['result']['data']

    def logout(self):
        requests.get(
            url=f"{self.base_url}//cgi-bin/login.cgi?requestname=0&cmd=0",
            cookies=self.cookies,
            verify=False,
            timeout=5
        )

    def __request(self, uri, method, payload=None, save=0):
        try:
            r = None  # 没他代码不美观，有他也没啥用
            if method == 'GET':
                r = requests.get(
                    url=f"{self.handler_url}?{uri}&token={self.token}",
                    cookies=self.cookies,
                    verify=False,
                    timeout=5
                )
            if method == "POST":
                r = requests.post(
                    url=f"{self.handler_url}?{uri}&token={self.token}",
                    data=payload,
                    cookies=self.cookies,
                    verify=False,
                    timeout=5
                )
            if r.status_code != 200:
                print(f"{uri} 请求错误")
                raise
            data = json.loads(r.content)

            if save != 0:  # 如果是edit操作，需要调用接口进行 应用配 置操作
                requests.post(
                    url=f"{self.handler_url}?controler=Updater&action=Update&token={self.cookies}",
                    cookies=self.cookies,
                    data={"isNeedCheckCommunication": "true"},
                    verify=False,
                    timeout=5
                )

            return data
        except Exception as e:
            print(e)


if __name__ == '__main__':
    sslvpn = SangforSSLVPN('192.168.103.108', 'admin', '123@pass')
    print(sslvpn.get_alrm(limit=20))
    # print(sslvpn.get_vip())
    # print(sslvpn.query_info('', 'group', mh=1))
    # print(sslvpn.add_user('test1', '测试', 'test', vip=1))
    # print(sslvpn.edit_user('test1', password='456456'))
    # print(sslvpn.del_user('test1'))
