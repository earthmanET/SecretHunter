# Another: @Captain_Pink
import platform
import argparse
import subprocess
import winreg
import importlib
import yaml
import sys
import os
import glob
from core.output import Output,Log 
from core.config import Config

def banner():
    print("""
   _____                    _   _    _             _            
  / ____|                  | | | |  | |           | |           
 | (___   ___  ___ _ __ ___| |_| |__| |_   _ _ __ | |_ ___ _ __ 
  \___ \ / _ \/ __| '__/ _ \ __|  __  | | | | '_ \| __/ _ \ '__|
  ____) |  __/ (__| | |  __/ |_| |  | | |_| | | | | ||  __/ |   
 |_____/ \___|\___|_|  \___|\__|_|  |_|\__,_|_| |_|\__\___|_|     
                                                
                                                Coded By @Captain_Pink       
    """)

def check_platform():
    sys_name=platform.system()
    if sys_name=='Windows':
        return True
    else:
        Log().error("[-]Please run the program on Windows platform")
        return False

def get_product_info_cmd():
    command="wmic product get name"
    p = subprocess.Popen(args=command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, close_fds=True)
    output_bytes=p.communicate()[0]
    output_str=str(output_bytes,encoding="gbk")
    software_list=output_str.split('\r\r\n')
    return software_list
    '''
    file=open("product_info_cmd","a")
    file.write(output_str)
    file.close()
    '''

def get_product_info():
    sub_key = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
           r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall']

    software_name = []
    for i in sub_key:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, i, 0, winreg.KEY_ALL_ACCESS)
            for j in range(0, winreg.QueryInfoKey(key)[0] - 1):
                try:
                    key_name = winreg.EnumKey(key, j)
                    key_path = i + '\\' + key_name
                    each_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS)
                    DisplayName, REG_SZ = winreg.QueryValueEx(each_key, 'DisplayName')
                    DisplayVersion, REG_SZ1 = winreg.QueryValueEx(each_key, 'DisplayVersion')
                    DisplayName = DisplayName.encode('utf-8')
                    software_name.append(DisplayName)
                except WindowsError:
                    pass
        except WindowsError:
            return False

    software_name = list(set(software_name))
    software_name = sorted(software_name)
    return software_name
    '''
    file=open("product_info","a")
    for result in software_name:
        file.writelines(result.decode("utf-8")+'\n')
        print(result.decode("utf-8"))
    file.close()
    '''

def import_module(modules_dir='./modules/', output_filename='', target_list=None):
    modules_dir_list=['browser','system']
    for dir in modules_dir_list:
        modules_path=modules_dir+dir
        modules_list=get_module(modules_path)
        for module in modules_list:
            try:
                meta_module=importlib.import_module(module['module_name'])
                meta_class=getattr(meta_module,module['class_name'])
                result_list=meta_class().run(target_list)
                Output().output_to_terminal(result_list)
                Output().output_to_file(output_filename,result_list)
            except Exception as e:
                Log().error('[-]'+str(e))
    
def get_module(module_path):
    module_list = []
    for module_name in glob.glob(module_path+"/*.py"):
        dict={}
        module_name=module_name[:-3]
        class_name=os.path.basename(module_name)
        module_name=os.path.normpath(module_name).replace('\\','.')
        dict['module_name']=module_name
        dict['class_name']=class_name
        module_list.append(dict)
    return module_list
    '''
    module_list=[]
    list = os.listdir(module_path)  # 列出文件夹下所有的目录与文件
    for i in range(0, len(list)):
        path = os.path.join(module_path, list[i])
        module_list.append(path)
    return module_list
    '''
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Configuration file path.', default='config.yaml')
    parser.add_argument('-o', '--output', help='The output file of the running result', default='./output/result')
    args = parser.parse_args()
    return args

def main():
    banner()
    if not check_platform():
        sys.exit()

    args=get_arguments()
    output_filename=args.output
    Output().create_output_file(output_filename)

    modules_dir='./modules/'
    config_path=args.config
    config_obj=Config(config_path)
    target_list=config_obj.get_target()
    import_module(modules_dir,output_filename,target_list)

if __name__ == "__main__":
    main()
