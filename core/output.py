import datetime
import time 

class Log:
    def info(self,info):
        level=2
        self.__print_log(level,info)

    def warning(self,info):
        level=3
        self.__print_log(level,info)

    def error(self,info):
        level=4
        self.__print_log(level,info)

    def __print_log(self,level,info):
        print(info)

class Output:
    def __init__(self):
        self.output_file=None

    def create_output_file(self,output_filename):
        #current_time=time.strftime("%Y_%m_%d_%H_%M_%S", time.localtime())
        #self.output_filename='result'+current_time
        try:
            output_file=open(output_filename,"w+")
            output_file.close()
        except:
            Log().error('File open failed')
            pass

    def output_to_file(self, output_filename, result):
        for result_item in result:
            try:
                with open(output_filename,'a') as output_file:
                    output_file.writelines('[+]'+result_item['desc']+'\n')
                    for data_item in result_item['data']:
                        for key in data_item:
                            if data_item[key]:
                                output_file.writelines(key+': '+str(data_item[key])+'\n')
                    output_file.writelines('\n')
            except:
                Log().error('[-]File open failed')
                pass
    
    def output_to_terminal(self, result):
        for result_item in result:
            try:
                Log().info('[+]'+result_item['desc'])
                for data_item in result_item['data']:
                    for key in data_item:
                        if data_item[key]:
                            Log().info(key+': '+str(data_item[key]))
                Log().info('')
            except:
                Log().error('[-]Output to terminal failed')
                pass
