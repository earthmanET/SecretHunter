import yaml

class Config:
    def __init__(self,yaml_path):
        self.yaml_path=yaml_path
        self.config=self.init_config()

    def init_config(self):
        yaml_path=self.yaml_path
        config_file = open(yaml_path,'r',encoding='utf-8')
        cont = config_file.read()
        config = yaml.load(cont,Loader=yaml.FullLoader)
        return config

    def get_target(self):
        target_list=self.config['target']
        return target_list