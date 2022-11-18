from abc import ABC, abstractmethod

from config import Config

class IProvider:
    def __init__(self, conf_path: str, conf_root = 'providers'):
        conf = Config()
        self.conf = conf.get(conf_path, conf_root)
        self.conf['user_agent'] = 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'
    

    @abstractmethod
    def check(self, domain: str, proxies: dict = {}):
        pass
