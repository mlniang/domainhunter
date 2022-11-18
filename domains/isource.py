import requests

from abc import ABC, abstractmethod
from config import Config

class ISource:
    def __init__(self, conf_path: str, conf_root = 'sources'):
        conf = Config()
        self.conf = conf.get(conf_path, conf_root)
        self.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0'}
        self.session = requests.Session()
    

    @abstractmethod
    def login(self, username: str, password: str, proxies: dict = {}):
        pass

    @abstractmethod
    def list_domains(self, **args):
        pass
