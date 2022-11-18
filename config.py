import os
import yaml

CONF_FILE = os.getenv('DOMAIN_HUNTER_CONF') or os.getenv('HOME') + '/.config/domainhunter/conf.yml'

class Config:
    
    def __init__(self):
        if not (os.path.isfile(CONF_FILE) and os.access(CONF_FILE, os.R_OK)):
            raise Exception("Config file not found or not readable. Please configure it correctly")
        
        with open(CONF_FILE, 'r') as stream:
            self.conf = yaml.safe_load(stream)
        
    def get(self, inner_path, root = 'providers'):
        value = self.conf[root] if root else self.conf
        parts = inner_path.split('.')
        for p in parts:
            if p not in value:
                return {}
            value = value[p]
        
        return value