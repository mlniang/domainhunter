import json
import requests

from providers.iprovider import IProvider

class CiscoUmbrella(IProvider):
    def __init__(self, key: str = None):
        super(CiscoUmbrella, self).__init__('cisco.umbrella')
        if key:
            self.conf['key'] = key

        if not self.conf.get('key', None):
            raise Execption("Cisco Umbrella API KEY missing, please configure it")

    def check(self, domain, proxies = {}):
        """Umbrella Domain reputation service"""
        if not self.conf.get('key', None):
            return '[-] Umbrella key not configured'
        try:
            s = requests.Session()
            url = 'https://investigate.api.umbrella.com/domains/categorization/?showLabels'
            postData = [domain]

            headers = {
                'User-Agent': self.conf['user_agent'],
                'Content-Type':'application/json; charset=UTF-8',
                'Authorization': 'Bearer {}'.format(self.conf['key'])
            }

            print('[*] Umbrella: {}'.format(domain))
            
            response = s.post(url,headers=headers,json=postData,verify=False,proxies=proxies)
            responseJSON = json.loads(response.text)
            if len(responseJSON[domain]['content_categories']) > 0:
                return responseJSON[domain]['content_categories'][0]
            else:
                return 'Uncategorized'

        except Exception as e:
            print('[-] Error retrieving Umbrella reputation! {0}'.format(e))
            return "error"