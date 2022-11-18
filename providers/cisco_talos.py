import json
import requests

from bs4 import BeautifulSoup
from providers.iprovider import IProvider

class CiscoTalos(IProvider):
    def __init__(self):
        super(CiscoTalos, self).__init__('cisco.talos')

    def check(self, domain, proxies = {}):
        s = requests.Session()
        base_url = 'https://talosintelligence.com'
        url = '{0}/cloud_intel/url_reputation?url={1}'.format(base_url, domain)
        headers = {
            'user-agent': self.conf['user_agent'],
            'Referer': '{0}/reputation_center'.format(base_url)
        }
        

        print('[*] Cisco Talos: {}'.format(domain))
        
        try:
            response = s.get(url, headers=headers, allow_redirects=True, proxies=proxies)

            responseJSON = json.loads(response.text)['reputation']

            if responseJSON['error'] != 'ERROR_NONE':
                a = 'ERROR: {0}'.format(str(responseJSON['error']))
            else:
                aup_cat = responseJSON['aup_cat']
                if len(aup_cat) == 0:
                    a = 'Uncategorized'
                else:
                    category = str(aup_cat[0]['desc_short'][0]['text'])
                    reputation = str(responseJSON['threat_level_mnemonic'])
                    a = '{0} (Reputation: {1})'.format(category, reputation)
        
            return a

        except Exception as e:
            print('[-] Error retrieving Talos reputation! {0}'.format(e))
            traceback.print_exc()
            return "error"