import json
import requests

from bs4 import BeautifulSoup
from providers.iprovider import IProvider

class McAfeeWG(IProvider):
    def __init__(self):
        super(McAfeeWG, self).__init__('mcafee.wg')

    def check(self, domain, proxies = {}):
        try:
            print('[*] McAfee Web Gateway (Cloud): {}'.format(domain))

            # HTTP Session container, used to manage cookies, session tokens and other session information
            s = requests.Session()

            headers = {
                'User-Agent': self.conf['user_agent'],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Referer':'https://sitelookup.mcafee.com/'
            }  

            # Establish our session information
            response = s.get("https://sitelookup.mcafee.com",headers=headers,verify=False,proxies=proxies)

            # Pull the hidden attributes from the response
            soup = BeautifulSoup(response.text,"html.parser")
            hidden_tags = soup.find_all("input",  {"type": "hidden"})
            for tag in hidden_tags:
                if tag['name'] == 'sid':
                    sid = tag['value']
                elif tag['name'] == 'e':
                    e = tag['value']
                elif tag['name'] == 'c':
                    c = tag['value']
                elif tag['name'] == 'p':
                    p = tag['value']

            # Retrieve the categorization infos 
            multipart_form_data = {
                'sid': (None, sid),
                'e': (None, e),
                'c': (None, c),
                'p': (None, p),
                'action': (None, 'checksingle'),
                'product': (None, '14-ts'),
                'url': (None, domain)
            }

            response = s.post('https://sitelookup.mcafee.com/en/feedback/url',headers=headers,files=multipart_form_data,verify=False,proxies=proxies)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text,"html.parser")
                for table in soup.findAll("table", {"class": ["result-table"]}):
                    datas = table.find_all('td')
                    if "not valid" in datas[2].text:
                        a = 'Uncategorized'
                    else:
                        status = datas[2].text
                        category = (datas[3].text[1:]).strip().replace('-',' -')
                        web_reputation = datas[4].text
                        a = '{0}, Status: {1}, Web Reputation: {2}'.format(category,status,web_reputation)
                return a
            else:
                raise Exception

        except Exception as e:
            print('[-] Error retrieving McAfee Web Gateway Domain Reputation!')
            return "error"
