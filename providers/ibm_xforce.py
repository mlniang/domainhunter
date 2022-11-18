import json
import requests

from providers.iprovider import IProvider

class IBMXForce(IProvider):
    def __init__(self):
        super(IBMXForce, self).__init__('ibm.xforce')

    def check(self, domain, proxies = {}):
        try:
            s = requests.Session()
            url = 'https://exchange.xforce.ibmcloud.com/url/{}'.format(domain)
            headers = {
                'User-Agent': self.conf['user_agent'],
                'Accept':'application/json, text/plain, */*',
                'x-ui':'XFE',
                'Origin':url,
                'Referer':url
            }

            print('[*] IBM xForce: {}'.format(domain))

            url = 'https://api.xforce.ibmcloud.com/url/{}'.format(domain)
            response = s.get(url,headers=headers,verify=False,proxies=proxies)

            responseJSON = json.loads(response.text)

            if 'error' in responseJSON:
                a = responseJSON['error']

            elif not responseJSON['result']['cats']:
                a = 'Uncategorized'
        
        ## TO-DO - Add noticed when "intrusion" category is returned. This is indication of rate limit / brute-force protection hit on the endpoint        

            else:
                categories = ''
                # Parse all dictionary keys and append to single string to get Category names
                for key in responseJSON['result']['cats']:
                    categories += '{0}, '.format(str(key))

                a = '{0}(Score: {1})'.format(categories,str(responseJSON['result']['score']))

            return a

        except Exception as e:
            print('[-] Error retrieving IBM-Xforce reputation! {0}'.format(e))
            return "error"