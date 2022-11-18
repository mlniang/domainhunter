
import base64
import json
import random
import requests

# Bluecoat XSRF
from hashlib import sha256

from providers.iprovider import IProvider

class Bluecoat(IProvider):
    def __init__(self):
        super(Bluecoat, self).__init__('symantec.bluecoat')

    def check(self, domain, proxies = {}):
        try:
            s = requests.Session()
            headers = {
                'User-Agent': self.conf['user_agent'],
                'Referer':'http://sitereview.bluecoat.com/'
            }

            # Establish our session information
            response = s.get("https://sitereview.bluecoat.com/",headers=headers,verify=False,proxies=proxies)
            response = s.head("https://sitereview.bluecoat.com/resource/captcha-request",headers=headers,verify=False,proxies=proxies)
            
            # Pull the XSRF Token from the cookie jar
            session_cookies = s.cookies.get_dict()
            if "XSRF-TOKEN" in session_cookies:
                token = session_cookies["XSRF-TOKEN"]
            else:
                raise NameError("No XSRF-TOKEN found in the cookie jar")
    
            # Perform SiteReview lookup
            
            # BlueCoat Added base64 encoded phrases selected at random and sha256 hashing of the JSESSIONID
            phrases = [
                'UGxlYXNlIGRvbid0IGZvcmNlIHVzIHRvIHRha2UgbWVhc3VyZXMgdGhhdCB3aWxsIG1ha2UgaXQgbW9yZSBkaWZmaWN1bHQgZm9yIGxlZ2l0aW1hdGUgdXNlcnMgdG8gbGV2ZXJhZ2UgdGhpcyBzZXJ2aWNlLg==',
                'SWYgeW91IGNhbiByZWFkIHRoaXMsIHlvdSBhcmUgbGlrZWx5IGFib3V0IHRvIGRvIHNvbWV0aGluZyB0aGF0IGlzIGFnYWluc3Qgb3VyIFRlcm1zIG9mIFNlcnZpY2U=',
                'RXZlbiBpZiB5b3UgYXJlIG5vdCBwYXJ0IG9mIGEgY29tbWVyY2lhbCBvcmdhbml6YXRpb24sIHNjcmlwdGluZyBhZ2FpbnN0IFNpdGUgUmV2aWV3IGlzIHN0aWxsIGFnYWluc3QgdGhlIFRlcm1zIG9mIFNlcnZpY2U=',
                'U2NyaXB0aW5nIGFnYWluc3QgU2l0ZSBSZXZpZXcgaXMgYWdhaW5zdCB0aGUgU2l0ZSBSZXZpZXcgVGVybXMgb2YgU2VydmljZQ=='
            ]
            
            # New Bluecoat XSRF Code added May 2022 thanks to @froyo75
            xsrf_token_parts = token.split('-')
            xsrf_random_part = random.choice(xsrf_token_parts)
            key_data = xsrf_random_part + ': ' + token
            # Key used as part of POST data
            key = sha256(key_data.encode('utf-8')).hexdigest()
            random_phrase = base64.b64decode(random.choice(phrases)).decode('utf-8')
            phrase_data = xsrf_random_part + ': ' + random_phrase
            # Phrase used as part of POST data
            phrase = sha256(phrase_data.encode('utf-8')).hexdigest()
            
            postData = {
                'url':domain,
                'captcha':'',
                'key':key,
                'phrase':phrase, # Pick a random base64 phrase from the list
                'source':'new-lookup'
            }

            headers = {
                'User-Agent': self.conf['user_agent'],
                'Accept':'application/json, text/plain, */*',
                'Accept-Language':'en_US',
                'Content-Type':'application/json; charset=UTF-8',
                'X-XSRF-TOKEN':token,
                'Referer':'http://sitereview.bluecoat.com/'
            }

            print('[*] BlueCoat: {}'.format(domain))
            response = s.post('https://sitereview.bluecoat.com/resource/lookup',headers=headers,json=postData,verify=False,proxies=proxies)
            
            # Check for any HTTP errors
            if response.status_code != 200:
                a = "HTTP Error ({}-{}) - Is your IP blocked?".format(response.status_code,response.reason)
            else:
                responseJSON = json.loads(response.text)
            
                if 'errorType' in responseJSON:
                    a = responseJSON['errorType']
                else:
                    a = responseJSON['categorization'][0]['name']
            
                # Print notice if CAPTCHAs are blocking accurate results and attempt to solve if --ocr
                if a == 'captcha':
                    if ocr:
                        # This request is also performed by a browser, but is not needed for our purposes
                        #captcharequestURL = 'https://sitereview.bluecoat.com/resource/captcha-request'

                        print('[*] Received CAPTCHA challenge!')
                        captcha = solveCaptcha('https://sitereview.bluecoat.com/resource/captcha.jpg',s)
                        
                        if captcha:
                            b64captcha = base64.urlsafe_b64encode(captcha.encode('utf-8')).decode('utf-8')
                        
                            # Send CAPTCHA solution via GET since inclusion with the domain categorization request doesn't work anymore
                            captchasolutionURL = 'https://sitereview.bluecoat.com/resource/captcha-request/{0}'.format(b64captcha)
                            print('[*] Submiting CAPTCHA at {0}'.format(captchasolutionURL))
                            response = s.get(url=captchasolutionURL,headers=headers,verify=False,proxies=proxies)

                            # Try the categorization request again

                            response = s.post('https://sitereview.bluecoat.com/resource/lookup',headers=headers,json=postData,verify=False,proxies=proxies)

                            responseJSON = json.loads(response.text)

                            if 'errorType' in responseJSON:
                                a = responseJSON['errorType']
                            else:
                                a = responseJSON['categorization'][0]['name']
                        else:
                            print('[-] Error: Failed to solve BlueCoat CAPTCHA with OCR! Manually solve at "https://sitereview.bluecoat.com/sitereview.jsp"')
                    else:
                        print('[-] Error: BlueCoat CAPTCHA received. Try --ocr flag or manually solve a CAPTCHA at "https://sitereview.bluecoat.com/sitereview.jsp"')
            return a

        except Exception as e:
            print('[-] Error retrieving Bluecoat reputation! {0}'.format(e))
            return "error"