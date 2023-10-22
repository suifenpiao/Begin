import mmh3
import sys
import requests
import urllib3
import base64
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
def hashico(url):
	target=url+"/favicon.ico"
	response = requests.get(url=target,verify=False)
	r1 = response.content
	r2=base64.encodebytes(r1)
	hash = mmh3.hash(r2)
	print('[fofa] icon_hash="' + str(hash)+'"')
if __name__ == '__main__':
	hashico(sys.argv[1])