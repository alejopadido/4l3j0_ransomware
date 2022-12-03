'''
requirements:
* pycryptodome
'''

from Crypto.PublicKey import RSA

# generacion de claves
key = RSA.generate(2048)
privateKey = key.export_key()
publicKey = key.public_key().export_key()

# guardado de claves en archivos
with open('private.pem', 'wb') as f:
    f.write(privateKey)

with open('public.pem', 'wb') as f:
    f.write(publicKey)

print('Clave privada guardada en private.pem')
print('Clave publica guardada en public.pem')
print('Hecho')
