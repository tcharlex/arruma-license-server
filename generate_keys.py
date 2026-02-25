from nacl.signing import SigningKey
import base64

# gera chave privada
private_key = SigningKey.generate()
public_key = private_key.verify_key

# salvar privada (servidor)
with open("license_private.key", "wb") as f:
    f.write(base64.b64encode(private_key.encode()))

# salvar pública (vai para o cliente futuramente)
with open("license_public.key", "wb") as f:
    f.write(base64.b64encode(public_key.encode()))

print("Chaves geradas!")
