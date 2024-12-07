from app.cipher import enc64, dec64  # Import encryption and decryption functions
import random
P = [random.randint(0, 15) for _ in range(16)]
K = [random.randint(0, 15) for _ in range(32)]
print("Plaintext",P)

E=enc64(P,K,28,True)
print(E)
print(dec64(E,K,28,True))
# print("enc",E)
# print("dec",dec64(E,K,28,True))

# 04 08 03 04 09 04 06 0b 0f 09 0c 0f 08 01 0d 0c 
# 04 08 03 04 09 04 06 0b 0f 09 0c 0f 08 01 0d 0c 
