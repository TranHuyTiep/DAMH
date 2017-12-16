import paho.mqtt.client as paho
import pysodium
from builtins import print

import ECC

url_client1_publicKey = 'chat/client1/publicKey'
url_client1_publicKey_massage2 = 'chat/client1/publicKey/massage2'
url_client1_message = 'chat/client1/message'
url_client2_publicKey = 'chat/client2/publicKey'
url_client2_message = 'chat/client2/message'
url_client2_publicKey_massage2 = 'chat/client2/publicKey/massage2'

# chung chi so khoa bi mat cua Ia
private_key = 294111635673278162351154176014102396387625451979036227419125313074038381658941
IC_a = 734094368413402745248246225420036830997793844421753261558905224574286217914420
C_ca_a = 160525881502485434026879635433951019388458014395473238246856144097602432343671
ID_a = 'huytiep'
n_a = ''
n_b = ''

ID_b = ''
IC_b = ''
C_ca_b = ''
Pk = ''
Lk = ''
massage_authen =''

n_a_templ = ''
n_b_templ = ''

def aead_chacha20poly1305_encrypt(key,input,nonce):
    key = bytes.fromhex(key)
    ad = nonce = bytes.fromhex(nonce)
    input = input.encode()
    output_str = pysodium.crypto_aead_chacha20poly1305_encrypt(input, ad, nonce, key)
    return output_str.hex()

def aead_chacha20poly1305_decrypt(key,input_cipherText,nonce):
    key = bytes.fromhex(key)
    ad = nonce = bytes.fromhex(nonce)
    input_cipherText = bytes.fromhex(input_cipherText)
    output_str = pysodium.crypto_aead_chacha20poly1305_decrypt(input_cipherText, ad, nonce, key)
    return output_str.decode()


#lang nghe message
def on_message(client, userdata, msg):
    # neu Ib goi
    if(msg.topic == url_client2_publicKey):
        global n_a
        global n_b
        global IC_b
        global ID_b
        global C_ca_b
        global Pk
        global Lk
        global massage_authen
        global n_b_templ
        global n_a_templ

        ms = (msg.payload).decode("utf-8")
        ms = (ms.split(','))
        n_b_templ = n_b = ms[1]
        ID_b = ms[2]
        IC_b = ms[3]
        C_ca_b = ms[4]

        # tinh khoa cong khai P b,A = C + P A · H(P A , I A ).
        P_client  = ECC.create_key_to_third_party(int(C_ca_b),ID_b,int(IC_b))
        # P = s v,B · P b,A .
        P = ECC.scalar_mult(private_key,ECC.x_to_Point(P_client))

        if(P[0]):
            state = pysodium.crypto_generichash_init(32)
            pysodium.crypto_generichash_update(state, str(P[0]).encode())
            # Pre Link Key, P K
            Pk = pysodium.crypto_generichash_final(state,32).hex()
            # α A = Auth(P K , (P A , P B , ρ A , ρ B )).
            massage_authen = str(IC_a)+str(IC_b)+n_a+n_b
            massage2 = aead_chacha20poly1305_encrypt(Pk,massage_authen,n_a)
            # gui cho B
            client.publish(url_client1_publicKey_massage2,massage2, qos=1)
    # lang nghe α B = Auth(P K , (P B , P A , ρ B , ρ A )).
    elif(msg.topic == url_client2_publicKey_massage2):
        ms = (msg.payload).decode("utf-8")
        try:
            verify = aead_chacha20poly1305_decrypt(Pk,ms,n_b)
            if(verify==massage_authen):
                Lk = str(Pk+n_a+n_b).encode()
                state2 = pysodium.crypto_generichash_init(32)
                pysodium.crypto_generichash_update(state2, Lk)
                Lk = pysodium.crypto_generichash_final(state2, 32).hex()
        except(ValueError):
            print(b'ValueError')
    # massage nhan dc
    else:
        ms = (msg.payload).decode("utf-8")
        ms = aead_chacha20poly1305_decrypt(Lk,(ms),n_b)
        print('Message nhận: ' + ms)

def on_connect(client, userdata, flags, rc):
    client.subscribe(url_client2_publicKey)
    client.subscribe(url_client2_publicKey_massage2)

client = paho.Client()
client.on_connect = on_connect
client.on_message = on_message
client.connect('test.mosquitto.org', 1883)
client.subscribe(url_client2_message)
# send Alice’s private key
# Alice’s public key
# Alice’s implicit certificate
# nonce
n_a_templ = n_a = pysodium.randombytes(8).hex()
send = 'massage1' + ',' + n_a + ',' + ID_a + ',' + str(IC_a) + ',' + str(C_ca_a)
client.publish(url_client1_publicKey, send, qos=1)

print('Nhâp message!')
run = True
while(run):
 client.loop_start()
 reply = input()
 reply = aead_chacha20poly1305_encrypt(Lk,reply,n_a)
 if(reply):
     client.publish('chat/client1/message', reply, qos=2)





