"""
Com-301's second assignment
Check ArtificialClass class for instruction and fill the main function.
"""

import json
import base64
import struct
import socket

from petlib import cipher
from sys import stdout
from time import sleep
from os import urandom

from hashlib import sha256


##################################
#######   Internal parts   #######
##################################
#  This part handles networking  #
# You shouldn't change this code #
##################################


class Message(object):
    """ A message between the client and the server

    Encodes byte arrays with base64 for text base transfer.
    """

    def __init__(
        self, message="", decrypted="", encrypted=b"", iv=b"", response="", error=""
    ):
        self.message = message
        self.decrypted = decrypted
        self.encrypted = encrypted
        self.iv = iv
        self.response = response
        self.error = error

    def to_json(self):
        msg = {
            "message": self.message,
            "decrypted": self.decrypted,
            "response": self.response,
            "error": self.error,
            "encrypted": str(base64.b64encode(self.encrypted), "utf8"),
            "iv": str(base64.b64encode(self.iv), "utf8") if self.iv != "" else "",
        }
        return json.dumps(msg)

    @staticmethod
    def load_json(string):
        dt = json.loads(string)
        msg = Message(
            message=dt["message"],
            decrypted=dt["decrypted"],
            encrypted=base64.b64decode(dt["encrypted"]),
            iv=base64.b64decode(dt["iv"]),
            response=dt["response"],
            error=dt["error"],
        )
        return msg


class Link(object):
    """ Handles the connection between the client and the server. """

    SERVER_HOST = "com-301-hw2.k8s.iccluster.epfl.ch"
    SERVER_PORT = 31337

    def __init__(self, _socket=None):
        """_socket option is used in the server's code."""
        self.socket = _socket

    def connect(self, host=SERVER_HOST, port=SERVER_PORT):
        """Connect to host:port. Creates a TCP connection to our server."""
        print(f"Connecting to {host}:{port}\n ...")
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((host, port))
            self.socket.settimeout(10000)
        except:
            print(
                f"Connection failed. We restrict access to EPFL IPs. "
                + "Make sure that you are connecting from EPFL's network."
            )
            self.disconnect()
        print(f"Connection established.")

    def disconnect(self):
        """Disconnect from the server and exit the program."""
        self.socket.close()
        exit()

    def send_message(self, message):
        """Send a message"""
        bts = message.to_json()
        self.socket.send(struct.pack("!i", len(bts)))
        self.socket.sendall(bts.encode("utf8"))

    def receive_message(self):
        """Receive a message"""
        data = self.socket.recv(4096)
        if len(data) == 0:
            print("Connection is terminated.")
            self.disconnect()
        size = struct.unpack("!i", data[:4])[0]
        data = data[4:]

        while len(data) < size:
            new = self.socket.recv(4096)
            if new is None:
                print("Connection error.")
                self.disconnect()

            data += new
        msg = Message.load_json(data)
        if msg.error != "":
            print(f"Challenge failed: {msg.error}")
            self.disconnect()
        return msg


####################################################
#######           Artificial Classroom       #######
####################################################
#      This code simulates Alie and the TA         #
#        You shouldn't change this code            #
####################################################


class ArtificialClass(object):
    def __init__(self, sciper, mode):
        """ Creates the artificial classroom to enable you
        to communicate with Alice and with the TA:

        - Receive Alice's encrypted messages.
        - Receive TA's convincing arguments
        - Send encrypted messages to Alice.

        Warning: you need to provide a valid sciper to get a valid token.

        Args:
            sciper: your sciper id
            mode: 'part1' for part 1, and 'part2' for part 2
        """
        if mode != "part1" and mode != "part2":
            print("Invalid mode")
            exit()

        print("Hi,")
        print(f"Your sciper id is {sciper}.")
        print(
            "Warning: if this is not your sciper id then you will receive an invalid token."
        )

        self.link = Link()
        self.link.connect()
        self.link.send_message(Message(message=mode, response=str(sciper)))

        # Here we create the key that Alice gives you to communicate with her
        # In practice Alice would give you this key out of band. 
        # For the purpose of the exercise the key is deterministic (the key will not change across executions).
        self.key = sha256(
            (str(sciper) + "|" + mode + "|sec_key").encode("utf8")
        ).digest()[:16]

    def get_symmetric_key_from_alice(self):
        """ Returns the symmetric key shared between you and Alice.

        Return:
            bytes: symmetric key
        """
        return self.key

    def _conversation(self):
        """ An internal function to contact the server and obtain responses from Alice and TA
            You do NOT need to use this function
        """
        message = self.link.receive_message()
        self.alice_enc_message = message.encrypted
        self.convincing_argument = message.response
        self.alice_iv_in = message.iv

    def receive_alice_message(self):
        """ Receives a new message from Alice.

        Return:
                alice_enc_message (bytes): Alice's encrypted message. You need to decrypt this message.
                alice_iv_in (bytes): Alice's message's IV. This can be empty.
        """
        self._conversation()
        return self.alice_enc_message, self.alice_iv_in

    def get_ta_argument(self, alice_message):
        """ Reveal Alice's concern to TA and receive a convincing argument. You need to get
        a new message from alice (recieve_alice_message) and decrypt it before asking TA for
        a new argument. 

        Args:
            alice_message (string): Alice's decrypted message 
        Return:
                convincing_argument (string): A convincing argument from the TA. You need to encrypt this.
        """
        print(f"Alice: {alice_message}")
        self.alice_dec_digest = sha256(bytes(alice_message, 'utf-8')).hexdigest()
        return self.convincing_argument

    def send_message_to_alice(self, response, IV_out=""):
        """ Respond to Alice's concern.

        You need to encrypt TA's argument and send it to Alice.
        If Alice needs an IV to decrypt your response you can enter it in IV_out.

        Args:
            response (bytes): Encrypted TA's convincing argument for Alice's concern.
            IV (bytes): Alice's message's IV. This can be empty.
        """

        print(f"You: [{self.convincing_argument}]")
        print(f"Sending", end='', flush=True)
        for _i in range(3):
            print(".", end='', flush=True)
            sleep(0.4)
        print('')

        # [we're sending hash of Alice's decrypted message back to her, to make sure that
        #  you are relying her messsage to TA correctly] 
        msg = Message(encrypted=response, decrypted=self.alice_dec_digest, iv=IV_out)
        self.link.send_message(msg)


##################################
#######    Assignment 2    #######
##################################
#     Solve Alice's problem      #
##################################

def enc_dec(cl, ciph_type):
    """
    Takes msg from alice, gets response from the ta and sends it to alice. Returns alice's response
    """

    msg1,iv = cl.receive_alice_message()
    key = cl.get_symmetric_key_from_alice()
    aes = cipher.Cipher(ciph_type)

    # if len(iv)==0:
    #     print("ALICE SENT AN EMPTY IV!")
    #     iv = ("\0"*16).encode('utf-8')
    #     print("iv is now",iv)

    dec = aes.dec(key,iv)
    txt = dec.update(msg1)
    txt += dec.finalize()
    txt = txt.decode('utf8') # change from byte string to string


    iv = urandom(16)
    ta_arg1 = cl.get_ta_argument(txt)

    enc = aes.enc(key,iv)
    ciph_ToA = enc.update(bytes(ta_arg1,'utf-8'))
    ciph_ToA += enc.finalize()
    cl.send_message_to_alice(ciph_ToA,iv)

    

def part_one():
    """ 
        Instantiate an ArtificialClass with your sciper id and convince Alice.
        Decrypt her messages and send to her the TA convincing arguments, 
        until she is convinced and gives you a token (you may need more than one message!)
    """

    # replace with your sciper!!!
    cl = ArtificialClass(sciper=313180, mode="part1")
    
    enc_dec(cl,"AES-128-CBC")
    enc_dec(cl,"AES-128-CBC")
    enc_dec(cl,"AES-128-CBC")
    enc_dec(cl,"AES-128-CBC")



def part_two():
    """ 
        Instantiate an ArtificialClass with your sciper id and convince Alice.
        Decrypt her messages and send to her the TA convincing arguments, 
        until she is convinced and gives you a token (you may need more than one message!)
    """

    # replace with your sciper!!!
    cl = ArtificialClass(sciper=313180, mode="part2")

    """
    It seems like for this part it's giving an error because the initializaiton vector is 
    returning zero the second time we recieve message from alice. I tried to resolve
    this by changing the vector to be nulls (identity) sot hat it's or'ed with itself but 
    that didn't work. also tried resuing first one but that didn't work.
    I don't know why the first time we decrypted alice's msg we did get a vector and 
    why CTR can sometimes have a vector and sometimes not??? Doesn't it just have a nonce?
    """

    enc_dec(cl,"AES-128-CTR")
    enc_dec(cl,"AES-128-CTR")
    enc_dec(cl,"AES-128-CTR")

    # msg1,iv = cl.receive_alice_message()
    # key = cl.get_symmetric_key_from_alice()

    # aes = cipher.Cipher("AES-128-CTR")

    # decrypt = aes.dec(key,iv)
    # txt = decrypt.update(msg1)
    # txt += decrypt.finalize()

    # txt=txt.decode('utf8')

    # print("Msg is:",txt)
    # ta_arg = cl.get_ta_argument(txt)

    # new_iv=urandom(16)
    # encrypt = aes.enc(key,new_iv)
    # toSend = encrypt.update(bytes(txt,'utf8'))
    # toSend += encrypt.finalize()

    # cl.send_message_to_alice(toSend, new_iv)

    # msg2,iv2 = cl.receive_alice_message()
    # msg1 = cl.get_alice_message()
    # decrypt
    # ta_arg1 = cl.get_ta_argument()
    # cl.send_message_to_alice(...)


def main():
    """ Assignment 2: Fill the main function.

    Solve two challenges. After getting a correct token, the program
    closes, so you need to run challenges one by one.
    """

   # part_one()
    part_two()


if __name__ == "__main__":
    main()
