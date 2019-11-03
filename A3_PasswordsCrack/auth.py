#!/usr/bin/python3
"""
Checks validity of passwords for Com-301 homework 6.
Read the main function for instruction.
"""
import json
import base64
import random
import string

from hashlib import sha256, scrypt
from collections import deque

simplified = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" # gets partial score
valid_chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
db = {}
sciper = 0
ans_hash = ""

def get_base64_str(bts):
    """gets a bytes a encodes it as a base64 string"""
    return str(base64.b64encode(bts), "utf8")


def gen_accept_token(sciper, part, username, password):
    return get_base64_str(
        sha256(f"{sciper}|{username}|{password}".encode("utf8")).digest()
    )


def initialize(_sciper):
    """Takes a sciper and initializes the system. This function loads assignment
	parameters from {sciper}_auth.json.

	Args:
		_sciper (int): sciper
	"""
    global db
    global sciper
    sciper = _sciper
    print("Hi,")
    print(f"Your sciper id is {sciper}.")
    print(
        "Warning: if this is not your sciper id then you will receive invalid tokens."
    )
    try:
        with open(str(sciper) + "_auth.json") as file:
            db = json.load(file)
    except Exception as e:
        print("Error!")
        print(
            f"Don't forget to download the {sciper}_auth.json from the grading",
            " site, and put it in the same directory as the script",
        )
        exit()


def hash_sha(password):
    return sha256(str(password).encode("utf8")).digest()


def hash_scrypt(salt, password):
    return scrypt(str(password).encode("utf8"), salt=salt, n=2 ** 10, r=8, p=1)


def check_correctness_sha(username, password):
    """Gets a user:pass from input and checks their validity for part 1.

	Args:
		username (string): username
		password (string): password
	"""
    global ans_hash
    if username not in db["sha256"]:
        print("invalid username")
        return False

    check = get_base64_str(hash_sha(password))
    if check != db["sha256"][username]:
#        print("Password is wrong")
        return False

    token = gen_accept_token(sciper, "1", username, password)
    print("Accept!")
    print(f"Your token: {token}")
    ans_hash = token
    return True


def check_correctness_scrypt(username, password):
    """Gets a user:pass from input and checks their validity for part 2.

	Args:
		username (string): username
		password (string): password
	"""
    if username not in db["scrypt"]:
        print("invalid username")
        return False
    
    salt = base64.b64decode(db["scrypt"][username]["salt"])
    check = get_base64_str(hash_scrypt(salt, password))
    expect = db["scrypt"][username]["hash"]
    if check != expect:
    #    print("Password is wrong")
        return False

    token = gen_accept_token(sciper, "2", username, password)
    print("Accept!")
    print(f"Your token: {token}")
    ans_hash = token
    return True

def brute(s,sha_users):
    """uses queue to do a depth first search
    but password space is too big so I get python memory errors, i think"""
    q = deque([""])
    while len(q)!=0:
        elt = q.popleft()
        print(elt)
        if len(q)!=0 and len(elt)!=len(q[0]): print("new len",elt)
        #yield elt #try password here

        for sha_u in sha_users:
            if check_correctness_sha(sha_u,elt):
                print("FOUND SHA PASSWORD:",sha_u,"is",elt)
                save_to_file(sha_u,elt)

        #checks passwords up to length 10
        if len(elt)>=10: continue #>=len(s): continue
        for i in s:
            q.append(elt+i)
        #print("Now q is",q)
    print("done with bf, last elt",elt)

def rand_brute(s,l,sha_users):
    for i in range(len(s)**l):
        elt = ''.join(random.choice(s) for i in range(l))
        print(elt)
        for sha_u in sha_users:
                if check_correctness_sha(sha_u,elt):
                    print("FOUND SHA PASSWORD:",sha_u,"is",elt)
                    save_to_file(sha_u,elt)

def counter_brute(s,starting):
    """ s is string you are searching
        user is list of users to check
        starting is string count you are starting at
    """
    #assumes starting is with atlest 2 characters
    curr = starting
    s_at=0
    while len(curr)<len(s):
        yield curr
        if s_at==len(s)-1: #we're at last digit
            curr = curr[:-1] + s[0]
            at=len(curr)-2 #at points to second to last digit
            while(at>=0): # go backwards through and find the digit that's not maxed out
                if curr[at]==s[-1]: # case where digit is maxed out. keep going back
                    curr = curr[:at]+s[0]+curr[at+1:] #+1 bc we want to replace char at at with s[0]
                    at-=1
                else:
                    s_ind = s.find(curr[at]) #find which digit we are at in s
                    curr = curr[:at]+s[s_ind+1]+curr[at+1:]
                    break #we're done
            if at==-1: # if we went all the way backwards and didn't use the break that means we need to add new digit infront
                curr = s[0]+curr
            s_at=0
        else:
            s_at+=1
            curr = curr[:-1] + s[s_at]
                

def save_to_file(u,guess):
    global ans_hash
    pfile = open("passwords.txt","a+")
    pfile.write(u+", "+guess+", "+ans_hash+'\n')
    pfile.close()

def main():
    """ Assignment 3: cracking passwords
	This scripts lets you check your password guesses .
	You need to call initialize with your sciper.
	Afterward you can check your passwords with:
		check_correctness_sha(username, password)
		check_correctness_scrypt(username, password)
	If the password is correct, then you'll receive a grade token.
	WARNING: to get a valid token, you should not change any function besides main
	"""
    initialize(_sciper=313180)
    # for i in brute("abc"):
    #     print(i)

    #design password cracking system
    print("starting bruteforce")
    sha_users = list(db["sha256"].keys())
    script_users = list(db["scrypt"].keys())


    # for guess in brute(simplified):
    #     for ind,sha_u in enumerate(sha_users):
    #         #print("at",u,guess)
    #         if check_correctness_sha(sha_u,guess):
    #             print("FOUND SHA PASSWORD:",sha_u,"is",guess)
    #            save_to_file(sha_u,guess)

            #     #return
            # if check_correctness_scrypt(script_users[ind],guess):
            #     print("FOUND Scrypt PASSWORD:",script_users[ind],"is",guess)
            #     save_to_file(script_users[ind],guess)
            
   # brute(simplified[:20],sha_users)

    # s= "0123456789abcdefghijklmnopqrstuvwxyz"
    # q = deque([""])
    # while len(q)!=0:
    #     elt = q.popleft()
    #     #print(elt)
    #     if len(q)!=0 and len(elt)!=len(q[0]): print("new len",elt)
    #     #yield elt #try password here

    #     for sha_u in sha_users:
    #         if check_correctness_sha(sha_u,elt):
    #             print("FOUND SHA PASSWORD:",sha_u,"is",elt)
    #             save_to_file(sha_u,elt)

    #     #checks passwords up to length 10
    #     if len(elt)>=10: continue #>=len(s): continue
    #     for i in s:
    #         q.append(elt+i)
    #     #print("Now q is",q)
    # print("done with bf, last elt",elt)

    #rand_brute("abcd123",4)
    # s=simplified
    # for l in range(5,12):
    #     print("on L",l)
    #     for i in range(len(s)**l):
    #         elt = ''.join(random.choice(s) for i in range(l))
    #         #print(elt)
    #         for sha_u in sha_users:
    #                 if check_correctness_sha(sha_u,elt):
    #                     print("FOUND SHA PASSWORD:",sha_u,"is",elt)
    #                     save_to_file(sha_u,elt)
    s=simplified
    for elt in counter_brute(s,"000"):
        print(elt)
        for ind,sha_u in enumerate(sha_users):
            if check_correctness_sha(sha_u,elt):
                print("FOUND SHA PASSWORD:",sha_u,"is",elt)
                save_to_file(sha_u,elt)
            if check_correctness_scrypt(script_users[ind],elt):
                print("FOUND Scrypt PASSWORD:",script_users[ind],"is",elt)
                save_to_file(script_users[ind],elt)

    print("finished checking bruteforce")

    check_correctness_sha("WhoCares123", "")

    
    check_correctness_scrypt("HoldTheDoor", "dont_know_the_pass")


if __name__ == "__main__":
    main()
