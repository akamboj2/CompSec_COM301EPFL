#!/usr/bin/python3
"""
Checks validity of passwords for Com-301 homework 6.
Read the main function for instruction.
"""
import json
import base64
import random
import string
# import time
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
    global ans_hash
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

def rand_brute(s,l,scrypt_users):
    """ just brute force using random strings on passwords
        s = string of possible characters
        l = length of passwords to try
        sha_users = users
    """
    for i in range(len(s)**l):
        elt = ''.join(random.choice(s) for i in range(l))
        print(elt)
        # for sha_u in sha_users:
            # if check_correctness_sha(sha_u,elt):
            #     print("FOUND SHA PASSWORD:",sha_u,"is",elt)
            #     save_to_file(sha_u,elt)
        for scrypt_u in scrypt_users:
            for at in [elt[:-1],elt[:-2],elt[:-3],elt[:-4]]: #might as well check length 7 6 5 4 as well
                if check_correctness_scrypt(scrypt_u,at):
                    print("FOUND Scrypt PASSWORD:",scrypt_u,"is",at)
                    save_to_file(scrypt_u,at)

def counter_brute(s,starting):
    """ generator returning your string as a counter
        s is string you are searching
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

def make_perm(l1,l2):
    """takes in a list of strings and makes permutation of them"""
    flatten = lambda l: [item for sublist in l for item in sublist]  # creds to  https://stackoverflow.com/questions/952914/how-to-make-a-flat-list-out-of-list-of-lists
    return flatten(list(map(lambda y: list(map(lambda x: y+x, l1)),l2)))

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
    
    for elt in counter_brute(simplified,"9PMM"):
        print(elt)
        for ind,sha_u in enumerate(sha_users):
            if check_correctness_sha(sha_u,elt):
                print("FOUND SHA PASSWORD:",sha_u,"is",elt)
                save_to_file(sha_u,elt)
            # if check_correctness_scrypt(script_users[ind],elt):
            #     print("FOUND Scrypt PASSWORD:",script_users[ind],"is",elt)
            #     save_to_file(script_users[ind],elt)
    """s = valid_chars #size is 94 chars

    #rand_brute(s,8,script_users)

    slist= list(s)
    # we should do the above 4 times. bc s = 94 characters and 94^5 overflows an 32 bit int but 94^4 is fine
    #jk 4 times breaks it (memory error) lets do it thrice.
    slist2=make_perm(slist,slist)
    slist3=make_perm(slist2,slist)
    #print(len(slist3)) #this is 857375 = 94^3 which is good!
    slistALL=[""]+slist+slist2 +slist3 #this should be 94^3+94^2+94 + 1 =839515
    #print(len(slistALL)) #and that's what it is yay!

    #NOTE! you have to change s_at if you're changing last digit in curr
    curr = "0000"  #farthest is 0t/0 without checking 5-7 digit space
    s_at=0 #sha is at 005O


    digit_print=0 #just a count to print every so often
    
    while len(curr)<5: #assuming curr starts at length 4. it's going to check up to through digit lenth 7. so if we get up to digit 5 we should jump to 8 digits: '0000'
        # if digit_print==25:
        #     digit_print=0
        print("incr, a 4th digit:",curr,s_at)

        for ind,elt in enumerate(map(lambda x: curr+x, slistALL)):
            #print(elt)
            for ind,sha_u in enumerate(sha_users):
                if check_correctness_sha(sha_u,elt):
                    print("FOUND SHA PASSWORD:",sha_u,"is",elt)
                    save_to_file(sha_u,elt)
                # if check_correctness_scrypt(script_users[ind],elt):
                #     print("FOUND Scrypt PASSWORD:",script_users[ind],"is",elt)
                #     save_to_file(script_users[ind],elt)
        
        
        if s_at==len(s)-1: #we're at last digit
            #digit_print+=1
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
            curr = curr[:-1] + s[s_at]"""
    

    print("finished checking bruteforce")


if __name__ == "__main__":
    # s1 = time.time()
    # check_correctness_sha('bob','123')
    # s1end=time.time()
    # s2=time.time()
    # check_correctness_scrypt('MsSmith','123')
    # s2end=time.time()
    # print(s1end-s1,s2end-s2)
    # so check_scrypt is muccchhh slower
   main()
