# cryptopals challenge 36
# http://cryptopals.com/sets/5/challenges/36
# Implement Secure Remote Password (SRP)
# 
# For Encryption course at JAMK.FI
# Jaroslav Seidel, Arne Sailer, Lydia Soffkey

import hashlib
import hmac as hmac_module
from random import randrange


# helpful functions
def hashToBytes(s):
    sha256 = hashlib.sha256()
    sha256.update(s.encode('ascii'))
    return sha256.digest()

def hashToInt(s):
    sha256 = hashlib.sha256()
    sha256.update(s.encode('ascii'))
    return int(sha256.hexdigest(), 16)

def hmac(K, salt):
    hmac_fn = hmac_module.new(str(salt).encode('ascii'), digestmod=hashlib.sha256)
    hmac_fn.update(K)
    return hmac_fn.digest()


# Replace A and B with C and S (client & server)

# C & S           
# Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
# N generated as random hex number
N = 0x9ad4498475b41ad3aafc0cac513bc22f7c0a93dd 
g = 2
k = 3
I = 'test@jamk.fi'
P = 'Finland'

# array for saving variables
def init():
    state = { 
        "N" : N, 
        "g" : g,
        "k" : k,
        "I" : I,
        "P" : P
    }
    return state

# S               
# 1. Generate salt as random integer              
# 2. Generate string xH=SHA256(salt|password)               
# 3. Convert xH to integer x somehow (put 0x on hexdigest)              
# 4. Generate v=g**x % N               
# 5. Save everything but x, xH
def step1(state):
    salt = randrange(2, 123456789)
    x = hashToInt(str(salt) + state["P"])
    v = pow(state["g"], x, state["N"])
    state["v"] = v
    state["salt"] = salt
    return state

# C->S            
# Send I, A=g**a % N (a la Diffie Hellman)
def step2(state):
    state["a"] = randrange(0, state["N"])
    state["A"] = pow(state["g"], state["a"], state["N"])
    return state

# S->C            
# Send salt, B=kv + g**b % N
def step3(state):
    state["b"] = randrange(0, state["N"])
    state["B"] = (pow(state["g"], state["b"], state["N"]) + state["k"]*state["v"]) % state["N"]
    return state
    
# S, C           
# Compute string uH = SHA256(A|B), u = integer of uH
def step4(state):
    state["u"] = hashToInt(str(state["A"]) + str(state["B"]))
    return state

# C               
# 1. Generate string xH=SHA256(salt|password)                 
# 2. Convert xH to integer x somehow (put 0x on hexdigest)                 
# 3. Generate S = (B - k * g**x)**(a + u * x) % N                 
# 4. Generate K = SHA256(S)
def step5(state):
    x = hashToInt(str(state["salt"]) + state["P"])
    S = pow((state["B"] - state["k"] * pow(state["g"], x, state["N"])), (state["a"] + state["u"] * x), state["N"])
    state["C_K"] = hashToBytes(str(S))
    return state

# S               
# 1. Generate S = (A * v**u) ** b % N                 
# 2. Generate K = SHA256(S)
def step6(state):
    S = pow(state["A"] * pow(state["v"], state["u"], state["N"]), state["b"], state["N"])
    state["S_K"] = hashToBytes(str(S))
    return state
    
# C->S            
# Send HMAC-SHA256(K, salt)
def step7(state):
    state["challenge"] = hmac(state["C_K"], state["salt"])
    return state

# S->C            
# Send "OK" if HMAC-SHA256(K, salt) validates
def validate(state):
    expected = hmac(state["S_K"], state["salt"])
    return expected == state["challenge"]


def test_srp():
    state = init()
    state = step1(state)
    state = step2(state)
    state = step3(state)
    state = step4(state)
    state = step5(state)
    state = step6(state)
    state = step7(state)
    return validate(state)

if __name__ == "__main__":
    if (test_srp()):
        print("Challenge 36 success")
    else:
        print("Challenge 36 failed")

