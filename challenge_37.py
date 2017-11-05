# cryptopals challenge 37
# http://cryptopals.com/sets/5/challenges/37
# Break SRP with a zero key
# 
# For Encryption course at JAMK.FI
# Jaroslav Seidel, Arne Sailer, Lydia Soffkey

from challenge_36 import N, g, k, step1, step2, step3, step4, step5, step6, step7, validate, hashToBytes, hashToInt
import hashlib
from random import randrange

# Get your SRP working in an actual client-server setting. "Log in" with
# a valid password using the protocol.
def run_SRP():
    state = { "N" : N, 
             "g" : g,
             "k" : k,
             "I" : 'test@jamk.fi',
             "P" : 'Finland'}
    state = step1(state)
    state = step2(state)
    state = step3(state)
    state = step4(state)
    state = step5(state)
    state = step6(state)
    state = step7(state)
    assert(validate(state))

# Now log in without your password by having the client send 0 as its
# "A" value. What does this to the "S" value that both sides compute?
def client0():
    state = { "N" : N, 
             "g" : g,
             "k" : k,
             "I" : 'test@jamk.fi',
             "P" : 'Finland'}
    state = step1(state)
    state = step2(state)
    state["A"] = 0
    state = step3(state)
    state = step4(state)
    state["C_K"] = hashToBytes(str(0))
    state = step6(state)
    state = step7(state)
    assert(validate(state))

# Now log in without your password by having the client send N, N*2, &c.
def clientN():
    state = { "N" : N, 
             "g" : g,
             "k" : k,
             "I" : 'test@jamk.fi',
             "P" : 'Finland'}
    state = step1(state)
    state = step2(state)
    _k = randrange(1, 30)
    state["A"] = _k*N
    state = step3(state)
    state = step4(state)
    state["C_K"] = hashToBytes(str(0))
    state = step6(state)
    state = step7(state)
    assert(validate(state))


if __name__ == "__main__":
    run_SRP()
    client0()
    clientN()
    print("Problem 37 success")