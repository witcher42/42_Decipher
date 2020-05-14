from __future__ import print_function
from random import randint
from sys import argv, stdout
import collections
import random
import math

def mulInv(n, q):  
    return extEuclid(n, q)[0] % q

def extEuclid(a, b):
    s0, s1, t0, t1 = 1, 0, 0, 1
    while b > 0:
        q, r = divmod(a, b)		# a//b, a%b
        a, b = b, r
        s0, s1, t0, t1 = s1, s0 - q * s1, t1, t0 - q * t1
        pass
    return s0, t0, a 			# a : always 1

def sqrRoot(n, q):
    r = pow(n,(q+1)/4,q) 		# r is a quadratic residue
    return r, q - r

Point = collections.namedtuple("Point", ["x", "y"])

class EC(object):
    def __init__(self, a, b, q):
        assert 0 < a and a < q and 0 < b and b < q and q > 2
        assert (4 * (a ** 3) + 27 * (b ** 2))  % q != 0 
        self.a = a			# no middle root (mod q)
        self.b = b
        self.q = q
        self.zero = Point(0, 0)
        pass

    def isOn(self, p):
        if p == self.zero: return True
        l = (p.y ** 2) % self.q
        r = ((p.x ** 3) + self.a * p.x + self.b) % self.q
        return l == r

    def addition(self, p1, p2):
        if p1 == self.zero: return p2 
        if p2 == self.zero: return p1
        if p1.x == p2.x and (p1.y != p2.y or p1.y == 0):
            return self.zero
        if p1.x == p2.x: 		# when P == Q (Doubling)
            l = (3 * p1.x * p1.x + self.a) * mulInv(2 * p1.y, self.q) % self.q
            pass
        else:				# when P != Q (Addition)
            l = (p2.y - p1.y) * mulInv(p2.x - p1.x, self.q) % self.q
            pass
        x = (l * l - p1.x - p2.x) % self.q
        y = (l * (p1.x - x) - p1.y) % self.q
        return Point(x, y)

    def smul(self, P, n):
        r = self.zero 			# Point(0, 0) : init every smul
        m2 = P
        while 0 < n: 			# O(log(n))
            if n & 1 == 1: 		# last try
                r = self.addition(r, m2)
                pass
            n, m2 = n >> 1, self.addition(m2, m2)
            pass
        return r

    def negation(self, p):
        return Point(p.x, -p.y % self.q)

    def findY(self, x):
        y2 = (x ** 3 + self.a * x + self.b) % self.q
        y, my = sqrRoot(y2, self.q)
        return y2 == y*y%self.q, y 	# validate y*y%self.q

    def random(self, xin):
        while True:
            if xin == 0 :
                x = random.randint(1,self.q) 
            else :
                x = xin
            y2 = (x ** 3 + self.a * x + self.b) % self.q
            if pow(y2,(self.q-1)/2,self.q) != 1 :
                continue
            y, my = sqrRoot(y2, self.q) 
            return Point(x, y)

class STREAM():
    def __init__(self, ec, seed, P, Q):
        self.ec = ec
        self.seed = seed 
        self.P = P	 
        self.Q = Q

    def genStream(self): 		# pseudo random
        t = self.seed			# IV
        s = (self.ec.smul(self.P,t)).x  
        self.seed = s			
        r = (self.ec.smul(self.Q,s)).x 
        return r & (2**(8 * 30) - 1) 	# return 30 bytes (encode 30 character)
	
    def encryption(self, pt):
        loop = (len(pt)+29)/30		# 30 bytes + 30 bytes + 30 bytes + ...
        ct = bytearray('')
        for i in range(0,loop): 
            r = self.genStream()
            blkLen = len(pt[30*i:30*(i+1)])
            for j in range(1,blkLen+1):    
		ct = ct + chr(((r>>((30-j)*8))&0xff)^pt[30*i+j-1]) 
        return ct

    def decryption(self, known_pt):	# attackers_dec(known_pt)
	r = self.ec.random(0)		# original__dec(ct, private_key)	
	G = self.ec.random(r.x)		# start point G : order of the G is q
	private_key = G.x		# assume (!) change G.x
	public__key = self.ec.smul(G,private_key)
	validation, y = ec.findY(G.x)
	if validation == True:
	    c1 = self.ec.smul(G,r.x)
	    c2 = self.ec.addition(known_pt,self.ec.smul(public__key,r.x))
	    negM = self.ec.negation(self.ec.smul(c1,private_key))
	    pt, compression = self.ec.addition(c2,negM)
	    print("output_pt:", Point(pt,compression)) 
	lst = []
	for i in range(0,(len(known_pt)+29)/30):
	    for k in range(30*i,30*(i+1)+1):  
		ct = pt/((2**8)**(30-k))
		lst.append(chr(ct&0xff))
	return ''.join(lst)

    def CPA(self, rt, kpt, q):		# do (!) 30 bytes
    	print(len(rt), "characters\n")
    	while self.seed < q:
	    stream = STREAM(ec,self.seed,P,Q);
	    pt = stream.encryption(bytearray(rt)) 
	    if (pt.find(kpt) != 0): 	# -1
	    	return pt
	    self.seed+=1


if __name__ == "__main__":
    prime = 112817876910624391112586233842848268584935393852332056135638763933471640076719
    A = 49606376303929463253586154769489869489108883753251757521607397128446713725753
    B = 79746959374671415610195463996521688925529471350164217787900499181173830926217
    ec = EC(A,B,prime) 			# A, B, prime : open to public
    P = Point(103039657693294116462834651854367833897272806854412839639851017006923575559024,
              77619251402197618012332577948300478225863306465872072566919796455982120391100)
    Q = Point(54754931428196528902595765731417656438047316294230479980073352787194748472682,
               31061354882773147087028928252065932953521048346447896605357202055562579555845)
    print("________________________________________________________")
    kpt = open('srcs/known_plain_text', 'r').read()
    print("           pt:",kpt)
    seed = 0xffffffffffffffff
    stream = STREAM(ec,seed,P,Q); 
    ct = stream.encryption(bytearray(kpt))
    print("  original ct:",ct)
    print(" encrypted ct:",bytes(ct).encode('hex'))
    stream = STREAM(ec,seed,P,Q); 
    pt = stream.encryption(bytearray(ct))
    print("   decoded pt:", pt)
    print("________________________________________________________")
    print("	Decipher Example\n")
    x = int('0x'+bytes(ct).encode('hex'), 16)
    validation, y = ec.findY(x)
    known_pt = Point(x, y)
    print("input__pt:", known_pt)
    pt = stream.decryption(known_pt)
    print("\n decipher:", pt)   
    print("________________________________________________________")
    print("	Chosen Plain-text Attack Start\n")
    ct = open('srcs/encrypted_text', 'r').read()
    rt = bytes(ct).encode('hex').decode('hex')
    stream = STREAM(ec,seed,P,Q);
    print(stream.CPA(rt,kpt,prime))
