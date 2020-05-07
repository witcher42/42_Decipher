from __future__ import print_function
from random import randint
from sys import argv, stdout
import collections
import random
import math

class STREAM():
    def __init__(self, ec):
        self.ec = ec

    def decryption(self, known_pt):	# attackers_dec(known_pt)
	x = 0			# original__dec(ct, private_key)
	r = self.ec.random(x)	# random int smaller than q 
	G = self.ec.random(x)	# start point G. order of the G is q.
	private_key = G.x	# assume (!) change G.x
	public__key = self.ec.smul(G,private_key)
	validation, y = ec.findY(G.x)
	print("Is on EC : ", validation)
	print("Is on EC : ", ec.isOn(G))
	c1 = self.ec.smul(G,r.x)
	c2 = self.ec.addition(known_pt,self.ec.smul(public__key,r.x))
	negM = self.ec.negation(self.ec.smul(c1,private_key))
	Pm = self.ec.addition(c2,negM)
	pt = []
	for i in range(0,(len(known_pt)+29)/30):
		while k<len(known_pt[30*i:30*(i+1)]):	
			rt = rt+Pm.x*(2**8)**(k-1)
			k+=1
			pt.append(chr(rt%(2**8)))
	return ''.join(pt)

if __name__ == "__main__":
    prime = 112817876910624391112586233842848268584935393852332056135638763933471640076719
    A = 49606376303929463253586154769489869489108883753251757521607397128446713725753
    B = 79746959374671415610195463996521688925529471350164217787900499181173830926217
    ec = EC(A,B,prime) # A, B, p : open to public.
    P = Point(103039657693294116462834651854367833897272806854412839639851017006923575559024,
              77619251402197618012332577948300478225863306465872072566919796455982120391100)
    Q = Point(54754931428196528902595765731417656438047316294230479980073352787194748472682,
               31061354882773147087028928252065932953521048346447896605357202055562579555845)
    #print("Is on EC : ", ec.isOn(P))
    #print("Is on EC : ", ec.isOn(Q))
    print("________________________________________________________")
    kpt = open('known_plain_text', 'r').read()
    print("           pt:",kpt)
    print("________________________________________________________")
    print('')
    seed = 0xffffffffffffffff
    stream = STREAM(ec,seed,P,Q); 
    ct = stream.encryption(bytearray(kpt))
    print("  original ct:",ct)
    print(" encrypted ct:",bytes(ct).encode('hex'))
    print("________________________________________________________")
    stream = STREAM(ec,seed,P,Q); 
    pt = stream.encryption(bytearray(ct))
    print("           pt:", pt)
    print("________________________________________________________")
    print('')
    """
    x = int('0x'+rt, 16)
    validation, y = ec.findY(x)
    known_pt = Point(x, y)
    print("input_pt:", known_pt)
    print('')
    pt = stream.decryption(known_pt)
    print('')    
    print("output_pt:", pt)
    print("________________________________________________________")
    print('')
    """
    print('Chosen Plain-text Attack Start')
    kpt = open('known_plain_text', 'r').read()
    ct = open('encrypted_text', 'r').read()
    rt = bytes(ct).encode('hex').decode('hex')
    seed = 0xffffffffffffffff
    loop = (len(rt)+29)/30
    print(len(rt), "characters")
    print('')
    flag = 0
    while (seed<prime and flag==0):
        for i in range(0,loop):
	    stream = STREAM(ec,seed,P,Q);
	    pt = stream.encryption(bytearray(rt)) 
	    if (pt.find(kpt) != 0):
	        print(pt)
		flag = 1
	        break;
	seed+=1
    print("________________________________________________________")
