class STREAM():
    def __init__(self, ec):
        self.ec = ec

    def decryption(self, pt):	# attackers_dec(known_pt)
        x = 0			# original__dec(ct, private_key)
        r = self.ec.random(x)	# random int smaller than q 
        G = self.ec.random(x)	# starting point G
        private_key = G.x	# assume (!)
        public__key = self.ec.smul(G,private_key)
        validation, y = ec.findY(G.x)
        print("Is on EC : ", validation)
        print("Is on EC : ", ec.isOn(G))
        c1 = self.ec.smul(G,r.x)
        c2 = self.ec.addition(pt,self.ec.smul(public__key,r.x))
        negM = self.ec.negation(self.ec.smul(c1,private_key))
        pt = self.ec.addition(c2,negM)
        return(pt)
	#k=1
	#m=self.ec.findY()
	#lst=[]
	#lst.append(chr(m%(2**8)))
	#while k<len(ct[0:30]):	
	#	m=m+ct[k]*(2**8)**(k-1)
	#	k+=1
	#	lst.append(chr(m%(2**8)))
	#return ''.join(lst)


if __name__ == "__main__":
    prime = 112817876910624391112586233842848268584935393852332056135638763933471640076719
    A = 49606376303929463253586154769489869489108883753251757521607397128446713725753
    B = 79746959374671415610195463996521688925529471350164217787900499181173830926217
    ec = EC(A,B,prime) # A, B, p : open to public.
    stream = STREAM(ec)
    x = int('0x'+'906b60079fd479497fc8965bac7513600ec1ac18d3aa709602f1bd995eeced', 16)
    validation, y = ec.findY(x)
    known_pt = Point(x, y)
    print("input_pt:",known_pt)
    pt = stream.decryption(known_pt)    
    print("output_pt:",pt)



    
    

