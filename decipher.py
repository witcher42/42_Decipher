    def decryption(self, ct):	# dec(ct, private key)
	#ct=ct+self.ec.findY(self.ec.random())
	c1, c2 = ct # c1(rP), c2(pt+rQ) 
	private_key = 0xffffffffffffffff
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