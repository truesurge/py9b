from struct import pack, unpack


def tea_encrypt_ecb(block, key):
	y, z = unpack("<LL", block)
	k = unpack("<LLLL", key)

	s = 0
	
	for i in xrange(32):
		s = (s + 0x9E3779B9L) & 0xFFFFFFFFL
		y = (y + (((z<<4)+k[0]) ^ (z+s) ^ ((z>>5)+k[1]))) & 0xFFFFFFFFL
		z = (z + (((y<<4)+k[2]) ^ (y+s) ^ ((y>>5)+k[3]))) & 0xFFFFFFFFL
	return pack("<LL", y, z)


def tea_decrypt_ecb(block, key):
	y, z = unpack("<LL", block)
	k = unpack("<LLLL", key)
	
	s = 0xC6EF3720

	for i in xrange(32):
		z = (z - (((y<<4)+k[2]) ^ (y+s) ^ ((y>>5)+k[3]))) & 0xFFFFFFFFL
		y = (y - (((z<<4)+k[0]) ^ (z+s) ^ ((z>>5)+k[1]))) & 0xFFFFFFFFL
		s = (s - 0x9E3779B9L) & 0xFFFFFFFFL
	return pack("<LL", y, z)


def xor(s1, s2):
	res = ""
	for i in xrange(8):
		res += chr(ord(s1[i]) ^ ord(s2[i]))
	return res
				

def checksum(data):
	s = 0
	for i in xrange(0, len(data), 4):
		s += unpack("<L", data[i:i+4])[0]
	return (((s>>16) & 0xFFFF) | ((s & 0xFFFF)<<16)) ^ 0xFFFFFFFF


def pad(data):
	sz = len(data)
	if (sz % 8)==0:
		s = checksum(data[0:-4])
		if s==unpack("<L", data[-4:])[0]: #new format with checksum, do nothing
			print "V1.4.1+ valid checkum detected"
			return data
	print "Appending checksum..."
	if sz % 4:
		data += "\x00"*(4-(sz % 4))
	if (len(data) % 8)==0:
		data += "\x00\x00\x00\x00"
	return data+pack("<L", checksum(data))


class XiaoTea:
	def __init__(self, key):
		self.key = key
		self.iv = "\x00"*8
		self.offset = 0


	def _UpdateKey(self):
		k = ""
		for i in xrange(16):
			k += chr((ord(self.key[i])+i) & 0xFF)
		self.key = k


	def encrypt(self, data):
		data = pad(data)
		res = ""
		for i in xrange(0, len(data) & 0xFFFFFFF8, 8):
			ct = tea_encrypt_ecb(xor(self.iv, data[i:i+8]), self.key)
			res += ct
			self.iv = ct
			self.offset += 8
			if (self.offset % 1024)==0:
				self._UpdateKey()
		return res


	def decrypt(self, data):
		res = ""
		for i in xrange(0, len(data), 8):
			ct = data[i:i+8]
			res += xor(self.iv, tea_decrypt_ecb(ct, self.key))
			self.iv = ct
			self.offset += 8
			if (self.offset % 1024)==0:
				self._UpdateKey()
		return res


__all__ = ["XiaoTea"]
