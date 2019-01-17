from sys import argv, exit
from os.path import getsize
from xiaotea import XiaoTea

updkey = "\xFE\x80\x1C\xB2\xD1\xEF\x41\xA6\xA4\x17\x31\xF5\xA0\x68\x24\xF0"

if len(argv)!=3:
	exit("Usage: "+argv[0]+" <infile> <outfile>")

cry = XiaoTea(updkey)

hfi = open(argv[1], "rb")
hfo = open(argv[2], "wb")

hfo.write(cry.encrypt(hfi.read()))

hfo.close()
hfi.close()
