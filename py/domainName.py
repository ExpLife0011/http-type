import os

domainName = set()

path = "../solveCDN/"
for filename in os.listdir(path):
	if filename[-1] != 'p': continue
	with open(path + filename, 'r') as f:
		for i in f.readlines():
			t = i.split()
			if len(t) != 3: continue
			domainName.add(t[0][::-1])
#	print(domainName)
	print(filename, len(domainName))
exit()


def simple():
	a = list(domainName)
	a.sort()
	for i in a:
		print(i[::-1])
#print(domainName)


# only use last 2 part of the name
def classify():
	classSet = set()
	for i in domainName:
		tmp = i.split('.')
		classSet.add(tmp[0] + '.' + tmp[1])
	for i in classSet:
		print(i[::-1])
	print(len(classSet))
classify()
	