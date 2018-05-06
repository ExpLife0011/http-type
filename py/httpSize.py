import os
from operator import itemgetter    

httpSize = {}
top = {}

path = "../solveCDN/"
filenames = os.listdir(path)
filenames.sort()
for cnt, filename in enumerate(filenames):
	if filename[-1] != 'p': continue
	with open(path + filename, 'r') as f:
		for i in f.readlines():
			t = i.split()
			if len(t) != 3: continue
						
			if t[0] not in httpSize: httpSize[t[0]] = 0
			httpSize[t[0]] += int(t[2])

a = sorted(httpSize.items(), key=itemgetter(1), reverse=True)

for i, j in a:
	print(i, j)
	if i not in top: top[i] = 0
	top[i] += j
#print(a)
exit()
#	print(filename, len(httpSize))

b = sorted(top.items(), key=itemgetter(1), reverse=True)
for i, j in b[:50]:
	print(i, j)
exit()

for i in top:
	print(i, top[i])
exit()


def simple():
	a = list(httpSize)
	a.sort()
	for i in a:
		print(i[::-1])
#print(httpSize)


# only use last 2 part of the name
def classify():
	classSet = set()
	for i in httpSize:
		tmp = i.split('.')
		classSet.add(tmp[0] + '.' + tmp[1])
	for i in classSet:
		print(i[::-1])
	print(len(classSet))
classify()
	