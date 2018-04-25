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
			
#			part = t[0].split('.')
#			print(part)
#			if len(part) < 2: continue
#			lastTwo = part[-3] + '.' + part[-2] + '.' + part[-1]
#			lastTwo = part[-2] + '.' + part[-1]
#			print(lastTwo)
#			if cnt > 12 and lastTwo[::-1] not in httpSize: print(lastTwo)
			
			if t[0] not in httpSize: httpSize[t[0]] = 0
			httpSize[t[0]] += int(t[2])
#	afterRank = [() for i ]
#	sorted(httpSize.items(), cmp=lambda x, y: cmp(x[1], y[1]))
	a = sorted(httpSize.items(), key=itemgetter(1), reverse=True)

	for i, j in a[:10]:
		if i not in top: top[i] = 0
		top[i] += j
#	print(a[:10])
#	exit()
	print(filename, len(httpSize))
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
	