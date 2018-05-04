import os
from operator import itemgetter    
import numpy as np

domain = []
with open("top_50") as f:
	for i in f.readlines():
		domain.append(i[:-1])
domain = domain[:30]

httpSize = {}
top = {}
path = "../solveCDNCnt/"
filenames = os.listdir(path)
filenames.sort()

dailyData = []

cnt = 0
for filename in filenames:
	if filename[-1] != 'p': continue
	cnt += 1
	
	today = {}
	for i in domain:
		today[i] = []
	with open(path + filename, 'r') as f:
		for i in f.readlines():
			t = i.split()
			if len(t) != 4: continue
			if t[0] not in domain: continue
			if int(t[3]) < 30: continue
			today[t[0]].append(t[1:])

#	print(today)
#	print(len(today))
	dailyData.append(today)
#print(dailyData)

ratio = {}
for i in domain:
	ratio[i] = {}

cnt = 0
for oneday in dailyData:
	cnt += 1
	for oneDomain in oneday.keys():
		totalCnt = 0
		for oneType in oneday[oneDomain]:
#			if cnt == 1:
			if oneType[0] not in ratio[oneDomain]:
				ratio[oneDomain][oneType[0]] = []
			totalCnt += int(oneType[2])
		
		for oneType in oneday[oneDomain]:
			ratio[oneDomain][oneType[0]].append(int(oneType[2]) / totalCnt)
		
#		print(oneday[oneDomain])
#		print(totalCnt)

for domainKey, domainValue in ratio.items():
	for typeKey, typeValue in domainValue.items():
		typeNp = np.array(typeValue)
		if np.average(typeNp) > 0.2:
			print(domainKey, typeKey, "%.3f" % np.average(typeNp), "%.3f" % np.var(typeNp), sep=', ')
