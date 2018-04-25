typelen = {}
with open("out", 'r') as f:
	for i in f.readlines():
		t = i.split()
		if len(t) != 3: continue
		httptype = t[1].split('/')[0]
		httptype = t[1]
		if typelen.get(httptype) == None: typelen[httptype] = 0
		print(t[2], end=' ')
		print(len(t), t)
		typelen[httptype] += int(t[2])

for i in typelen.keys():
	print(i, typelen[i])