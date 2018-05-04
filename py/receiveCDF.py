import os
import numpy as np
from pylab import *

def draw(filename):
	typeRatio = {}
	errorRatio = 0
	
	with open(filename) as f:
		for i in f.readlines():
			cut = i.split()
			if len(cut) != 7: continue
	#		print(cut)
			
			mimetype = cut[-3].split("/")[0]
	#		print(mimetype)
			if mimetype not in typeRatio: typeRatio[mimetype] = []
			if cut[-2] == '0': continue
			ratio = float(cut[-1]) / float(cut[-2])
			if ratio > 1: 
				errorRatio += 1
				continue
			typeRatio[mimetype].append(ratio)

	print("errorRatio: ", errorRatio)
	#print(typeRatio)

	cnt = 0
	num_bins = 10000
	bins = np.arange(num_bins + 1) / num_bins
	for typek, value in typeRatio.items():
	#	if typek != 'application/multipart-formdata': continue
	#	if typek != 'video': continue
		if len(value) < 100: continue
		print(typek, len(value))
		
		cnt += 1

		data = np.array(value)
		print(data)

		counts, bin_edges = np.histogram(data, bins=bins)
		cdf = np.cumsum(counts)

	#	print(counts)
	#	print(bin_edges)
	#	print(cdf)
		
	#	plt.figure(cnt / 5)
		plt.figure(filename)
		plt.plot(bin_edges[1:], cdf/cdf[-1], label=typek)
		plt.legend()

	print(cnt)
#	plt.show()
	plt.savefig(filename)

dir = "../ratioOut/"
picCnt = 0
for i in os.listdir(dir):
	if 'png' in i: continue
	picCnt += 1
#	if picCnt > 3: break
	print(i)
	draw(dir + i)