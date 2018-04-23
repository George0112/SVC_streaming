import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import os,sys

np.set_printoptions(threshold=np.inf)
mpl.rcParams['lines.markersize'] = 1

arr = np.zeros((2,10000), dtype =int)
c1=0
c2=0

for line in open('buffer.txt'):
	if "MyLog" in line:
		if "Before" in line:
			if "egress port 2" in line:
				#print line
				arr[0,c1] = int(line.split()[-1])
				#print arr[0,c1]
				c1=c1+1
"""		else:
			#print line
			arr[1,c2] = int(line.split()[-1])
			#print arr[1,c2]
			c2=c2+1
"""
x1=[i+1 for i in range(1,10001)]
y1=arr[0,:]
y2=arr[1,:]

plt.xticks(fontsize=20)
plt.yticks(fontsize=20)
plt.plot(x1,y1,linewidth=1)
plt.axis([889, 1879,-1,65])
plt.xlabel('Packet Number', fontsize=30)
plt.ylabel('Buffer Level (packes)', fontsize=30)

plt.legend()
plt.show()

