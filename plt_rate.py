import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import os,sys

np.set_printoptions(threshold=np.inf)
mpl.rcParams['lines.markersize'] = 1

arr = np.zeros((2,10000), dtype =int)
c1=0
c2=0

for line in open('bmv2Log.txt.3.txt'):
	if "MyLog" in line:
		if "Before" in line:
			#print line
			arr[0,c1] = int(line.split()[-1])
			#print arr[0,c1]
			c1=c1+1
		else:
			#print line
			arr[1,c2] = int(line.split()[-1])
			#print arr[1,c2]
			c2=c2+1

x1=[i+1 for i in range(1,10001)]
y1=arr[0,:]
y2=arr[1,:]

plt.plot(x1,y1,linewidth=1,label="Before")
plt.plot(x1,y2,linewidth=1,label="After")
plt.axis([-1,c1-1,-1,25])
plt.xlabel('Packet Number')
plt.ylabel('Output Buffer Size')

plt.legend()
plt.show()

