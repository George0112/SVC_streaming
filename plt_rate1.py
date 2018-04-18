import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
import os,sys

np.set_printoptions(threshold=np.inf)
mpl.rcParams['lines.markersize'] = 1

arr1 = np.zeros((2,100000), dtype = int)
arr2 = np.zeros((2,100000), dtype = int)
p1=0;
p2=0;
r1=0;
r2=0;
tmp=0;

for line in open('output.txt'):
    if "MyLog" in line:
        if "port" in line:
            #print line
            tmp = int(line.split()[-1])-1
            #print tmp
        elif "time" in line:
            if tmp == 0:
                arr1[0][p1]=int(line.split()[-1])
                p1=p1+1
            else:
                arr2[0][p2]=int(line.split()[-1])
                p2=p2+1
        elif "rate" in line:
            #print line
            if tmp == 0:
                arr1[1][r1]=int(line.split()[-1])
                r1=r1+1
            else:
                arr2[1][r2]=int(line.split()[-1])
                r2=r2+1

x1=arr1[0,:]
x2=arr2[0,:]
y1=arr1[1,:]
y2=arr2[1,:]

plt.plot(x1,y1,linewidth=1,label="port1")
plt.plot(x2,y2,linewidth=1,label="port2")
#plt.axis([-1,c1-1,-1,25])
plt.xlabel('Time')
plt.ylabel('Rate')

plt.legend()
plt.show()

