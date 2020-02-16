import csv

l = [0,0,0,0,0,0,0,0,0]
n = [0,0,0,0,0,0]

def checkRow(name):
    if name == "Threat":
        return 0
    elif name == "Vulnerability":
        return 1
    elif name == "Risk":
        return 2

with open("compilation.csv", "r") as comp:
    data = csv.reader(comp)
    for row in data:
        if row[0] == "Symantec":
            l[checkRow(str(row[2]))] += 1
        elif row[0] == "Kaspersky":
            l[checkRow(str(row[2]))+3] += 1
        elif row[0] == "TrendMicro":
            l[checkRow(str(row[2]))+6] += 1

print(str(l))

n = [(l[0]+l[2]/2),(l[1]+l[2]/2),(l[3]+l[5]/2),(l[4]+l[5]/2),(l[6]+l[8]/2),(l[7]+l[8]/2)]
print(str(n))

with open("analysis.csv", "w") as d:
    d.write("Type,TC,VC\nSymantec,{0},{1}\nKaspersky,{2},{3}\nTrendMicro,{4},{5}".format(n[0],n[1],n[2],n[3],n[4],n[5]))

input("Done.")
