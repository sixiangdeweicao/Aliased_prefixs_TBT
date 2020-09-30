
f=open("/home/sgl/icmp_tbg/TBT/memo/abnormal-prefixes/abnormal-prefixes.txt","r")
prefixs=set()
for line in f:
    if line !="":
        lines=line.split(" ")
        prefix=lines[1]
        prefixs.add(prefix)
print(len(prefixs))
