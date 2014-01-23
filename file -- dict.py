#This scripts reads the /proc/meminfo file and puts it into a dictionary

mem_info_file = '/proc/meminfo'

f = open(mem_info_file, 'r')
answer = {}
value_dict= {}
for line in f:
    k, v = line.strip().split(':')

    a = v.strip().split()
    value_dict[k.strip()]  = a[0]
f.close()

print value_dict
