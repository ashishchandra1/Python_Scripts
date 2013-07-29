matchfile = 'matchfile.txt'
inputfile = 'inputfile.txt'
count = 0


with open(inputfile, 'r') as f:
    names = set([line.strip() for line in f])

with open(matchfile, 'r') as f:
    for line in f:
      name=line.strip()

      if name in names:
          count = count + 1

    print count
