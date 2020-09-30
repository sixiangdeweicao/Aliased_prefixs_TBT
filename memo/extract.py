import os

dir = './memo/result'

with open('./memo/dubious_non_aliased_prefixes.txt', 'w', encoding='utf-8') as output:
    for i in os.listdir(dir):
        file = os.path.join(dir, i)
        with open(file, 'r', encoding='utf-8') as f:
            line = f.readline()
            line2 = f.readline()
            while line2:
                l = line2.strip().split()[:-1]
                s = set(l)
                ok = False
                if len(s) == 2:
                    ok = not ('-1' in s or '-2' in s)
                elif len(s) == 3:
                    ok = not ('-1' in s and '-2' in s)
                elif len(s) > 3:
                    ok = True
                if ok:
                    if '?' not in line2 and '×' not in line2 and '*' not in line2 and '$' not in line2 and '^' not in line2:
                        print(line, file=output, end='')
                        # print(line2)
                line = f.readline()
                line2 = f.readline()
