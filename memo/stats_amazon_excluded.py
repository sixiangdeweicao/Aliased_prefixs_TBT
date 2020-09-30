import os
import numpy as np
import matplotlib.pyplot as plt
from prettytable import PrettyTable

directory = './memo/result'
lst = os.listdir(directory)
count = 0
count_star = 0
count_x = 0
count_s = 0
count_star_s = 0
count_star_ns = 0
count_mo = 0
count_q = 0
count_x_q = 0
count_no = 0
count_s_q = 0
count_u = 0

for i in lst:
    file_name = os.path.join(directory, i)
    with open(file_name, 'r', encoding='utf-8') as f:
        line = f.readline()
        line2 = f.readline()
        while line2:
#            if line.split()[-1].startswith('2600:9000:'):
#                line = f.readline()
#                line2 = f.readline()
#                continue
            count += 1
            if '?' in line2 and '*' in line2:
                line = f.readline()
                line2 = f.readline()
                count_x_q += 1
                count_x += 1
                count_q += 1
                continue
            if '?' in line2:
                line = f.readline()
                line2 = f.readline()
                count_q += 1
                if '$' in line2:
                    count_s_q += 1
                continue
            elif '×' in line2:
                line = f.readline()
                line2 = f.readline()
                count_x += 1
                continue
            if '*' in line2:
                count_star += 1
            if '$' in line2:
                count_s += 1
            if '^' in line2:
                count_u += 1
            if '*' in line2 and '$' in line2:
                count_star_s += 1
            if '*' in line2 and '$' not in line2:
                count_star_ns += 1
            ok = False
            s = set(line2.split()[:-1])
            if len(s) == 1:
                if '-1' in s:
                    count_mo += 1
            if len(s) == 2:
                ok = not ('-1' in s or '-2' in s)
            elif len(s) == 3:
                ok = not ('-1' in s and '-2' in s)
            elif len(s) > 3:
                ok = True
            if ok:
                if '*' not in line2 and '$' not in line2 and '^' not in line2:
                    count_no += 1
            line = f.readline()
            line2 = f.readline()


def get_percent(x):
    global count
    return '%.2f%%' % (x / count * 100)

# plt.subplot(311)
# plt.pie(x=[count_x, count - count_x], labels=['Reachable', 'Unreachable'], autopct='%.2f%%')
# plt.show()


table = PrettyTable(['类型', '数量', '比例'])
table.add_row(('总计', count, '100%'))
table.add_row(('无法Ping通', count_x, get_percent(count_x)))
table.add_row(('无法进一步诱导 [MTU = 1280]', count_q, get_percent(count_q)))
table.add_row(('虽然无法进一步诱导，但分片ID值递增', count_s_q, get_percent(count_s_q)))
table.add_row(('诱导分片全部失败', count_mo, get_percent(count_mo)))
table.add_row(('可通过观察前两个IP的诱导情况判定其是别名前缀', count_star, get_percent(count_star)))
table.add_row(('因为第二个IP收包出现异常，所以无法用此法判定其是否是别名前缀', count_u, get_percent(count_u)))
table.add_row(('诱导成功，而且分片ID值递增', count_s, get_percent(count_s)))
table.add_row(('诱导成功，第二个IP收包正常，但不仅ID值不递增，也无法通过比较前两个IP的诱导情况判定其是否是别名前缀', count_no, get_percent(count_no)))
print(table)
os.system("pause")
