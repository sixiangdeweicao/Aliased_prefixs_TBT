import multiprocessing
import random
import re
import string
import tqdm
import time
import fcntl
import ipaddress

from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6PacketTooBig
from scapy.sendrecv import send, sniff, sr, sr1


def random_generate_ip(ip_prefix):
    """Generate IPv6 addresses with ip prefixes given.

    Arguments:
        ip_prefix {str} -- IP prefix

    Returns:
        list -- List of IP addresses generated.
    """
    network = ipaddress.ip_network(ip_prefix)
    exploded = network.exploded
    ip = []
    array = exploded.split(':')
    n = int(array[-1].split('/')[-1])
    array[-1] = array[-1].split('/')[0]
    idx = n // 16
    left = n % 16
    for i in '02468ace':
        if array[idx] != '0000':
            s = '0' * (4 - len(array[idx])) + array[idx]
            res = ''
            for bit in s:
                tmp = str(bin(int(bit, 16)))[2:]
                tmp = '0' * (4 - len(tmp)) + tmp
                res += tmp
            res = res[:left]
            tmp = str(bin(int(i, 16))[2:])
            tmp = '0' * (4 - len(tmp)) + tmp
            res = res + tmp
            res += ''.join(random.choices('01', k=16 - len(res)))
            array[idx] = str(hex(int(res, 2)))[2:]
        else:
            array[idx] = i + ''.join(random.choices('0123456789abcdef', k=3))
        for j in range(idx + 1, 8):
            array[j] = ''.join(random.choices('0123456789abcdef', k=4))
        ip.append(ipaddress.IPv6Address(':'.join(array)).compressed)
    return ip


def send_echo_multiprocess(addr, data, index, str_f, seq=0):
    """Send echo request and sniff the reply.

    Arguments:
        addr {str} -- target address
        data {str} -- payload
        index {int} -- number of currently handling IP prefix
        str_f {list(str)} -- a list to store log strings

    Keyword Arguments:
        seq {int} -- sequence number in the ping request (default: {0})

    Returns:
        list -- list of packets received
    """
    # try:
    #     str_f.append('--> Sending Echo Request to IP #%d, Seq = %d' % (index, seq))
    #     base = IPv6(dst=addr, plen=len(data) + 8)
    #     extension = ICMPv6EchoRequest(data=data, seq=seq)
    #     packet = base / extension
    #     send(packet, verbose=False)
    #     rcv = sniff(timeout=0.5, filter='src %s' % addr)
    #     # rcv = sr1(packet, verbose=False, timeout=0.5)
    #     ans, unans = sr(packet, verbose=True, timeout=1)
    #     res = []
    #     print(addr)
    #     print(rcv)
    #     print(ans, '*', unans)
    #     for i in ans:
    #         res.append(i.show(dump=True))
    #     #     res.append(i[1])
    #     # res.append(rcv)
    #     print(res)
    #     # print(rcv)
    # except:
    #     import traceback
    #     traceback.print_exc()

    str_f.append('--> Sending Echo Request to IP '+ addr+' #%d, Seq = %d' % (index, seq))
    base = IPv6(dst=addr, plen=len(data) + 8)
    extension = ICMPv6EchoRequest(data=data, seq=seq)
    packet = base / extension

    send(packet, verbose=False)
    rcv = sniff(timeout=0.5, filter='src %s' % addr)
    res = []
    for i in rcv:
        res.append(i.show(dump=True))
    return res


def send_too_big_multiprocess(addr, data, index, str_f, mtu=1280):
    """Send too big packet ICMPv6 packet.

    Arguments:
        addr {str} -- target address
        data {str} -- payload
        index {int} -- number of current handling IP prefix
        str_f {list(str)} -- a list of strings that store the log

    Keyword Arguments:
        mtu {int} -- mtu value in the packet too big ICMPv6 Packet (default: {1280})
    """
    str_f.append('==> Sending TBT to IP #%d, MTU = %d' % (index, mtu))
    src = IPv6(dst=addr).src
    base = IPv6(src=addr, dst=src, plen=len(data) + 8)

    too_big_extension = ICMPv6PacketTooBig(mtu=mtu) / \
        (base / ICMPv6EchoRequest(data=data[:mtu - 96], seq=0))

    base = IPv6(dst=addr)

    too_big_packet = base / too_big_extension

    send(too_big_packet, verbose=False)


def get_fragmented_mtu(packets):
    """Infer the path mtu by the packets received from the target IP

    Arguments:
        packets {list(packets)} -- list of packets

    Returns:
        int -- value of mtu, return None if not fragmented.
    """
    if not packets:
        return None

    flag = (len(packets) > 1) and ('Fragment' in packets[1])
    if 'Fragment' not in packets[0]:
        if flag:
            return int(re.search(r'plen(.*?)\n', packets[1]).group().strip().split()[-1]) + 40
        else:
            return None

    if flag:
        return max(int(re.search(r'plen(.*?)\n', packets[0]).group().strip().split()[-1]) + 40,
                   int(re.search(r'plen(.*?)\n', packets[1]).group().strip().split()[-1]) + 40)
    else:
        return int(re.search(r'plen(.*?)\n', packets[0]).group().strip().split()[-1]) + 40


def get_fragmented_id(packets):
    """Get fragementation ID of the packets given.

    Arguments:
        packets {list(packet)} -- list of packets

    Returns:
        str -- fragmentation id
    """
    for packet in packets:
        if 'Fragment' in packet:
            return int(re.search(r'id(.*?)\n', packet).group().strip().split()[-1])
    return -1


def random_generate_data(total_length):
    """Randomly generate data in length given.

    Arguments:
        total_length {int} -- length of the whole IPv6 Packet

    Returns:
        str -- data generated.
    """
    payload_length = total_length - 40
    data_length = payload_length - 8
    return ''.join(random.choices(string.ascii_letters + string.digits, k=data_length))


def is_ascending(id):
    """Judge if the id is ascending.

    Arguments:
        id {list(int)} -- list of ids

    Returns:
        bool -- if the id is ascending.
    """
    _id = []
    for i in id:
        if i != -1 and i != -2:
            _id.append(i)
    is_ascending = True
    if len(_id) > 1:
        for i in range(len(_id) - 1):
            if _id[i] > _id[i + 1]:
                is_ascending = False
                break
        if is_ascending:
            return True
    return False


def solve_multiprocess(ip_prefix, count):
    """Work on ip prefix given.

    Arguments:
        ip_prefix {str} -- ip prefix
        count {int} -- number of currently handling IP prefix

    Returns:
        (list, list, list, list) -- three lists of strings storing different kind of log.
    """
  
    str_f = ['', '#' + str(count) + ' Working on Prefix ' + ip_prefix]
    str_g = []
    str_h = []
    str_r = []
    str_part=[]
    '''
    str_f : Store the detailed log.
    str_g : Store the ipid.
    str_r : Store the result.
    str_h : Store the abnormal situation. includ This method is not available and the ip is no response
    str_part: Store the result of Fragmentation occurs in some addresses (not all addresses)
    '''

    # generate IP list in Prefix: the default number of IP is 8
    data = random_generate_data(1300)
    ips = random_generate_ip(ip_prefix)
    n = len(ips)

    # First, send a data packet with a length of 1300B to detect whether fragmentation occurs.
    # If fragmentation does not occur, send ICMP TOO BIG package (mut is 1280B) to an address in the prefix, then Detect whether fragmentation occurs in other addresses when send ping package with 1300B
    # If fragmentation occur, make the MTU value(MTU=1280B). This method is not available

    # flag=False, the prefix is not alias;flag=true, the prefix is alias
    # flag_e=true, This method is not available.
    # flag_n=true, the ip is no response.
    flag = False
    flag_e = False
    flag_n = False
    flag_p=False

    for i in range(n):
        rcv = send_echo_multiprocess(ips[i], data, i, str_f)

        max_try = 3
        while not rcv and max_try > 0:
            str_f.append('IP #%d: %s is not available' % (i, ips[i]))
            send_echo_multiprocess(ips[i], data, i, str_f)
            max_try =max_try - 1

        if not rcv:
            str_f.append('IP #%d: %s is no response' % (i, ips[i]))
            flag_n = True
            str_f.append(
                'Cannot receive echo reply from IP #%d, '
                'so we cannot decide whether it is an alised prefix'%(i))
            str_h.append("#"+str(count)+" "+ip_prefix + " no_response")
            return (str_f, str_g, str_h, str_r)
        else:
            _mtu = get_fragmented_mtu(rcv)
            if _mtu:
                str_f.append(
                    '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, get_fragmented_id(rcv)))
                if _mtu == 1280:
                    flag_e = True
                    str_h.append("#"+str(count)+" "+ip_prefix + " unavailable")
                return (str_f, str_g, str_h, str_r)
            else:
                str_f.append(
                    '<-- Receive Echo Reply from IP #%d, Not Fragmented' % 0)


    send_too_big_multiprocess(ips[0], data, 0, str_f, mtu=1280)

    id = [-1] * n  # Store the fragmentation ID of each ping reply.
    id2= [-1] * n  # Store the fragmentation ID of each ping reply including send TBT to the address that does not fragment
    for i in range(n):
        rcv = send_echo_multiprocess(ips[i], data, i, str_f, seq=0)
        max_retries = 3
        while not rcv and max_retries >= 0:
            max_retries =max_retries-1
            str_f.append(
                '<!> IP: %s no response, retrying... <!>' % ips[i])
            rcv = send_echo_multiprocess(ips[i], data, i, str_f, seq=0)

        if not rcv:
            str_f.append(
                '<!> Cannot Receive Echo Reply from IP #%d' % i)
            id[i] = -2  # No reply received.
        else:
            _mtu = get_fragmented_mtu(rcv)
            if _mtu:
                tmp = get_fragmented_id(rcv)
                id[i] = tmp
                id2[i]= tmp
                str_f.append(
                    '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, tmp))
            else:
                str_f.append(
                    '<-- Receive Echo Reply from IP #%d, Niot Fragmented' % i)

                send_too_big_multiprocess(ips[i], data, i, str_f, mtu=1280)
                rcv = send_echo_multiprocess(ips[i], data, i, str_f, seq=0)
                max_retries = 3
                while not rcv and max_retries >= 0:
                    max_retries =max_retries - 1
                    str_f.append(
                        '<!> IP: %s no response, retrying... <!>' % ips[i])
                    rcv = send_echo_multiprocess(ips[i], data, i, str_f, seq=0)
                if rcv:
                    _mtu = get_fragmented_mtu(rcv)
                    if _mtu:
                        flag_p=True
                        str_f.append(
                        '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, tmp))
                        tmp = get_fragmented_id(rcv)
                        id2[i]= tmp
                        str_f.append(
                        '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, tmp))


    # Statistics fragmentation in ip list
    number_fragented=0
    for i in id:
        if i >= 2:
            number_fragented=number_fragented+1


    if number_fragented >= 1:
        flag = True
        str_r.append('# '+str(count)+' '+ip_prefix + ' alised_possibility:'+str(number_fragented) )

    tmp = ' '.join([str(i) for i in id]) + ' '
    str_f.append('id['+tmp+']')

    tmp1 = ' '.join([str(i) for i in id2]) + ' '
    str_f.append('id2['+tmp1+']')

    if number_fragented >= 1:
        str_g.append('# '+str(count)+ip_prefix)
        str_g.append('id['+tmp+']')
        str_g.append('id['+tmp1+']')


  

    return (str_f, str_g, str_h, str_r)



# def alisedbig(ip_prefix):
#     str_ff=['', '#' + ' Working on Prefix ' + ip_prefix]
#     ips=random_generate_ip(ip_prefix)
#     n=len(ips)
#     data=random_generate_data(1316)
#     mtus=set()
#     for i in range(n):
#         rcv=send_echo_multiprocess(ips[i],data,i,str_ff)
#         max_try = 3
#         while not rcv and max_try > 0:
#             str_ff.append('IP #%d: %s is not available' % (i, ips[i]))
#             send_echo_multiprocess(ips[i], data, i, str_ff)
#             max_try =max_try - 1
#         if not rcv:
#             str_ff.append('IP #%d: %s is not responce' % (i, ips[i]))
#             return str_ff
#         else:
#             _mtu=get_fragmented_mtu(rcv)
#             if _mtu:
#                 str_ff.append(
#                     '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, get_fragmented_id(rcv)))
#                 mtus.add(_mtu)
#             else:
#                 return str_ff

#     current_mtu = 1308
#     send_too_big_multiprocess(ips[0], data, i, str_ff, mtu=current_mtu)

#     for i in range(n):
#         rcv=send_echo_multiprocess(ips[i],data,i,str_ff)
#         max_try = 3
#         while not rcv and max_try > 0:
#             str_ff.append('IP #%d: %s is not available' % (i, ips[i]))
#             send_echo_multiprocess(ips[i], data, i, str_ff)
#             max_try =max_try - 1
#             if not rcv:
#                 str_ff.append('IP #%d: %s is not responce' % (i, ips[i]))
#                 return str_ff
#             else:
#                 _mtu=get_fragmented_mtu(rcv)
#             if _mtu:
#                 str_ff.append(
#                     '<-- Receive Echo Reply from IP #%d, MTU = %d, id = %d' % (i, _mtu, get_fragmented_id(rcv)))
#                 mtus.add(_mtu)
#                 return str_ff
#             else:
#                  str_ff.append('<-- Receive Echo Reply from IP #%d, Not Fragmented' % i)

    
#     return str_ff


# def runing():
#     f=open("text.txt","r")
#     for line in f:
#         if line:
#             ip_prefix=line.strip()
#             str_ff=alisedbig(ip_prefix)
#             for s in str_ff:
#                 print(s)
#             print("")



def write_file(array):
    """Write log to the files.

    Arguments:
        array {(list, list, list, list)} -- three lists of strings storing different kinds of log.
    """
    #print('Writing Files...')
    global f, g, h, r
    str_f, str_g, str_h, str_r = array
    fcntl.flock(f, fcntl.LOCK_EX)
    for i in str_f:
        print(i, file=f)
    fcntl.flock(f, fcntl.LOCK_UN)

    fcntl.flock(g, fcntl.LOCK_EX)
    for i in str_g:
        print(i, file=g)
    fcntl.flock(g, fcntl.LOCK_UN)

    fcntl.flock(h, fcntl.LOCK_EX)
    for i in str_h:
        print(i, file=h)
    fcntl.flock(h, fcntl.LOCK_UN)
    for i in str_r:
        print(i, file=r)
    fcntl.flock(r, fcntl.LOCK_UN)


file_no = 1
f_name = './memo/sgl-log/sgl-log_%d.txt'
g_name = './memo/ipid/ipid_%d.txt'
h_name = './memo/abnormal-prefixes/abnormal-prefixes.txt'
r_name = './memo/aliased-prefixes/aliased-prefixes.txt'


f = open(f_name % file_no, 'a+', encoding='utf-8')
g = open(g_name % file_no, 'a+', encoding='utf-8')
h = open(h_name, 'a+', encoding='utf-8')
r = open(r_name, 'a+', encoding='utf-8')


def run(process_number=64,batch_size=1000):
    global file_no, f, g
    total = 734685
    count = 0
    bar = tqdm.tqdm(total=total)
    sum = 0
    with open('prefixes.txt', 'r', encoding='utf-8') as input_stream:
        while True:
            if sum >= batch_size:
                sum = sum % batch_size
                file_no += 1
                f.close()
                g.close()
                f = open(f_name % file_no, 'a+', encoding='utf-8')
                g = open(g_name % file_no, 'a+', encoding='utf-8')
            p = multiprocessing.Pool(process_number)
            lines = []
            for _ in range(process_number):
                line = input_stream.readline()
                if line:
                    lines.append(line)
                else:
                    break
            if len(lines) == 0:
                break
            for line in lines:
                count += 1
                sum += 1
                ip_prefix = line.strip()
                p.apply_async(solve_multiprocess, args=(
                    ip_prefix, count,), callback=write_file)
            p.close()
            p.join()
            bar.update(len(lines))


if __name__ == '__main__':
    run(process_number=64, batch_size=10000)
    # data = random_generate_data(1300)
    # strf=[]
    # rcv=send_echo_multiprocess('2600:9000:205b::1',data,0,strf)
    # print(rcv)
    f.close()
    g.close()
    h.close()
    r.close()


#runing()