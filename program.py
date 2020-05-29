import re
import signal
from subprocess import Popen, PIPE
import ipwhois


class ASInfo:
    def __init__(self, ip, ans, country, provider):
        self.ip = ip
        self.ans = ans
        self.country = country
        self.provider = provider


def get_trace(addr):
    trace_list = []
    is_successfully = False
    with Popen(['tracert', '-d', '-w', '1000', addr], stdin=PIPE, stdout=PIPE, encoding='cp866') as f:
        while True:
            line = f.stdout.readline()
            print(line)
            if not line or line.count('*') == 3:
                f.send_signal(signal.SIGTERM)
                break
            if "Трассировка завершена" in line:
                is_successfully = True
                f.send_signal(signal.SIGTERM)
                break
            trace_list.append(line)
    return trace_list, is_successfully


def main():
    ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
    test = ['8.8.8.8', '172.253.70.47']
    trace, flag = get_trace(test[0])
    if flag:
        print("Конечный узел был достигнут")
    else:
        print("Не удалось достичь конечного узла")

    data = []
    for s in trace:
        ip = re.findall(ip_pattern, s)
        if len(ip) != 0:
            data.append(ip[0])
    ip_list = data[1:]

    result = []
    for ip in ip_list:
        try:
            info = ipwhois.IPWhois(ip).lookup_whois()
            net = info['nets'][0]
            provider = net['description'].replace('\n', ' ') if net['description'] is not None else '*'
            tmp = ASInfo(ip, info['asn'], net['country'], provider)
            result.append(tmp)
        except ipwhois.IPDefinedError:
            result.append(ASInfo(ip, '*', '*', '*'))
    write_all(result)


def write_all(data):
    print("{0:20} {1:10} {2:6} {3}".format('IP', 'AS', 'Country', 'Provider'))
    for info in data:
        print("{0:20} {1:10} {2:6} {3:}".format(info.ip, info.ans, info.country, info.provider))


if __name__ == '__main__':
    main()
