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
    is_finish = False
    is_successfully = False
    with Popen(['tracert', '-d', '-w', '1000', addr], stdin=PIPE, stdout=PIPE) as f:
        while True:
            line = str(f.stdout.readline(), 'cp866')
            if not line or line.count('*') == 3:
                f.send_signal(signal.SIGTERM)
                break
            if "Трассировка завершена" in line:
                is_successfully = True
                f.send_signal(signal.SIGTERM)
                break
            trace_list.append(line)
            print(line)
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
            a = ASInfo(ip, info['asn'], net['country'], net['description'])
            result.append(a)
            print(info)
        except ipwhois.IPDefinedError:
            result.append(ASInfo(ip, '', '', ''))

    print(trace)
    print(ip_list)
    print(result)


if __name__ == '__main__':
    main()
