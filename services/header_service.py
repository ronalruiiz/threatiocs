import re
import dateutil.parser
from email.parser import HeaderParser
import time
from helpers.contex_processors import duration


class HeaderService:

    def date_parser(this,line):
        try:
            r = dateutil.parser.parse(line, fuzzy=True)

        # if the fuzzy parser failed to parse the line due to
        # incorrect timezone information issue #5 GitHub
        except ValueError:
            r = re.findall('^(.*?)\s*(?:\(|utc)', line, re.I)
            if r:
                r = dateutil.parser.parse(r[0])
        return r


    def get_headerVal(this,h, data, rex='\s*(.*?)\n\S+:\s'):
        r = re.findall('%s:%s' % (h, rex), data, re.X | re.DOTALL | re.I)
        if r:
            return r[0].strip()
        else:
            return None
        
    def get_analyze(self, mail_data):
        r = {}
        n = HeaderParser().parsestr(mail_data)
        graph = []
        received = n.get_all('Received')
        if received:
            received = [i for i in received if ('from' in i or 'by' in i)]
        else:
            received = re.findall(
                'Received:\s*(.*?)\n\S+:\s+', mail_data, re.X | re.DOTALL | re.I)
        c = len(received)
        for i in range(len(received)):
            if ';' in received[i]:
                line = received[i].split(';')
            else:
                line = received[i].split('\r\n')
            line = list(map(str.strip, line))
            line = [x.replace('\r\n', ' ') for x in line]
            try:
                if ';' in received[i + 1]:
                    next_line = received[i + 1].split(';')
                else:
                    next_line = received[i + 1].split('\r\n')
                next_line = list(map(str.strip, next_line))
                next_line = [x.replace('\r\n', '') for x in next_line]
            except IndexError:
                next_line = None
            
            print(line[-1])
            org_time = self.date_parser(line[-1])
            if not next_line:
                next_time = org_time
            else:
                next_time = self.date_parser(next_line[-1])

            if line[0].startswith('from'):
                data = re.findall(
                    """
                    from\s+
                    (.*?)\s+
                    by(.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s|$
                    )""", line[0], re.DOTALL | re.X)
            else:
                data = re.findall(
                    """
                    ()by
                    (.*?)
                    (?:
                        (?:with|via)
                        (.*?)
                        (?:\sid\s|$)
                        |\sid\s
                    )""", line[0], re.DOTALL | re.X)

            delay = (org_time - next_time).seconds
            if delay < 0:
                delay = 0

            try:
                ftime = org_time.utctimetuple()
                ftime = time.strftime('%m/%d/%Y %I:%M:%S %p', ftime)
                r[c] = {
                    'Timestmp': org_time,
                    'Time': ftime,
                    'Delay': delay,
                    'Direction': [x.replace('\n', ' ') for x in list(map(str.strip, data[0]))]
                }
                c -= 1
            except IndexError:
                pass

        for i in list(r.values()):
            if i['Direction'][0]:
                graph.append(["From: %s" % i['Direction'][0], i['Delay']])
            else:
                graph.append(["By: %s" % i['Direction'][1], i['Delay']])

        totalDelay = sum([x['Delay'] for x in list(r.values())])
        fTotalDelay = duration(totalDelay)
        delayed = True if totalDelay else False

        summary = {
            'From': n.get('From') or self.get_headerVal('from', mail_data),
            'To': n.get('to') or self.get_headerVal('to', mail_data),
            'Cc': n.get('cc') or self.get_headerVal('cc', mail_data),
            'Subject': n.get('Subject') or self.get_headerVal('Subject', mail_data),
            'MessageID': n.get('Message-ID') or self.get_headerVal('Message-ID', mail_data),
            'Date': n.get('Date') or self.get_headerVal('Date', mail_data),
        }

        security_headers = ['Received-SPF', 'Authentication-Results',
                            'DKIM-Signature', 'ARC-Authentication-Results']

        return {"data":r, "delayed":delayed, "summary":summary,"n":n, "security_headers":security_headers} 