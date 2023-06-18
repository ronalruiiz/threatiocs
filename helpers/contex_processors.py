import re

def register_context_processors(app):
    app.context_processor(lambda: {'country': get_country_for_IP,'duration':duration})
    # Agrega más context processors si es necesario

def get_country_for_IP(line):
    ipv4_address = re.compile(r"""
        \b((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d))\b""", re.X)
    ip = ipv4_address.findall(line)
    if ip:
        ip = ip[0]  # take the 1st ip and ignore the rest
        # if IP(ip).iptype() == 'PUBLIC':
        #     r = reader.country(ip).country
        #     if r.iso_code and r.name:
        return {
            # 'iso_code': r.iso_code.lower(),
            #'country_name': r.name
            'iso_code': "na",
            'country_name': "na"
        }


def duration(seconds, _maxweeks=99999999999):
    return ', '.join(
        '%d %s' % (num, unit)
        for num, unit in zip([
            (seconds // d) % m
            for d, m in (
                (604800, _maxweeks),
                (86400, 7), (3600, 24),
                (60, 60), (1, 60))
        ], ['wk', 'd', 'hr', 'min', 'sec'])
        if num
    )