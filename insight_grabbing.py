#!/usr/bin/python
import json, re
import random
import sys
try:
    from urllib.request import build_opener
except:
    from urllib2 import build_opener

INSIGHT_ADDR = 'http://178.19.221.38:3000'


# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0'+str(random.randrange(1000000)))]
    try:
        return opener.open(*args).read().strip()
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)


def history(a):
    hashes = json.loads(make_request(INSIGHT_ADDR + '/api/addr/'+a))["transactions"]
    o = []
    for i in range(0, len(hashes), 10):
        h = hashes[i:i+10]
        t = json.loads(make_request(INSIGHT_ADDR + '/api/multitx/'+','.join(h)))
        sys.stderr.write('Getting txs: %d\n' % i)
        if isinstance(t, dict):
            t = [t]
        for tee in t:
            for i, out in enumerate(tee["vout"]):
                if a in out["scriptPubKey"]["addresses"]:
                    o.append({"output": tee["txid"]+':'+str(i),
                              "block_height": tee["confirmedIn"],
                              "value": out["valueSat"]})
    return o


def get_block_timestamp(a):
    addrtail = ','.join([str(x) for x in a]) if isinstance(a, list) else str(a)
    o = json.loads(make_request(INSIGHT_ADDR + '/api/blockheader-by-index/'+addrtail))
    if isinstance(o, list):
        return [x['time'] for x in o]
    else:
        return o['time']


def fetchtx(a):
    addrtail = ','.join(a) if isinstance(a, list) else a
    return json.loads(make_request(INSIGHT_ADDR + '/api/rawmultitx/'+addrtail))
