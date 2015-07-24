import bitcoin as b
import sys
import json
import os
import insight_grabbing

# Timestamp of sale start: midnight CET Jul 22
start = 1406066400
# Initial sale rate
initial_rate = 2000
# Initial sale rate duration
initial_period = 14 * 86400
# step size for declining rate phase
rate_decline = 30
# Length of step
rate_period = 86400
# Number of declining periods
rate_periods = 22
# Final rate
final_rate = 1337
# Period during which final rate is effective
final_period = 6 * 86400 + 3600  # 1h of slack
# Accept post-sale purchases?
post_rate = 0
# Exodus address
exodus = '36PrZ1KHYMpqSyAQXSG8VwbUiq2EogxLo2'
# Minimum satoshis accepted
minimum = 1000000
# Maximum satoshis accepted
maximum = 150000000000

# Create caches directory
caches = {}

# Foundation address
foundation_address = 'cb3c3fc99b3983fd536d0cfdeb8090669aff57df'

try:
    os.mkdir('caches')
except:
    pass

if '--insight' in sys.argv:
    ipport = (sys.argv+[None])[sys.argv.index('--insight') + 1]
    if ipport:
        insight_grabbing.INSIGHT_ADDR = 'http://'+ipport
    _fetchtx = insight_grabbing.fetchtx
    _history = insight_grabbing.history
    _get_block_timestamp = insight_grabbing.get_block_timestamp
else:
    _fetchtx = b.blockr_fetchtx
    _history = b.history
    _get_block_timestamp = b.get_block_timestamp


# Cache methods that get networking data. Important since this script takes
# a very long time, and will almost certainly be interrupted multiple times
# while in progress
def cache_method_factory(method, filename):
    def new_method(arg):
        if filename not in caches:
            try:
                caches[filename] = json.load(open(filename, 'r'))
            except:
                caches[filename] = {}
        c = caches[filename]
        if str(arg) not in c:
            c[str(arg)] = method(arg)
            json.dump(c, open(filename, 'w'))
        return c[str(arg)]
    return new_method

# Cached versions of the blockr.io or insight methods that we need
get_block_timestamp = cache_method_factory(_get_block_timestamp,
                                           'caches/blocktimestamps.json')
fetchtx = cache_method_factory(_fetchtx, 'caches/fetchtx.json')
history = cache_method_factory(_history, 'caches/history.json')


# Get a dictionary of the transactions and block heights, taking as input
# a history produced by pybitcointools
def get_txs_and_heights(outs):
    txs = {}
    heights = {}
    for i in range(0, len(outs), 20):
        txhashes = []
        fetched_heights = []
        for j in range(i, min(i + 20, len(outs))):
            if outs[j]['output'][65:] == '0':
                txhashes.append(outs[j]['output'][:64])
                fetched_heights.append(outs[j]['block_height'])
            else:
                sys.stderr.write("Non-purchase tx found: %s\n" %
                                 fetchtx(outs[j]['output'][:64]))
        fetched_txs = fetchtx(txhashes)
        assert len(fetched_txs) == len(txhashes)
        for h, tx, ht in zip(txhashes, fetched_txs, fetched_heights):
            txs[h] = tx
            heights[h] = ht
        sys.stderr.write('Processed transactions: %d\n' % len(txs))
    return {"txs": txs, "heights": heights}


# Produce a json list of purchases, taking as input a dictionary of
# transactions and heights
def list_purchases(obj):
    txs, heights = obj['txs'], obj['heights']
    process_queue = []
    for h in txs:
        txhex = str(txs[h])
        txouts = b.deserialize(txhex)['outs']
        if len(txouts) >= 2 and txouts[0]['value'] >= minimum - 30000:
            addr = b.script_to_address(txouts[0]['script'])
            if addr == exodus:
                v = txouts[0]['value'] + 30000
                process_queue.append({
                    "tx": h,
                    "addr": b.b58check_to_hex(b.script_to_address(
                                              txouts[1]['script'])),
                    "value": v,
                    "height": heights[h]
                })
    # Determine the timestamp for every block height. We care about
    # the timestamp of the previous confirmed block before a transaction.
    # Save the results as a dictionary of transaction data
    o = []
    for i in range(0, len(process_queue), 20):
        subpq = process_queue[i:i+20]
        t = get_block_timestamp([x['height'] - 1 for x in subpq])
        assert len(t) == len(subpq), [x['height'] - 1 for x in subpq]
        o.extend([{
            "tx": _a["tx"],
            "addr": _a["addr"],
            "value": _a["value"],
            "time": _b
        } for _a, _b in zip(subpq, t)])
        sys.stderr.write('Gathered outputs: %d\n' % len(o))
    return o


# Compute ether value from BTC value, using as input objects containing
# ether address, value and time and saving a map of ether address => balance
def evaluate_purchases(purchases):
    balances = {}
    for p in purchases:
        if p["time"] < start + initial_period:
            rate = initial_rate
        elif p["time"] < start + initial_period + rate_period * rate_periods:
            pid = (p["time"] - (start + initial_period)) // rate_period + 1
            rate = initial_rate - rate_decline * pid
        elif p["time"] < start + initial_period + rate_period * \
                rate_periods + final_period:
            rate = final_rate
        else:
            rate = post_rate
        # Round to the nearest finney
        balance_to_add = (p["value"] * rate // 10**5) * 10**15
        balances[p["addr"]] = balances.get(p["addr"], 0) + balance_to_add
    return balances


# Compute a genesis block from purchase balances
def mk_genesis_block(balances):
    o = {k: {"balance": str(v)} for k, v in balances.items()}
    total_purchased = sum(balances.values())
    o[foundation_address] = {
        "balance": str(total_purchased * 198 // 1000)
    }
    sys.stderr.write("Finished, total purchased: %d\n" % total_purchased)
    sys.stderr.write("Foundation address: %s\n" % foundation_address)
    sys.stderr.write("Foundation balance: %s\n" % (total_purchased * 198 // 1000))
    return {
        "nonce": "0x0000000000000042",
        "timestamp": "0x00",
        "difficulty": "0x20000",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "extraData": "0x",
        "gasLimit": "0x13880000",
        "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "coinbase": "0x0000000000000000000000000000000000000000",
        "alloc": o
    }


def evaluate():
    outs = history(exodus)
    sys.stderr.write('Gathered history: %d\n' % len(outs))
    th = get_txs_and_heights(outs)
    sys.stderr.write('Gathered txs and heights\n')
    p = list_purchases(th)
    sys.stderr.write('Listed purchases\n')
    o = evaluate_purchases(p)
    sys.stderr.write('Computed purchases\n')
    g = mk_genesis_block(o)
    return g

if __name__ == '__main__':
    print json.dumps(evaluate(), indent=4)
