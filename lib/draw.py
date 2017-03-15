#!/usr/bin/python

import sys
import getopt
import sqlite3
import matplotlib.pyplot as plt
from sets import Set


def extract_ids(c, arch):
    q = "SELECT * FROM task WHERE Id IN \
    (SELECT Id FROM info WHERE Arch = '%s' And Kind = 'Trace')" % arch
    c.execute(q)
    return c.fetchall()


def find_comparable_ids(c, arch):
    qt = "SELECT * FROM info WHERE Arch = '%s' And Kind = 'Trace'" % arch
    qb = "SELECT * FROM info WHERE Arch = '%s' And Kind = 'Static'" % arch
    c.execute(qt)
    traces = list(c.fetchall())
    c.execute(qb)
    statics = list(c.fetchall())
    x = []
    for tr in traces:
        tid = tr[0]
        tnm = tr[2]
        for st in statics:
            if tnm == st[2]:
                x.append((st[0], tid))
    return x


def extract_dyn_data(c, task_id):
    q = "SELECT * FROM dynamic_data WHERE Id_task = '%d'" % task_id
    c.execute(q)
    return c.fetchall()


def extract_addrs(c, task_id):
    q = "SELECT Addrs FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    c.execute(q)
    return c.fetchall()


def extract_insns(c, task_id):
    q = "SELECT * FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    c.execute(q)
    return c.fetchall()


def unique_insn_count(c, task_id):
    r = extract_insns(c, task_id)
    return len(r)


def fetch_addrs(c, task_id):
    addrs = extract_addrs(c, task_id)
    r = []
    for x in addrs:
        y = x[0].split(' ')
        r = r + list(y)
    r = map((lambda x: int(x.strip())), r)
    return Set(r)


def coverage(c, static_id, trace_id):
    trace = fetch_addrs(c, trace_id)
    stat = fetch_addrs(c, static_id)
    inter = Set.intersection(trace, stat)
    return (float(len(inter)) / len(stat))


def is_lib_addr(addr, bins):
    return (not any(x <= addr <= y for x, y in bins))


def filter_bin_addrs(addrs, bins):
    s = set()
    [s.add(x) for x in addrs if not is_lib_addr(x, bins)]
    return s


def false_negative(tr_addrs, st_addrs, bins):
    sit = Set.intersection(st_addrs, tr_addrs)
    lit = set()
    [lit.add(x) for x in tr_addrs if is_lib_addr(x, bins)]
    addrs = Set.union(sit, lit)
    return Set.difference(tr_addrs, addrs)


def false_negative_rel(tr_addrs, st_addrs, bins):
    fn = false_negative(tr_addrs, st_addrs, bins)
    s = filter_bin_addrs(tr_addrs, bins)
    return float(len(fn)) / float(len(s))


def power(tr_addrs, bins):
    s = filter_bin_addrs(tr_addrs, bins)
    return float(len(s)) / len(tr_addrs)


def fetch_data(c, static_id, trace_id):
    dyn_data = extract_dyn_data(c, trace_id)
    suc, und, uns, unk = 0, 0, 0, 0
    for data in dyn_data:
        suc += int(data[3])
        und += int(data[4])
        uns += int(data[5])
        unk += int(data[6])
    total = suc + und + uns + unk
    tr_ad = fetch_addrs(c, trace_id)
    st_ad = fetch_addrs(c, static_id)
    bins = [(min(st_ad), max(st_ad))]
    for x, y in bins:
        print "%Xd, %Xd" % (x, y)
    fn = false_negative_rel(tr_ad, st_ad, bins)
    pw = power(tr_ad, bins)
    return {"sucs_rel": float(suc) / total,
            "uns_rel": float(uns) / total,
            "unk_rel": float(unk) / total,
            "sucs_abs": suc,
            "uns_abs": uns,
            "unk_abs": unk,
            "und_abs": und,
            "false_neg": fn,
            "stat_power": pw}


def draw_errors(arch, uns, unk, und):
    labels = ['semantic soundness',
              'semantic completeness', 'disassembler errors']
    total = uns + unk + und
    errors = [uns, unk, und]
    errors = map((lambda x: float(x) / total), errors)
    fig, ax = plt.subplots()
    ax.set_title(arch)
    fig.canvas.set_window_title('')
    ax.pie(errors, labels=labels, autopct='%1.3f%%', labeldistance=1.2)
    ax.axis('equal')


def draw_sum(arch, suc, uns, unk, und):
    labels = ['successful', 'errors']
    explode = (0.1, 0.0)
    colors = ['g', 'r']
    errors = uns + unk + und
    total = suc + errors
    numbers = [suc, errors]
    numbers = map((lambda x: float(x) / total * 100), numbers)
    fig, ax = plt.subplots()
    fig.canvas.set_window_title('')
    ax.set_title(arch)
    ax.pie(numbers, explode=explode, colors=colors, labels=labels,
           autopct='%1.1f%%', labeldistance=1.2)
    ax.axis('equal')


def draw_graphs(arch, sucss, unsnd, unknw, fn, pw):
    x = range(len(sucss))
    fig, ax1 = plt.subplots()
    ax1.set_title(arch)
    fig.canvas.set_window_title('')
    ax1.set_ylabel('rel %', color='b')
    l1, = ax1.plot(x, sucss)
    l2, = ax1.plot(x, unsnd)
    l3, =  ax1.plot(x, unknw)
    l4, =  ax1.plot(x, fn)
    l5, =  ax1.plot(x, pw)
    plt.legend([l1, l2, l3, l4, l5],
               ['successful', 'semantic soundness',
                'semantic completeness',
                'false negative', 'statistic power'])
    plt.grid()


def draw(c, arch):
    pairs = find_comparable_ids(c, arch)
    data = map((lambda (s, t): fetch_data(c, s, t)), pairs)
    sucss = map((lambda d: d["sucs_rel"]), data)
    unsnd = map((lambda d: d["uns_rel"]), data)
    unknw = map((lambda d: d["unk_rel"]), data)
    fn = map((lambda d: d["false_neg"]), data)
    pw = map((lambda d: d["stat_power"]), data)
    suc = reduce((lambda x, d: x + d['sucs_abs']), data, 0)
    uns = reduce((lambda x, d: x + d['uns_abs']), data, 0)
    unk = reduce((lambda x, d: x + d['unk_abs']), data, 0)
    und = reduce((lambda x, d: x + d['und_abs']), data, 0)
    draw_sum(arch, suc, uns, unk, und)
    draw_errors(arch, uns, unk, und)
    draw_graphs(arch, sucss, unsnd, unknw, fn, pw)
    plt.show()


def total_trace_count(c, task_id):
    stats = extract_dyn_data(c, task_id)
    total = 0
    suc, und, uns, unk = 0, 0, 0, 0
    for data in stats:
        suc += int(data[3])
        und += int(data[4])
        uns += int(data[5])
        unk += int(data[6])
    total += suc + und + uns + unk
    return total

def play(c):
    trace_id = 1
    static_id = 25
    tr_ad = fetch_addrs(c, trace_id)
    st_ad = fetch_addrs(c, static_id)

    bins = [(min(st_ad), max(st_ad))]
    for x,y in bins:
        print "%Xd, %Xd" % (x, y)
    fn = false_negative_rel(tr_ad, st_ad, bins)
    pw = power(tr_ad, bins)
    print "%f %f"  % (fn, pw)


if __name__ == "__main__":
    arch = ''
    db = ''
    argv = sys.argv[1:]
    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["arch=", "db="])
    except getopt.GetoptError:
        print "usage: draw.py --arch=arch-name --db=database"
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-a", "--arch"):
            arch = arg
        elif opt in ("--db"):
            db = arg
    conn = sqlite3.connect(db)
    c = conn.cursor()
    draw(c, arch)
#    play(c)
    conn.close()
