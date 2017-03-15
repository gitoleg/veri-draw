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


def calc(c, arch):
    tasks = extract_ids(c, arch)
    x = []
    for task in tasks:
        task_id = long(task[0])
        dyn_data = extract_dyn_data(c, task_id)
        suc, und, uns, unk = 0, 0, 0, 0
        for data in dyn_data:
            suc += int(data[3])
            und += int(data[4])
            uns += int(data[5])
            unk += int(data[6])
        tot = suc + und + uns + unk
        x.append((suc, uns, tot))
    return x


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


def fetch_data(c, static_id, trace_id):
    dyn_data = extract_dyn_data(c, trace_id)
    suc, und, uns, unk = 0, 0, 0, 0
    for data in dyn_data:
        suc += int(data[3])
        und += int(data[4])
        uns += int(data[5])
        unk += int(data[6])
    total = suc + und + uns + unk
    ins_t = extract_insns(c, trace_id)
    ins_s = extract_insns(c, static_id)
    tr_ad = fetch_addrs(c, trace_id)
    st_ad = fetch_addrs(c, static_id)
    inter = Set.intersection(tr_ad, st_ad)
    diffr = Set.difference(tr_ad, st_ad)
    return {"unique_trace": len(ins_t),
            "unique_binary": len(ins_s),
            "unique_library": len(diffr),
            "coverage": float(len(inter)) / len(st_ad),
            "sucs_rel": float(suc) / total,
            "uns_rel": float(uns) / total,
            "sucs_abs": suc,
            "uns_abs": uns,
            "unk_abs": unk,
            "und_abs": und,
            "total": total}


def draw_errors(arch, uns, unk, und):
    labels = ['semantic soundness',
              'semantic completeness', 'disassembler errors']
    total = uns + unk + und
    errors = [uns, unk, und]
    errors = map((lambda x: float(x) / total), errors)
    fig, ax = plt.subplots()
    fig.canvas.set_window_title('')
    ax.pie(errors, labels=labels, autopct='%1.3f%%', labeldistance=1.2)
    ax.axis('equal')
    ax.set_title(arch)


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
    ax.pie(numbers, explode=explode, colors=colors, labels=labels,
           autopct='%1.1f%%', labeldistance=1.2)
    ax.axis('equal')
    ax.set_title(arch)


def draw_graphs(arch, unq_t, unq_b, unq_l, sucss, unsnd, cover):
    x = range(len(unq_t))
    fig, ax1 = plt.subplots()
    fig.canvas.set_window_title('')
    ax2 = ax1.twinx()
    ax1.set_ylabel('abs numbers', color='b')
    l1, = ax1.plot(x, unq_t)
    l2, = ax1.plot(x, unq_b)
    l21, =  ax1.plot(x, unq_l)
    ax2.set_ylabel('rel numbers', color='r')
    l3, = ax2.plot(x, sucss, 'r-')
    l4, = ax2.plot(x, unsnd, 'r-')
    l5, = ax2.plot(x, cover, 'r-')
#    plt.legend([l1, l2], ['total', 'successful'])
    plt.grid()


def draw(c, arch):
    pairs = find_comparable_ids(c, arch)
    data = map((lambda (s, t): fetch_data(c, s, t)), pairs)
    sucss = map((lambda d: d["sucs_rel"]), data)
    unsnd = map((lambda d: d["uns_rel"]), data)
    cover = map((lambda d: d["coverage"]), data)
    unq_t = map((lambda d: d["unique_trace"]), data)
    unq_b = map((lambda d: d["unique_binary"]), data)
    unq_l = map((lambda d: d["unique_library"]), data)
    suc = reduce((lambda x, d: x + d['sucs_abs']), data, 0)
    uns = reduce((lambda x, d: x + d['uns_abs']), data, 0)
    unk = reduce((lambda x, d: x + d['unk_abs']), data, 0)
    und = reduce((lambda x, d: x + d['und_abs']), data, 0)
    draw_sum(arch, suc, uns, unk, und)
    draw_errors(arch, uns, unk, und)
    draw_graphs(arch, unq_t, unq_b, unq_l, sucss, unsnd, cover)
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
    t = list(fetch_addrs(c, 1))
    s = list(fetch_addrs(c, 25))
    t.sort()
    s.sort()
    a = max(s)
    cnt = sum(1 for i in t if i > a)
    print "static: %d, trace: %d / %d" % (len(s), cnt, len(t))
    print "max static %0X" % a
    print "insn count %d %d" % (unique_insn_count(c, 25), unique_insn_count(c, 1))
    for i in t:
        print "%0X" % i


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
    conn.close()
