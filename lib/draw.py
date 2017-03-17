#!/usr/bin/python

import argparse
import sqlite3
import matplotlib.pyplot as plt


def execute(c, q):
    c.execute(q)

    return c.fetchall()

def extract_ids(c, arch):
    q = "SELECT * FROM task WHERE Id IN \
    (SELECT Id FROM info WHERE Arch = '%s' And Kind = 'Trace')" % arch
    return execute(c, q)


def find_pairs(c, arch):
    qt = "SELECT * FROM info WHERE Arch = '%s' And Kind = 'Trace'" % arch
    qb = "SELECT * FROM info WHERE Arch = '%s' And Kind = 'Static'" % arch
    traces = list(execute(c, qt))
    statics = list(execute(c, qb))
    ids, names = [], []
    for tr in traces:
        tid = tr[0]
        tnm = tr[2]
        for st in statics:
            if tnm == st[2]:
                ids.append((st[0], tid))
                names.append((st[2], tr[2]))
    return ids, names


def extract_dyn_data(c, task_id):
    q = "SELECT * FROM dynamic_data WHERE Id_task = '%d'" % task_id
    return execute(c, q)


def extract_addrs(c, task_id):
    q = "SELECT Addrs FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    return execute(c, q)

def extract_insns(c, task_id):
    q = "SELECT * FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    return execute(c, q)

def extract_exec_ranges(c, task_id):
    q = "SELECT * FROM bin_info WHERE Id_task = '%s'" % task_id
    return map((lambda x: (x[2], x[3])), execute(c, q))


def extract_name(c, task_id):
    q = "SELECT Name FROM info WHERE Id = '%s'" % task_id
    c.execute(q)
    r = c.fetchone()
    return r[0]


def to_addrs(s):
    return map((lambda x: int(x.strip())), list(s.split(' ')))


def fetch_insns(c, task_id):
    q = "SELECT Name, Bytes, Addrs FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    return map((lambda (n, b, a): (n, b, to_addrs(a))), execute(c, q))


def unfolded_insns(c, task_id):
    r = []
    x = fetch_insns(c, task_id)
    for name, bytes, addrs in fetch_insns(c, task_id):
        for a in addrs:
            r.append((name, bytes, a))
    return r


def fetch_addrs(c, task_id):
    x = set()
    for i in unfolded_insns(c, task_id):
        x.add(i[2])
    return x


def is_lib_addr(addr, bins):
    return (not any(x <= addr <= y for x, y in bins))


def filter_bin_addrs(addrs, bins):
    return filter((lambda x: not is_lib_addr(x, bins)), addrs)


def false_negative(tr_addrs, st_addrs, bins):
    sit = st_addrs.intersection(tr_addrs)
    lit = filter((lambda x: is_lib_addr(x, bins)), tr_addrs)
    addrs = sit.union(lit)
    return tr_addrs - addrs


def false_negative_rel(tr_addrs, st_addrs, bins):
    fn = false_negative(tr_addrs, st_addrs, bins)
    s = filter_bin_addrs(tr_addrs, bins)
    slen = len(s)
    if slen == 0:
        return 0
    else:
        return float(len(fn)) / float(len(s))


def stat_power(c, id_t, bins):
    tr = unfolded_insns(c, id_t)
    unique = set()
    unique_bin = set()
    for x in tr:
        unique.add(x[1])
        if not is_lib_addr(x[2], bins):
            unique_bin.add(x[1])
    return float(len(unique_bin)) / len(unique)


def bin_lib_ratio(tr_addrs, bins):
    total = len(tr_addrs)
    bin = len(filter_bin_addrs(tr_addrs, bins))
    lib = total - bin
    return (float(bin) / total, float(lib) / total)


def find_code_ranges(c, sid, static_addrs):
    try:
        return extract_exec_ranges(c, sid)
    except:
        return [(min(static_addrs), max(static_addrs))]


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
    bins = find_code_ranges(c, static_id, st_ad)
    fn = false_negative_rel(tr_ad, st_ad, bins)
    pw = stat_power(c, trace_id, bins)

    name = extract_name(c, static_id)
    print "%s - fn: %g, pw %g" % (name, fn, pw)

    bin, lib = bin_lib_ratio(tr_ad, bins)
    return {"suc_rel": float(suc) / total,
            "uns_rel": float(uns) / total,
            "unk_rel": float(unk) / total,
            "suc_abs": suc,
            "uns_abs": uns,
            "unk_abs": unk,
            "und_abs": und,
            "false_neg": fn,
            "stat_power": pw,
            "bin_in_trace": bin,
            "lib_in_trace": lib,
            "trace_len" : total}


def make_title(arch, plot_name):
    return  "{}: {}".format(arch, plot_name)


def set_legend_linewidth(leg, width):
    for legobj in leg.legendHandles:
        legobj.set_linewidth(width)


def make_subplot(arch, plot_name):
    title = make_title(arch, plot_name)
    fig, ax = plt.subplots()
    fig.canvas.set_window_title(title)
    ax.set_title(title)
    ax.set_facecolor('lightgray')
    return fig, ax


def percent_str(x, y, name):
    p = 100.0 * x / y
    return '{0:.3f}% {1}'.format(p, name)


def draw_errors(arch, uns, unk, und):
    title = make_title(arch, "errors structure")
    total = uns + unk + und
    errors = map((lambda x: float(x) / total), [uns, unk, und])
    fig, ax = plt.subplots()
    ax.set_title(title)
    fig.canvas.set_window_title(title)
    a = ax.pie(errors)
    labels = [percent_str(uns, total, 'semantic soundness'),
              percent_str(unk, total, 'semantic completeness'),
              percent_str(und, total, 'disassembler errors')]
    plt.legend(a[0], labels, loc='upper left', bbox_to_anchor=(-0.1, 1.),)
    ax.axis('equal')


def draw_summary(arch, suc, uns, unk, und):
    fig, ax = make_subplot(arch, "summary")
    labels = ['successful', 'errors']
    explode = (0.1, 0.0)
    colors = ['g', 'r']
    errors = uns + unk + und
    total = suc + errors
    numbers = [suc, errors]
    numbers = map((lambda x: float(x) / total * 100), numbers)
    ax.pie(numbers, explode=explode, colors=colors, labels=labels,
                 autopct='%1.1f%%', labeldistance=1.2)
    ax.axis('equal')


def draw_stats(arch, sucss, unsnd, unknw, fn, pw):
    fig, ax = make_subplot(arch, "statistics")
    x = range(len(sucss))
    ax.set_ylabel('rel ', color='b')
    l1, = ax.plot(x, unsnd)
    l2, = ax.plot(x, unknw)
    l3, = ax.plot(x, fn)
    l4, = ax.plot(x, pw)
    leg = plt.legend([l1, l2, l3, l4],
               ['semantic soundness',
                'semantic completeness',
                'false negative', 'statistic power'])
    set_legend_linewidth(leg, 3)
    plt.grid()


def draw_total(arch, sucss, unsnd, unknw, undis):
    fig, ax= make_subplot(arch, "total numbers")
    x = range(len(sucss))
    l1, = ax.plot(x, sucss)
    l2, = ax.plot(x, unsnd, color='r')
    l3, = ax.plot(x, unknw, color='m')
    l4, = ax.plot(x, undis, color='y')
    ax.set_ylabel('instructions', color='b')
    ax.fill_between(x, sucss)
    leg = plt.legend([l1, l2, l3, l4],
               ['successful', 'semantic soundness',
                'semantic completeness', 'disassembling errors'])
    set_legend_linewidth(leg, 3)
    plt.grid()


def draw_bin_ratio(arch, bin):
    fig, ax = make_subplot(arch, "binary/library code ratio")
    x = range(len(bin))
    y = map((lambda a: 1.0), x)
    l1, = ax.plot(x, y)
    l2, = ax.plot(x, bin, color = 'g')
    ax.plot(x, bin, color = 'gray')
    ax.fill_between(x, y)
    ax.fill_between(x, bin, color='g')
    leg = plt.legend([l1, l2], ['code in libraries', 'code in binary'])
    set_legend_linewidth(leg, 5)
    plt.grid()


def constraint(data, len):
    if len == None:
        return data
    else:
        return data[:len]

def draw(c, arch, threshold, len):
    pairs, names = find_pairs(c, arch)
    pairs = constraint(pairs, len)
    data = map((lambda (s, t): fetch_data(c, s, t)), pairs)
    data = filter((lambda d: d["trace_len"] > threshold), data)
    sucss_rel = map((lambda d: d["suc_rel"]), data)
    unsnd_rel = map((lambda d: d["uns_rel"]), data)
    unknw_rel = map((lambda d: d["unk_rel"]), data)
    sucss_abs = map((lambda d: d["suc_abs"]), data)
    unsnd_abs = map((lambda d: d["uns_abs"]), data)
    unknw_abs = map((lambda d: d["unk_abs"]), data)
    undis_abs = map((lambda d: d["und_abs"]), data)
    fn = map((lambda d: d["false_neg"]), data)
    pw = map((lambda d: d["stat_power"]), data)
    suc = sum(sucss_abs)
    uns = sum(unsnd_abs)
    unk = sum(unknw_abs)
    und = sum(undis_abs)
    bin = map((lambda d: d["bin_in_trace"]), data)
    draw_summary(arch, suc, uns, unk, und)
    draw_errors(arch, uns, unk, und)
    draw_stats(arch, sucss_rel, unsnd_rel, unknw_rel, fn, pw)
    draw_total(arch, sucss_abs, unsnd_abs, unknw_abs, undis_abs)
    draw_bin_ratio(arch, bin)
    plt.show()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='Draws results of verification')
    p.add_argument('--len', type=int, help='Constraint a points count')
    p.add_argument('--thr', default=0, type=int,
                   help='threshold, min number of instructions in a trace')
    p.add_argument('--arch', help='architecture')
    p.add_argument('db', help='database')
    args = p.parse_args()
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    draw(c, args.arch, args.thr, args.len)
    conn.close()
