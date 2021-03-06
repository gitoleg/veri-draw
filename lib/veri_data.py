#!/usr/bin/python

import sqlite3


def fetchall(c, q):
    c.execute(q)
    return c.fetchall()


def fetchone(c, q):
    c.execute(q)
    return c.fetchone()


def extract_ids(c, arch):
    q = "SELECT * FROM task WHERE Id IN \
    (SELECT Id FROM info WHERE Arch = '%s' And Kind = 'Trace')" % arch
    return fetchall(c, q)


def find_pairs(c, arch):
    qt = "SELECT * FROM info WHERE Arch = '%s' And Kind = 'Trace'" % arch
    qb = "SELECT * FROM info WHERE Arch = '%s' And Kind = 'Static'" % arch
    traces = list(fetchall(c, qt))
    statics = list(fetchall(c, qb))
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
    return fetchall(c, q)


def extract_addrs(c, task_id):
    q = "SELECT Addrs FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    return fetchall(c, q)


def extract_insns(c, task_id):
    q = "SELECT * FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    return fetchall(c, q)


def extract_exec_ranges(c, task_id):
    q = "SELECT * FROM bin_info WHERE Id_task = '%s'" % task_id
    return map((lambda x: (x[2], x[3])), fetchall(c, q))


def extract_name(c, task_id):
    q = "SELECT Name FROM info WHERE Id = '%s'" % task_id
    return fetchone(c,q)[0]


def to_addrs(s):
    return map((lambda x: int(x.strip())), list(s.split(' ')))


def fetch_insns(c, task_id):
    q = "SELECT Name, Bytes, Addrs FROM Insn WHERE Id IN \
    (SELECT Id_insn FROM task_insn WHERE Id_task = '%s')" % task_id
    return map((lambda (n, b, a): (n, b, to_addrs(a))), fetchall(c, q))


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
