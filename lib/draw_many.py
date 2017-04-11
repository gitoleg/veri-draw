#!/usr/bin/python

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import sqlite3
import argparse
from os import path

import draw
import veri_data


arch = 'x86-64'


def constraint(data, length):
    if len == None:
        return data
    else:
        return data[:length]

def fetch_data(c, len, thr):
    pairs, names = veri_data.find_pairs(c)
    pairs = constraint(pairs, len)
    data = map((lambda (s, t): veri_data.fetch_data(c, s, t)), pairs)
    return filter((lambda d: d["trace_len"] > thr), data)


def draw_stat(fig, ax, name, data):
    sucss_rel = map((lambda d: d["suc_rel"]), data)
    unsnd_rel = map((lambda d: d["uns_rel"]), data)
    unknw_rel = map((lambda d: d["unk_rel"]), data)
    fn = map((lambda d: d["false_neg"]), data)
    pw = map((lambda d: d["stat_power"]), data)
    draw.draw_stats2(fig, ax, name, unsnd_rel, unknw_rel)


def draw_all(curs, length, thr):
    data = map((lambda (name, c): (name, fetch_data(c, length, thr))), curs)
    fig, ax = draw.make_subplot(arch, "stats")
    ax.set_ylabel('%')
    ticks_y = ticker.FuncFormatter(lambda y, pos: '{0:.1f}'.format(y * 100))
    ax.yaxis.set_major_formatter(ticks_y)
    map((lambda (name, data): draw_stat(fig, ax, name, data)), data)
    plt.grid()
    plt.show()


def chart_name(fname):
    x = path.basename(fname)
    return path.splitext(x)[0]


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='Draws results of verification')
    p.add_argument('--len', type=int, help='Constraint a points count')
    p.add_argument('--thr', default=0, type=int,
                   help='threshold, min number of instructions in a trace')
    p.add_argument('--db', nargs='+', help='databases paths')
    args = p.parse_args()
    dbs = map((lambda x: (chart_name(x), sqlite3.connect(x))), args.db)
    curs = map((lambda (name, conn): (name, conn.cursor())), dbs)
    draw_all(curs, args.len, args.thr)
    iter((lambda (name, conn): conn.close()), dbs)
