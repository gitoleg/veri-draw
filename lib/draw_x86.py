#!/usr/bin/python

import argparse
import sqlite3
import matplotlib.pyplot as plt
import veri_data

arch = 'x86_64'


def percent_str(x, y, name):
    p = 100.0 * x / y
    return '{0:.3f}% {1}'.format(p, name)


def draw_errors(uns, unk, und):
    total = uns + unk + und
    errors = map((lambda x: float(x) / total), [uns, unk, und])
    explode = (0.0, 0.1, 0.15)
    labels = [percent_str(uns, total, 'semantic soundness'),
              percent_str(unk, total, 'semantic completeness'),
              percent_str(und, total, 'disassembler errors')]
    a = plt.pie(errors, explode=explode, startangle=90)
    plt.legend(a[0], labels, bbox_to_anchor=(-0.05, 0.0),
               loc='center left')
    plt.axis('equal')


def constraint(data, length):
    if len == None:
        return data
    else:
        return data[:length]


def draw(info, fig, length, threshold):
    (name, c), n = info
    sub = fig.add_subplot(n)
    sub.set_title(name)
    pairs, names = veri_data.find_pairs(c, arch)
    pairs = constraint(pairs, length)
    data = map((lambda (s, t): veri_data.fetch_data(c, s, t)), pairs)
    data = filter((lambda d: d["trace_len"] > threshold), data)
    uns = sum(map((lambda d: d["uns_abs"]), data))
    unk = sum(map((lambda d: d["unk_abs"]), data))
    und = sum(map((lambda d: d["und_abs"]), data))
    print 'errors for %s: uns %d, unk %d, und %d' % (name, uns, unk, und)
    draw_errors(uns, unk, und)


def draw_all(curs, length, thr):
    fig = plt.figure(1)
    fig.canvas.set_window_title('compare lifters')
    for i in zip(curs, [221,222,223]):
        draw(i, fig, length, thr)
    plt.show()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description='Draws results of verification')
    p.add_argument('--len', type=int, help='Constraint a points count')
    p.add_argument('--thr', default=0, type=int,
                   help='threshold, min number of instructions in a trace')
    p.add_argument('--legacy', help='database with legacy lifter results')
    p.add_argument('--modern', help='database with modern lifter results')
    p.add_argument('--merge',  help='database with merge  lifter results')
    args = p.parse_args()
    dbs = filter((lambda (n,x): x != None),
                 [('legacy', args.legacy),
                  ('modern', args.modern),
                  ('merge', args.merge)])
    conns = map((lambda (name, db): (name, sqlite3.connect(db))), dbs)
    curs =  map((lambda (name, conn): (name, conn.cursor())), conns)
    draw_all(curs, args.len, args.thr)
    iter((lambda (name, conn): conn.close()), conns)
