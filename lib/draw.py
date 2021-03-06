#!/usr/bin/python

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import argparse
import sqlite3
import veri_data


def make_title(arch, plot_name):
    return "{}: {}".format(arch, plot_name)


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
    title = make_title(arch, "error structure")
    total = uns + unk + und
    errors = map((lambda x: float(x) / total), [uns, unk, und])
    fig, ax = plt.subplots()
    ax.set_title(title)
    fig.canvas.set_window_title(title)
    explode = (0.0, 0.1, 0.15)
    a = ax.pie(errors, explode=explode, startangle=90)
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


def draw_arrow(ax, x, y, dx, dy, label):
    ax.arrow(x, y, dx, dy, head_width=0.005,
             head_length=10, zorder=4)
    xh, yh = x + dx / 2.0 + 0.1, y + dy / 2.0
    plt.text(xh, yh, label, color='blue')


def draw_stats(arch, sucss, unsnd, unknw, fn, pw):
    fig, ax = make_subplot(arch, "stats")
    x = range(len(sucss))
    ax.set_ylabel('%', color='b')
    l1, = ax.plot(x, unsnd, color='r')
    l2, = ax.plot(x, unknw, color='y')
    l3, = ax.plot(x, fn)
    ticks_y = ticker.FuncFormatter(lambda y, pos: '{0:.1f}'.format(y * 100))
    ax.yaxis.set_major_formatter(ticks_y)
    # half = len(sucss) / 2.0
    # x0 = half / 2.0
    # draw_arrow(ax, 0, 0.25, x0, -0.01, 'gcc')
    # draw_arrow(ax, half, 0.25, x0, -0.01, 'icc')
    leg = plt.legend([l1, l2, l3],
                     ['semantic soundness',
                      'semantic completeness',
                      'false negative'])
    set_legend_linewidth(leg, 3)
    plt.grid()



def draw_total(arch, sucss, unsnd, unknw, undis):
    fig, ax = make_subplot(arch, "total numbers")
    x = range(len(sucss))
    l1, = ax.plot(x, sucss)
    l2, = ax.plot(x, unsnd, color='r')
    l3, = ax.plot(x, unknw, color='m')
    l4, = ax.plot(x, undis, color='y')
    ax.set_ylabel('instructions, 1e3', color='b')
    ax.fill_between(x, sucss)
    ticks_y = ticker.FuncFormatter(lambda y, pos: '{0:g}'.format(y / 1000))
    ax.yaxis.set_major_formatter(ticks_y)
    leg = plt.legend([l1, l2, l3, l4],
                     ['successful', 'semantic soundness',
                      'semantic completeness', 'disassembling errors'])
    set_legend_linewidth(leg, 3)
    plt.grid()


def draw_bin_ratio(arch, bin):
    fig, ax = make_subplot(arch, "binary/library ratio")
    x = range(len(bin))
    y = map((lambda a: 1.0), x)
    l1, = ax.plot(x, y)
    l2, = ax.plot(x, bin, color='g')
    ax.plot(x, bin, color='gray')
    ax.fill_between(x, y)
    ax.fill_between(x, bin, color='g')
    leg = plt.legend([l1, l2], ['code in libraries', 'code in binary'])
    set_legend_linewidth(leg, 5)
    plt.grid()


def constraint(data, length):
    if len == None:
        return data
    else:
        return data[:length]


def draw(c, arch, length, threshold):
    pairs, names = veri_data.find_pairs(c, arch)
    pairs = constraint(pairs, length)
    data = map((lambda (s, t): veri_data.fetch_data(c, s, t)), pairs)
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


if __name__ == '__main__':
    p = argparse.ArgumentParser(description='Draws results of verification')
    p.add_argument('--len', type=int, help='Constraint a points count')
    p.add_argument('--thr', default=0, type=int,
                   help='threshold, min number of instructions in a trace')
    p.add_argument('--arch', help='architecture')
    p.add_argument('db', help='database')
    args = p.parse_args()
    conn = sqlite3.connect(args.db)
    c = conn.cursor()
    draw(c, args.arch,  args.len, args.thr)
