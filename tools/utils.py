import csv
import matplotlib.pyplot as plt
import statistics
import numpy as np

########## FILE PARSING UTILS ##########
def parse_ciphersuites(filename):
    with open(filename, 'r') as fl:
        return [line.strip() for line in fl.readlines()]

def parse_algorithms(filename):
    with open(filename, 'r') as fl:
        algs = {'CIPHER': [], 'MD': [], 'KE': []}

        for line in fl.readlines():
            line = line.split(',')
            algs[line[0].strip()] += [line[1].strip()]

        ciphersuites = []
        for ke in algs['KE']:
            for cipher in algs['CIPHER']:
                for md in algs['MD']:
                    ciphersuites.append('TLS-' + ke + '-WITH-' + cipher + '-' + md)

        return ciphersuites

def parse_csv_to_data(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[3:]
        data = {}
        data_keys = {}

        for hdr in headers:
            for ext in ['_out', '_in']:
                entry = hdr + ext
                data[entry] = {}
                data_keys[entry] = [] 

        for row in csv_reader:
            data_size = row['data_size']
            operation = row['operation']

            for hdr in headers:
                val = int(row[hdr])

                if val != 0:
                    if operation == 'encrypt' or operation == 'digest':
                        hdr += '_out'
                    elif operation == 'decrypt' or operation == 'verify':
                        hdr += '_in'

                    if data_size not in data_keys[hdr]:
                        data_keys[hdr].append(data_size)
                        data[hdr][data_size] = []

                    data[hdr][data_size].append(val)
        
        return data, headers

########## PLOTTING UTILS ##########
def save_fig(fig, fname):
    fig.tight_layout()
    fig.savefig(fname)
    plt.close(fig)
    plt.cla()

def custom_errorbar(x, y, e, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, fmt='.', capsize=5, barsabove=True, **kwargs)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

def multiple_custom_plots(x, y1, y2, ax=None, title=None, ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()

    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

def custom_bar(y_list, width=0.25, ax=None, title=None, labels=[], xtickslabels=None, ylabel=None):
    if ax is None:
        ax = plt.gca()

    x = np.arange(len(xtickslabels))
    x *= (len(y_list)//2 + 1)

    for i in range(len(y_list)):
        x1 = x + (i + (1 - len(y_list))/2)*width

        ax.bar(x1, y_list[i], width=width, label=labels[i])

    ax.set_xticks(x)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

def custom_scatter(x, y, ax=None, title=None, xticks=None, xtickslabels=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

########## DATA ANALYSIS UTILS ##########
def filter_z_score(data, headers, weight=2):
    for hdr in headers:
        for ext in ['_out', '_in']:
            entry = hdr + ext
            op_dict = data[entry]
            
            for key in op_dict:
                tmp = []
                mean = np.mean(op_dict[key])
                stdev = np.std(op_dict[key])

                for val in op_dict[key]:
                    stdw = weight * stdev

                    if val > (mean + stdw):
                        continue
                    elif val < (mean - stdw):
                        continue
                    else:
                        tmp.append(val)
                
                data[entry][key] = tmp

    return data

def filter_iqr(data, headers, weight=1.5):
    for hdr in headers:
        for ext in ['_out', '_in']:
            entry = hdr + ext
            op_dict = data[entry]
            
            for key in op_dict:
                tmp = []
                q1 = np.quantile(op_dict[key], 0.25)
                q3 = np.quantile(op_dict[key], 0.75)
                iqr = q3 - q1

                for val in op_dict[key]:
                    iqrw = weight * iqr

                    if val > (q3 + iqrw):
                        continue
                    elif val < (q1 - iqrw):
                        continue
                    else:
                        tmp.append(val)
                
                data[entry][key] = tmp

    return data

def calc_statistics(out_op, in_op):
    stats = {
        'data_size': [],
        'mean_out': [], 'mean_in': [],
        'stdev_out': [], 'stdev_in': [],
        'median_out': [], 'median_in': [],
        'mode_out': [], 'mode_in': []
    }

    for key in out_op:
        stats['data_size'].append(key)

        mean = np.mean(out_op[key])
        stdev = np.std(out_op[key])
        median = np.median(out_op[key])
        mode = statistics.mode(out_op[key])

        stats['mean_out'].append(mean)
        stats['stdev_out'].append(stdev)
        stats['median_out'].append(median)
        stats['mode_out'].append(mode)

        mean = np.mean(in_op[key])
        stdev = np.std(in_op[key])
        median = np.median(in_op[key])
        mode = statistics.mode(in_op[key])

        stats['mean_in'].append(mean)
        stats['stdev_in'].append(stdev)
        stats['median_in'].append(median)
        stats['mode_in'].append(mode)

    return stats