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

def multiple_custom_bar(y_list, width=0.25, ax=None, title=None, labels=[], xtickslabels=None, ylabel=None):
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

def calc_statistics(data, hdr, stats_type):
    stats = {'data_size': []}

    for stat in stats_type:
        stats[stat + '_out'] = []
        stats[stat + '_in'] = []

    for key in data[hdr + '_out']:
        stats['data_size'].append(key)

        for stat in stats_type:
            if stat == 'mean':
                stats['mean_out'].append(np.mean(data[hdr + '_out'][key]))
                stats['mean_in'].append(np.mean(data[hdr + '_in'][key]))

            elif stat == 'stddev':
                stats['stddev_out'].append(np.std(data[hdr + '_out'][key]))
                stats['stddev_in'].append(np.std(data[hdr + '_in'][key]))

            elif stat == 'median':
                stats['median_out'].append(np.median(data[hdr + '_out'][key]))
                stats['median_in'].append(np.median(data[hdr + '_in'][key]))

            elif stat == 'mode':
                stats['mode_out'].append(statistics.mode(data[hdr + '_out'][key]))
                stats['mode_in'].append(statistics.mode(data[hdr + '_in'][key]))

            else:
                print(f' {stat} is not an allowed type of statistic')
                return None

    return stats