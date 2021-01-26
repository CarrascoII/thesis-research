import csv
import matplotlib.pyplot as plt
import statistics
import numpy as np
import subprocess

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

def parse_alg_data(filename):
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

def parse_session_data(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[3:]
        data = {}

        for hdr in headers:
            data[hdr] = {}
            
            for endpoint in ['server', 'client']:
                data[hdr][endpoint] = []

        for row in csv_reader:
            endpoint = row['endpoint']

            for hdr in headers:
                val = int(row[hdr])

                if val != 0:
                    data[hdr][endpoint].append(val)
        
        return data, headers

########## PLOTTING UTILS ##########
def save_fig(fig, fname):
    fig.tight_layout()
    fig.savefig(fname)
    plt.close(fig)
    plt.cla()

def custom_errorbar(x, y, e, ax=None, title=None, xlabel='data_size', ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, fmt='.', capsize=5, barsabove=True, **kwargs)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)

    return(ax)

def multiple_custom_plots(x, y1, y2, ax=None, title=None, xlabel='data_size', ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()

    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

def custom_bar(y_list, yerr, ax=None, title=None, labels=[], xlabel='data_size', xtickslabels=None, ylabel=None):
    x_list = []

    if ax is None:
        ax = plt.gca()

    for i in range(len(y_list)):
        x = (i + (1 - len(y_list)))
        x_list.append(x)
        ax.bar(x, y_list[i], alpha=0.7, align='center', yerr=yerr[i], capsize=5)

    ax.set_xticks(x_list)
    ax.set_xticklabels(xtickslabels, rotation=60, ha='right', va='top')
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    # ax.legend()

    return(ax)

def multiple_custom_bar(y_list, width=0.25, ax=None, title=None, labels=[], xlabel='data_size', xtickslabels=None, ylabel=None):
    if ax is None:
        ax = plt.gca()

    x = np.arange(len(xtickslabels))
    x *= (len(y_list)//2 + 1)

    for i in range(len(y_list)):
        x1 = x + (i + (1 - len(y_list))/2)*width
        ax.bar(x1, y_list[i], width=width, label=labels[i])

    ax.set_xticks(x)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

def custom_scatter(x, y, ax=None, title=None, xlabel='data_size', xticks=None, xtickslabels=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)

    return(ax)

########## DATA ANALYSIS UTILS ##########
def filter_z_score(data, weight=2):
    keys = data.keys()

    for entry in keys:
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

def filter_iqr(data, weight=1.5):
    keys = data.keys()

    for entry in keys:
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

def calc_alg_statistics(data, hdr, stats_type):
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

def calc_session_statistics(data, hdr, stats_type):
    stats = {'keys': []}

    for stat in stats_type:
        stats[stat] = {}

    for key in data[hdr]:
        stats['keys'].append(key)

        for stat in stats_type:
            if stat == 'mean':
                stats['mean'][key] = np.mean(data[hdr][key])

            elif stat == 'stddev':
                stats['stddev'][key] = np.std(data[hdr][key])

            elif stat == 'median':
                stats['median'][key] = np.median(data[hdr][key])

            elif stat == 'mode':
                stats['mode'][key] = statistics.mode(data[hdr][key])

            else:
                print(f' {stat} is not an allowed type of statistic')
                return None

    return stats

########## PROFILLER UTILS ##########
def check_endpoint_ret(return_code, endpoint, ciphersuite, stdout, stderr, strlen):
    last_msg = [
        'Final status:',
        f'  -Suite being used:          {ciphersuite}'
    ]
    strout = stdout.decode('utf-8').strip('\n')
    last_out = strout.split('\n')[-2:]
    strerr = stderr.decode('utf-8').strip('\n')
    last_err = strerr.split('\n')

    print(f'\tChecking {endpoint} return code'.ljust(strlen, '.'), end=' ')

    if return_code != 0:
        print('error\n\tGot an unexpected return code!!!' + 
             f'\n\tDetails: {return_code}')
        return return_code

    if last_err[0] != '':
        print('error\n\tAn unexpected error occured!!!' +
             f'\n\tDetails:\n\t\t{last_err}')
        return -1

    for i in range(0, len(last_msg)):
        if last_msg[i] != last_out[i]:
            print('error\n\tLast message was not the expected one!!!' +
                 f'\n\t\tExpected:\n\t\t{last_msg[0]}\n\t\t{last_msg[1]}' +
                 f'\n\n\t\tObtained:\n\t\t{last_out[0]}\n\t\t{last_out[1]}')
            return -1

    print('ok')
    return return_code

def check_make_ret(return_code, stdout, stderr):
    strerr = stderr.decode('utf-8').strip('\n')
    last_err = strerr.split('\n')

    if return_code != 0:
        print('error\n\tCompilation failed!!!' + 
             f'\n\tDetails: {return_code}')
        return return_code

    if last_err[0] != '':
        print('error\n\tAn unexpected error occured!!!' +
             f'\n\tDetails:\n\t\t{last_err}')
        return -1

    print('ok')
    return return_code

def make_progs(target):
    args = ['make', '-C', '../l-tls', target]

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return check_make_ret(ret, stdout, stderr)