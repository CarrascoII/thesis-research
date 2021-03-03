import csv
import matplotlib.pyplot as plt
import statistics
import numpy as np
import subprocess

########## FILE PARSING UTILS ##########
def parse_ciphersuites(filename):
    with open(filename, 'r') as fl:
        return [line.strip() for line in fl.readlines()]

def write_ciphersuites(target, ciphersuites):
    with open('example/' + target + '_suites.txt', 'w') as fl:
        fl.writelines([f'{suite}\n' for suite in ciphersuites])

def parse_services(filename):
    with open(filename, 'r') as fl:
        algs = {'CONF': [], 'INT': [], 'AUTH': [], 'PFS': []}

        for line in fl.readlines():
            line = line.split(',')
            algs[line[0].strip()] += [line[1].strip()]

        ciphersuites = []

        for conf in algs['CONF']:
            for inte in algs['INT']:
                for auth in algs['AUTH']:
                    ciphersuites.append('TLS-' + auth + '-WITH-' + conf + '-' + inte)

                    for pfs in algs['PFS']:
                        ciphersuites.append('TLS-' + pfs + '-' + auth + '-WITH-' + conf + '-' + inte)

        return ciphersuites

def parse_services_grouped(filename, serv_set, ciphersuites):
    serv_dict = {}
    servs = {}

    for serv in serv_set:
        serv_dict[serv] = {}
        servs[serv.upper()] = []
         
    with open(filename, 'r') as fl:
        for line in fl.readlines():
            line = line.split(',')
            if line[0].strip() in list(servs.keys()):
                serv_dict[line[0].strip().lower()][line[1].strip()] = []
                servs[line[0].strip()] += [line[1].strip()]

        for suite in ciphersuites:
            for key in servs:
                for serv in servs[key]:
                    if key == 'CONF' and suite.find(serv) != -1:
                        serv_dict['conf'][serv].append(suite)
                        break
                    
                    elif key == 'INT' and suite.find(serv, len(suite) - len(serv)) != -1:
                        serv_dict['int'][serv].append(suite)
                        break

                    elif key == 'AUTH' and suite.find('TLS-' + serv + '-WITH') != -1:
                        serv_dict['auth'][serv].append(suite)
                        break

                    elif key == 'PFS' and suite.find('TLS-' + serv + '-') != -1:
                        serv_dict['pfs'][serv].append(suite)
                        break

        return serv_dict

def parse_algorithms(filename):
    with open(filename, 'r') as fl:
        algs = {'CIPHER': [], 'MD': [], 'KE': []}

        for line in fl.readlines():
            line = line.split(',')
            algs[line[0].strip()] += [line[1].strip()]

        ciphersuites = []

        for cipher in algs['CIPHER']:
            for md in algs['MD']:
                for ke in algs['KE']:
                    ciphersuites.append('TLS-' + ke + '-WITH-' + cipher + '-' + md)

        return ciphersuites

def parse_algorithms_grouped(filename, alg_set, ciphersuites):
    alg_dict = {}
    algs = {}

    for alg in alg_set:
        alg_dict[alg] = {}
        algs[alg.upper()] = []
         
    with open(filename, 'r') as fl:
        for line in fl.readlines():
            line = line.split(',')
            if line[0].strip() in list(algs.keys()):
                alg_dict[line[0].strip().lower()][line[1].strip()] = []
                algs[line[0].strip()] += [line[1].strip()]

        for suite in ciphersuites:
            for key in algs:
                for alg in algs[key]:
                    if key == 'CIPHER' and suite.find(alg) != -1:
                        alg_dict['cipher'][alg].append(suite)
                        break
                    
                    elif key == 'MD' and suite.find(alg, len(suite) - len(alg)) != -1:
                        alg_dict['md'][alg].append(suite)
                        break

                    elif key == 'KE' and suite.find('TLS-' + alg + '-WITH') != -1:
                        alg_dict['ke'][alg].append(suite)
                        break

        return alg_dict

def parse_ke(ciphersuites):
    ke = []

    for suite in ciphersuites:
        i = suite.find('-WITH')
        tmp = suite[4:i]

        if tmp not in ke:
            ke.append(tmp)

    return ke

def parse_record_data(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[3:]
        data = {}
        sub_keys = []

        for hdr in headers:
            for ext in ['_out', '_in']:
                sub_keys.append(hdr + ext)

        for row in csv_reader:
            data_size = row['data_size']
            operation = row['operation']

            if data_size not in data.keys():
                data[data_size] = {}
                
                for sub in sub_keys:
                    data[data_size][sub] = []

            for hdr in headers:
                val = int(row[hdr])

                if val != 0:
                    if operation == 'encrypt' or operation == 'digest':
                        hdr += '_out'

                    elif operation == 'decrypt' or operation == 'verify':
                        hdr += '_in'
                        
                    data[data_size][hdr].append(val)

        return data, headers

def parse_handshake_data(filename, index=1):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[index:]
        data = {}

        for endpoint in ['server', 'client']:
            data[endpoint] = {}

            for hdr in headers:
                data[endpoint][hdr] = []

        for row in csv_reader:
            endpoint = row['endpoint']

            for hdr in headers:
                val = int(row[hdr])

                if val != 0:
                    data[endpoint][hdr].append(val)
        
        return data, headers

def write_alg_csv(filename, stats):
    hdrs = list(stats.keys())
    keys = stats['keys']
    lines = []
    line = ''

    for hdr in hdrs:
        line += hdr + ','

    line = line.replace('keys', 'data_size')

    if filename.find('cipher') != -1:
        line = line.replace('out', 'encrypt')
        line = line.replace('in', 'decrypt')

    elif filename.find('md') != -1:
        line = line.replace('out', 'hash')
        line = line.replace('in', 'verify')

    lines.append(line[:-1] + '\n')

    for i in range(len(keys)):
        line = ''

        for hdr in hdrs:
            line += str(stats[hdr][i]) + ','

        lines.append(line[:-1] + '\n')

    with open(filename, 'w') as fl:
        fl.writelines(lines)

def write_record_cmp_csv(path, all_stats):
    lines = {'out': [], 'in': []}
    keys = []
    line = 'ciphersuite,data_size,'
    operation = []

    for suite in all_stats:
        for key in all_stats[suite]:
            if key.find('out') != -1:
                keys.append(key[:-4])
                line += key[:-4] + ','

        break

    for end in lines:
        lines[end].append(line[:-1] + '\n')

    for suite in all_stats:
        for end in lines:
            line = suite + ','

            for i in range(len(all_stats[suite]['keys'])):
                sub = line + str(all_stats[suite]['keys'][i]) + ','

                for key in keys:
                    sub += str(all_stats[suite][key + '_' + end][i]) + ','

                lines[end].append(sub[:-1] + '\n')

    if path.find('cipher') != -1:
        operation = ['encrypt', 'decrypt']

    elif path.find('md') != -1:
        operation = ['hash', 'verify']

    for end, op in zip(lines, operation):
        with open(path + op + '_statistics.csv', 'w') as fl:
            fl.writelines(lines[end])

def write_handshake_cmp_csv(path, all_stats):
    lines = {'server': [], 'client': []}
    line = ''

    for suite in all_stats:
        for key in all_stats[suite]:
            line += key + ','
        break

    line = line.replace('keys', 'ciphersuite')
    for end in lines:
        lines[end].append(line[:-1] + '\n')

    for suite in all_stats:
        for i, end in zip(range(len(lines.keys())), lines):
            line = suite + ','

            for key in list(all_stats[suite].keys())[1:]:
                line += str(all_stats[suite][key][i]) + ','

            lines[end].append(line[:-1] + '\n')

    for end in lines:
        with open(path + end + '_statistics.csv', 'w') as fl:
            fl.writelines(lines[end])

def assign_target(ciphersuites, filename):
    with open(filename, 'r') as fl:
        exec_dict = {}
        rem_lst = []        

        for line in fl.readlines():
            line = line.split(',')
            target = line[0].strip()
            tls = 'TLS-' + line[1].strip() + '-WITH'
            tmp = ciphersuites.copy()

            if target not in exec_dict.keys():
                exec_dict[target] = []

            for suite in ciphersuites:
                if suite.find(tls) != -1:
                    exec_dict[target].append(suite)
                    tmp.remove(suite)

            ciphersuites = tmp.copy()

        for key in exec_dict:
            if len(exec_dict[key]) == 0:
                rem_lst.append(key)

        for key in rem_lst:
            exec_dict.pop(key)

        return exec_dict

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

def custom_plots(x, y1, y2, ax=None, title=None, xlabel='data_size', ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()

    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()
    return(ax)

def multiple_custom_plots(x, y_lst, ax=None, title=None, xlabel='data_size', ylabel=None, kwargs_lst=None):
    if ax is None:
        ax = plt.gca()

    for y, kwargs in zip(y_lst, kwargs_lst):
        ax.plot(x, y, **kwargs)

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
    return(ax)

def grouped_custom_bar(y_list, yerr, ax=None, title=None, labels=[], label_lim=0, xlabel='data_size', xtickslabels=None, ylabel=None):
    x_list = [0]

    if ax is None:
        ax = plt.gca()

    for i in range(len(y_list)):
        x_list.append(x_list[-1] + (len(y_list[i]) + len(y_list[i+1]))/2)

        if len(x_list) == len(y_list):
            break

    for x, y, err, label in zip(x_list, y_list, yerr, labels):
        x1 = [x + (i + (1 - len(y))/2) for i in range(len(y))]
        ax.bar(x1, y, yerr=err, capsize=2)

        for i, j1, j2, s in zip(x1, y, err, label):
            ax.text(i - 0.35, j1 + j2 + label_lim/100, s, rotation=90)

    ax.set_xticks(x_list)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    return(ax)

def multiple_custom_bar(y_list, yerr, width=0.5, ax=None, title=None, labels=[], xlabel='data_size', xtickslabels=None, ylabel=None):
    x = np.arange(len(xtickslabels))
    x *= (len(y_list)//2 + 1)

    if ax is None:
        ax = plt.gca()

    for i in range(len(y_list)):
        x1 = x + (i + (1 - len(y_list))/2)*width
        ax.bar(x1, y_list[i], width=width, label=labels[i], yerr=yerr[i], capsize=6*width)

    ax.set_xticks(x)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()
    return(ax)

def custom_scatter(x, y, ax=None, title=None, xlabel='data_size', xtickslabels=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(np.arange(len(xtickslabels)))
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    return(ax)

########## DATA ANALYSIS UTILS ##########
def filter_z_score(data, weight=2):
    for key in data:
        sub_dict = data[key]
        
        for sub in sub_dict:
            tmp = []
            mean = np.mean(sub_dict[sub])
            stdev = np.std(sub_dict[sub])

            for val in sub_dict[sub]:
                stdw = weight * stdev

                if val > (mean + stdw):
                    continue

                elif val < (mean - stdw):
                    continue

                else:
                    tmp.append(val)
            
            data[key][sub] = tmp

    return data

def filter_iqr(data, weight=1.5):
    for key in data:
        sub_dict = data[key]

        for sub in sub_dict:
            tmp = []
            q1 = np.quantile(sub_dict[sub], 0.25)
            q3 = np.quantile(sub_dict[sub], 0.75)
            iqr = q3 - q1

            for val in sub_dict[sub]:
                iqrw = weight * iqr

                if val > (q3 + iqrw):
                    continue

                elif val < (q1 - iqrw):
                    continue

                else:
                    tmp.append(val)
            
            data[key][sub] = tmp

    return data

def calc_pfs_statistics(data, alt_data, stats_type, hdrs):
    for key in data:
        for sub in data[key]:
            m = len(data[key][sub])
            n = len(alt_data[key][sub])

            if n < m:
                m = n
            elif n == m:
                continue

            data[key][sub] = data[key][sub][:m]
            alt_data[key][sub] = alt_data[key][sub][:m]
        
    stats = calc_statistics(data, stats_type)
    alt_stats = calc_statistics(alt_data, stats_type)

    for key in list(stats.keys())[1:]:
        for hdr in hdrs:
            if key == 'mean_' + hdr:
                for i in range(len(stats['keys'])):
                    stats[key][i] = stats[key][i] - alt_stats[key][i]
            
            elif key == 'stddev_' + hdr:
                for end in stats['keys']:
                    idx = stats['keys'].index(end) 
                    cov = np.cov([data[end][hdr], alt_data[end][hdr]])
                    v = np.square(stats[key][idx]) + np.square(alt_stats[key][idx]) - 2*cov[0][1]
                    stats[key][idx] = np.sqrt(v)

    return stats

def calc_statistics(data, stats_type):
    stats = {'keys': list(data.keys())}
    ops = {
        'mean': np.mean,
        'stddev': np.std,
        'median':np.median,
        'mode': statistics.mode
    }

    for sub in data[stats['keys'][0]]:
        for stat in stats_type:
            stats[stat + '_' + sub] = []

    for key in data:
        for sub in data[key]:
            for stat in stats_type:
                try:
                    stats[stat + '_' + sub].append(ops[stat](data[key][sub]))

                except:
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

    print(f'    Checking {endpoint} return code'.ljust(strlen, '.'), end=' ', flush=True)

    if return_code != 0:
        print(f'error\n    Got an unexpected return code!!!\n    Details: {return_code}')
        return return_code

    if last_err[0] != '':
        print(f'error\n    An unexpected error occured!!!\n    Details:\n        {last_err}')
        return -1

    for i in range(0, len(last_msg)):
        if last_msg[i] != last_out[i]:
            print('error\n    Last message was not the expected one!!!' +
                 f'\n        Expected:\n        {last_msg[0]}\n        {last_msg[1]}' +
                 f'\n\n        Obtained:\n        {last_out[0]}\n        {last_out[1]}')
            return -1

    print('ok')
    return return_code

def check_make_ret(return_code, stdout, stderr):
    strerr = stderr.decode('utf-8').strip('\n')
    last_err = strerr.split('\n')

    if return_code != 0:
        print(f'error\n    Compilation failed!!!\n    Details: {return_code}')
        return return_code

    if last_err[0] != '':
        print(f'error\n    An unexpected error occured!!!\n    Details:\n        {last_err}')
        return -1

    print('ok')
    return return_code

def make_progs(target):
    args = ['make', '-C', '../l-tls', target]
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return check_make_ret(ret, stdout, stderr)