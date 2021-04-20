import csv
import matplotlib.pyplot as plt
import statistics
import numpy as np
import subprocess
import settings

########## FILE PARSING UTILS ##########
def parse_ciphersuites(filename):
    with open(filename, 'r') as fl:
        return [line.strip() for line in fl.readlines()]

def write_ciphersuites(target, ciphersuites):
    with open('examples/' + target + '_suites.txt', 'w') as fl:
        fl.writelines([f'{suite}\n' for suite in ciphersuites])

def parse_algorithms(filename):
    with open(filename, 'r') as fl:
        algs = {'CIPHER': [], 'MD': [], 'KE': []}
        ciphersuites = []

        for line in fl.readlines():
            line = line.split(',')
            algs[line[0].strip()] += [line[1].strip()]

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

def parse_services(filename):
    with open(filename, 'r') as fl:
        algs = {'CONF': [], 'INT': [], 'AUTH': [], 'KE': [], 'PFS': []}

        for line in fl.readlines():
            line = line.split(',')
            algs[line[0].strip()] += [line[1].strip()]

        ciphersuites = []

        for conf in algs['CONF']:
            for inte in algs['INT']:
                for auth in algs['AUTH']:
                    suite = 'TLS-' + auth + '-WITH-' + conf + '-' + inte
                    
                    if suite not in ciphersuites:
                        ciphersuites.append(suite)

                    for ke in algs['KE']:
                        if ke == 'PSK':
                            suite = 'TLS-' + auth + '-PSK-WITH-' + conf + '-' + inte
                        else:
                            suite = 'TLS-' + ke + '-' + auth + '-WITH-' + conf + '-' + inte

                        if suite not in ciphersuites:
                            ciphersuites.append(suite)

                    for pfs in algs['PFS']:
                        suite = 'TLS-' + pfs + '-' + auth + '-WITH-' + conf + '-' + inte

                        if suite not in ciphersuites:
                            ciphersuites.append(suite)

        return ciphersuites

def parse_services_grouped(filename, serv_set, ciphersuites):
    serv_dict = {}
    alg_conv = {}

    for serv in serv_set:
        serv_dict[serv] = {}

    with open(filename, 'r') as fl:
        for line in fl.readlines():
            line = line.split(',')
            serv = line[0].strip()
            alg = line[1].strip()

            if serv.lower() not in list(serv_dict.keys()):
                continue

            elif serv not in list(alg_conv.keys()):
                alg_conv[serv.upper()] = []

            serv_dict[serv.lower()][alg] = []
            alg_conv[serv] += [alg]

        for suite in ciphersuites:
            for serv in alg_conv:
                for alg in alg_conv[serv]:
                    if suite.find('-' + alg + '-') != -1:
                        serv_dict[serv.lower()][alg].append(suite)
                    
                    elif serv == 'INT' and suite.find(alg, len(suite) - len(alg)) != -1:
                        serv_dict[serv.lower()][alg].append(suite)

            if 'hs' in serv_dict:
                alg = suite[4:suite.find('-WITH')]

                if alg not in list(serv_dict['hs'].keys()):
                    serv_dict['hs'][alg] = []
                
                serv_dict['hs'][alg].append(suite)

        return serv_dict

def parse_record_data(filename, alg, serv=None):
    if serv != None:
        alg = settings.serv_to_alg[serv]

    with open(filename, mode='r') as fl:
        opts = settings.alg_parser_opts[alg]
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[opts[0]:]
        data = {}
        sub_keys = []

        for hdr in headers:
            for end in settings.alg_labels[alg]:
                sub_keys.append(hdr + '_' + end)

        for row in csv_reader:
            key = row[opts[1]]
            operation = row[opts[2]]

            if key not in data.keys():
                data[key] = {}
                
                for sub in sub_keys:
                    data[key][sub] = []

            for hdr in headers:
                val = int(row[hdr])

                if val != 0:
                    hdr += '_' + operation
                    data[key][hdr].append(val)

        return data, headers

def parse_handshake_data(filename, alg, serv):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[4:]
        avail_op = settings.ke_operations_per_service[serv]
        data = {}
        sub_keys = []
        row_lst = []
        curr_test = 0

        for hdr in headers:
            for end in settings.serv_labels[serv]:
                sub_keys.append(hdr + '_' + end)

        for row in csv_reader:
            test_id = int(row['test_id'])

            if test_id == curr_test:
                row_lst.append(row)
                key = row['keylen']

                if key not in data.keys():
                    data[key] = {}
                
                    for sub in sub_keys:
                        data[key][sub] = []

            else:
                curr_test = test_id
                all_val = {}

                for sub in sub_keys:
                    all_val[sub] = 0

                for elem in row_lst:
                    operation = elem['operation']

                    if operation in avail_op[alg]:
                        for hdr in headers:
                            val = int(elem[hdr])

                            if serv == 'auth':
                                hdr += '_' + elem['endpoint']
                            else:
                                hdr += '_' + settings.serv_labels[serv][0]

                            all_val[hdr] += val

                for sub in all_val:
                    if all_val[sub] != 0:
                        data[row_lst[0]['keylen']][sub].append(all_val[sub])

                row_lst = []

        return data, headers

def parse_overhead_data(filename, alg, serv):
    hs_fname = None
    hs_data = None
    hs_hdrs = None
    idx = 4 if filename.find('ke_data.csv') != -1 else 3

    if filename.find('/ke_data.csv') != -1:
        hs_fname = filename.replace('/ke', '/handshake')
        hs_data, hs_hdrs = parse_overhead_data(hs_fname, alg, serv)

    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[idx:]
        data = {}
        sub_keys = []
        row_lst = []
        curr_test = 0

        for hdr in headers:
            for end in settings.serv_labels[serv]:
                sub_keys.append(hdr + '_' + end)

        for row in csv_reader:
            test_id = int(row['test_id'])

            if test_id == curr_test:
                row_lst.append(row)
                key = row['keylen']

                if key not in data.keys():
                    data[key] = {}
                
                    for sub in sub_keys:
                        data[key][sub] = []

            else:
                curr_test = test_id
                all_val = {}

                for sub in sub_keys:
                    all_val[sub] = 0

                for elem in row_lst:
                    for hdr in headers:
                        all_val[hdr + '_' + settings.serv_labels[serv][0]] += int(elem[hdr])

                for sub in all_val:
                    data[row_lst[0]['keylen']][sub].append(all_val[sub])

                row_lst = []

        if hs_fname != None and list(data.keys()) == list(hs_data.keys()) and headers == hs_hdrs:
            for keylen in data:
                for sub in sub_keys:
                    for i in range(len(data[keylen][sub])):
                        hs_data[keylen][sub][i] -= data[keylen][sub][i]

        return data, headers

def parse_session_data(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[2:]
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

def write_alg_csv(filename, labels, stats):
    hdrs = list(stats.keys())
    keys = stats['keys']
    lines = []
    line = ''

    for hdr in hdrs:
        line += hdr + ','

    line = line.replace('keys', 'msglen')
    line = line.replace('out', labels[0])
    line = line.replace('in', labels[1])
    lines.append(line[:-1] + '\n')

    for i in range(len(keys)):
        line = ''

        for hdr in hdrs:
            line += str(stats[hdr][i]) + ','

        lines.append(line[:-1] + '\n')

    with open(filename, 'w') as fl:
        fl.writelines(lines)

def write_alg_cmp_csv(path, hdr, alg, all_stats):
    labels = settings.alg_labels[alg]
    lines = {}
    keys = []
    line = hdr + ',' + settings.alg_parser_opts[alg][1] + ','
    elem = next(iter(all_stats.values()))

    for end in labels:
        lines[end] = []

    for key in elem:
        if key.find(labels[0]) != -1:
            idx = len(labels[0]) + 1
            keys.append(key[:-idx])
            line += key[:-idx] + ','

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

    for end, label in zip(lines, labels):
        with open(path + label + '_statistics.csv', 'w') as fl:
            fl.writelines(lines[end])

def write_serv_cmp_csv(path, hdr, serv, all_stats):
    labels = settings.serv_labels[serv]
    alg = settings.serv_to_alg[serv]
    lines = {}
    keys = []
    line = hdr + ',' + settings.alg_parser_opts[alg][1] + ','
    elem = next(iter(all_stats.values()))

    for end in labels:
        lines[end] = []

    for key in elem:
        if key.find(labels[0]) != -1:
            idx = len(labels[0]) + 1
            keys.append(key[:-idx])
            line += key[:-idx] + ','

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

    for end, label in zip(lines, labels):
        with open(path + label + '_statistics.csv', 'w') as fl:
            fl.writelines(lines[end])

def write_session_cmp_csv(path, all_stats):
    lines = {'client': [], 'server': []}
    line = 'ciphersuite,'
    elem = next(iter(all_stats.values()))

    for key in list(elem.keys())[1:]:
        line += key + ','

    for key in lines:
        lines[key].append(line[:-1] + '\n')

    for key in all_stats:
        for i, end in enumerate(elem['keys']):
            line = key + ','

            for sub in list(all_stats[key].keys())[1:]:
                line += str(all_stats[key][sub][i]) + ','

            lines[end].append(line[:-1] + '\n')

    for key in lines:
        with open(path + key + '_statistics.csv', 'w') as fl:
            fl.writelines(lines[key])

def get_ke_algs(ciphersuites):
    ke = []

    for suite in ciphersuites:
        i = suite.find('-WITH')
        tmp = suite[4:i]

        if tmp not in ke:
            ke.append(tmp)

    return ke

########## PLOTTING UTILS ##########
def save_fig(fig, fname):
    fig.tight_layout()
    fig.savefig(fname)
    plt.close(fig)
    plt.cla()

def custom_errorbar(x, y, e, ax=None, title=None, xlabel='msglen', ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, fmt='.', capsize=5, barsabove=True, **kwargs)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    return(ax)

def custom_plots(x, y1, y2, ax=None, title=None, xlabel='msglen', ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()

    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()
    return(ax)

def multiple_custom_plots(x, y_lst, ax=None, title=None, xlabel='msglen', ylabel=None, kwargs_lst=None):
    if ax is None:
        ax = plt.gca()

    for y, kwargs in zip(y_lst, kwargs_lst):
        ax.plot(x, y, **kwargs)

    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()
    return(ax)

def custom_bar(y_list, yerr, ax=None, title=None, labels=[], xlabel='msglen', xtickslabels=None, ylabel=None):
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

def grouped_custom_bar(y_list, yerr, ax=None, title=None, labels=[], label_lim=0, xlabel='msglen', xtickslabels=None, ylabel=None):
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

def multiple_custom_bar(y_list, yerr, width=0.5, ax=None, title=None, labels=[], xlabel='msglen', xtickslabels=None, ylabel=None):
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

def custom_scatter(x, y, ax=None, title=None, xlabel='msglen', xtickslabels=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(np.arange(len(xtickslabels)))
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    return(ax)

########## DATA ANALYSIS UTILS ##########
# def filter_z_score(data, weight=2):
#     for key in data:
#         sub_dict = data[key]
        
#         for sub in sub_dict:
#             tmp = []
#             mean = np.mean(sub_dict[sub])
#             stdev = np.std(sub_dict[sub])

#             for val in sub_dict[sub]:
#                 stdw = weight * stdev

#                 if val > (mean + stdw):
#                     continue

#                 elif val < (mean - stdw):
#                     continue

#                 else:
#                     tmp.append(val)
            
#             data[key][sub] = tmp

#     return data

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

    for i in range(0, len(last_out)):
        if last_msg[i] != last_out[i]:
            print('error\n    Last message was not the expected one!!!\n      Expected:')
            for j in range(len(last_out)):
                print(f'\n        {last_msg[j]}')

            print(f'\n      Obtained:')
            for j in range(len(last_out)):
                print(f'\n        {last_out[j]}')

            return -1

    print('ok')
    return return_code

def make_progs(target):
    args = ['make', '-C', '../l-tls', target]
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode
    strerr = stderr.decode('utf-8').strip('\n')
    last_err = strerr.split('\n')

    if ret != 0:
        print(f'error\n    Compilation failed!!!\n    Details: {ret}')
        return ret

    if last_err[0] != '':
        print(f'error\n    An unexpected error occured!!!\n    Details:\n        {last_err}')
        return -1

    print('ok')
    return ret
