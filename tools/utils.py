import os
import subprocess
from csv import DictReader
from statistics import mode
from copy import deepcopy
import numpy as np
import matplotlib.pyplot as plt
import settings

########## FILE PARSING UTILS ##########
def parse_ciphersuites(filename):
    with open(filename, 'r') as fl:
        return [line.strip() for line in fl.readlines()]

def group_ciphersuites(suites, serv_set):
    groups = {}
    tmp = []
    rem = []

    for serv in serv_set:
        for alg in settings.ke_operations_per_service[serv]:
            if alg not in tmp:
                tmp.append(alg)

    # print(f'{tmp}')

    for suite in suites:
        alg = suite[4:suite.find('-WITH')]

        if alg not in list(groups.keys()):
            groups[alg] = []
        
        groups[alg].append(suite)

    # print(f'before: {list(groups.keys())}')

    for key in groups:
        keep = False
        algs = key.split('-')

        for alg in algs:
            # if alg not in tmp:
            #     rem.append(key)
            if alg in tmp:
                keep = True
                keep = True
                break

        if keep == False:
            rem.append(key)

    for key in rem:
        groups.pop(key)

    # print(f'after:  {list(groups.keys())}')

    return groups

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

        if serv == 'ke':
            serv_dict[serv]['SHA256'] = []
            serv_dict[serv]['SHA384'] = []

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

                if serv == 'KE': 
                    if suite.find('SHA384', len(suite) - 6) != -1:
                        serv_dict[serv.lower()]['SHA384'].append(suite)

                    else:
                        serv_dict[serv.lower()]['SHA256'].append(suite)

        return serv_dict

def parse_record_data(filename, alg, serv=None):
    if serv != None:
        alg = settings.serv_to_alg[serv]

    fnames = []
    opts = settings.alg_parser_opts[alg]
    data = {}

    for end in ['srv_', 'cli_']:
        fnames.append(filename + end + alg + '_data.csv')

    for fname in fnames:
        sub_keys = []
        
        with open(fname, mode='r') as fl:
            csv_reader = DictReader(fl)
            headers = csv_reader.fieldnames[opts[0]:]

            for hdr in headers:
                for end in settings.alg_labels[alg]:
                    sub_keys.append(hdr + '_' + end)

            for row in csv_reader:
                msglen = row[opts[1]]
                operation = row[opts[2]]

                if msglen not in data.keys():
                    data[msglen] = {}
                    
                    for sub in sub_keys:
                        data[msglen][sub] = []

                for hdr in headers:
                    val = int(row[hdr])

                    if val != 0:
                        hdr += '_' + operation
                        data[msglen][hdr].append(val)

    return data, headers

def parse_handshake_data(filename, alg, serv=None):
    fnames = []
    data = {}
    label = alg if serv == None else settings.serv_to_alg[serv]
    avail_op = None if serv == None else settings.ke_operations_per_service[serv]
    opts = settings.alg_parser_opts[label]

    for end in ['srv_', 'cli_']:
        fnames.append(filename + end + label + '_data.csv')

    for fname, endpoint in zip(fnames, settings.alg_labels[label]):
        sub_keys = []
        
        with open(fname, mode='r') as fl:
            csv_reader = DictReader(fl)
            headers = csv_reader.fieldnames[opts[0]:]
            row_dict = {}

            for hdr in headers:
                sub_keys.append(hdr + '_' + endpoint)

            for row in csv_reader:
                if serv == None or row['operation'] in avail_op[alg]:
                    test_id = int(row['test_id'])
                    sec_lvl = row['sec_lvl']

                    if sec_lvl not in data.keys():
                        data[sec_lvl] = {}

                    if sec_lvl not in row_dict:
                        row_dict[sec_lvl] = {}

                    if test_id not in row_dict[sec_lvl]:
                        row_dict[sec_lvl][test_id] = []

                    row_dict[sec_lvl][test_id].append(row)

            for sec_lvl in row_dict:
                for test_id in row_dict[sec_lvl]:
                    all_val = {}

                    for sub in sub_keys:
                        all_val[sub] = 0

                        if sub not in data[sec_lvl].keys():
                            data[sec_lvl][sub] = []

                    for row in row_dict[sec_lvl][test_id]:
                        for hdr in headers:
                            all_val[hdr + '_' + endpoint] += int(row[hdr])

                    for sub in all_val:
                        data[sec_lvl][sub].append(all_val[sub])

    return data, headers

def parse_servs_data(filename, algs, servs):
    data = {}
    ke_opts = settings.alg_parser_opts['ke']
    alg_lst = algs.split('-')

    if filename.find('SHA384', len(filename) - 6) != -1:
        alg_lst.append('SHA384')
    else:
        alg_lst.append('SHA256')

    for ext, endpoint in zip(['srv_', 'cli_'], ['server', 'client']):
        fname = filename + ext + 'ke_data.csv'
        sub_keys = []

        with open(fname, mode='r') as fl:
            csv_reader = DictReader(fl)
            headers = csv_reader.fieldnames[ke_opts[0]:]
            row_dict = {}

            for hdr in headers:
                sub_keys.append(hdr + '_' + endpoint)

            for row in csv_reader:
                sec_lvl = row['sec_lvl']
                tmp = sec_lvl
                test_id = int(row['test_id'])
                operation = row['operation']

                for serv in servs:
                    for alg in alg_lst:
                        try:
                            if operation in settings.ke_operations_per_service[serv][alg]:
                                tmp = alg + '_' + tmp
                        
                        except KeyError:
                            continue

                if tmp == sec_lvl:
                    continue

                else:
                    sec_lvl = tmp

                if sec_lvl not in data.keys():
                    data[sec_lvl] = {}

                if sec_lvl not in row_dict:
                    row_dict[sec_lvl] = {}

                if test_id not in row_dict[sec_lvl]:
                    row_dict[sec_lvl][test_id] = []

                row_dict[sec_lvl][test_id].append(row)

            for sec_lvl in row_dict:
                for test_id in row_dict[sec_lvl]:
                    all_val = {}

                    for sub in sub_keys:
                        all_val[sub] = 0

                        if sub not in data[sec_lvl].keys():
                            data[sec_lvl][sub] = []

                    for row in row_dict[sec_lvl][test_id]:
                        for hdr in headers:
                            all_val[hdr + '_' + endpoint] += int(row[hdr])

                    for sub in all_val:
                        data[sec_lvl][sub].append(all_val[sub])

    return data, headers

def get_extra_labels(filename, algs, servs):
    fname = filename + 'srv_ke_data.csv'
    alg_lst = algs.split('-')
    labels = []

    if filename.find('SHA384', len(filename) - 6) != -1:
        alg_lst.append('SHA384')
    else:
        alg_lst.append('SHA256')

    with open(fname, mode='r') as fl:
        csv_reader = DictReader(fl)

        for row in csv_reader:
            test_id = int(row['test_id'])
            operation = row['operation']

            if test_id != 0:
                break

            for serv in servs:
                for alg in alg_lst:
                    try:
                        if operation in settings.ke_operations_per_service[serv][alg]:
                            if serv == 'auth':
                                if operation == 'rsa_decrypt':
                                    labels.append('D')

                                elif operation in ['rsa_sign_with_sha512', 'ecdsa_sign_with_sha512']:
                                    labels.append('E')

                                else:
                                    labels.append('A')

                            elif serv == 'ke':
                                labels.append('B')

                            elif serv == 'pfs':
                                labels.append('C')

                            break

                    except KeyError:
                        continue

    labels = sorted(list(dict.fromkeys(labels)))

    return labels

def parse_session_data(filename):
    data = {}

    for ext, endpoint in zip(['srv_', 'cli_'], ['server', 'client']):
        fname = filename + ext + 'session_data.csv'

        with open(fname, mode='r') as fl:
            csv_reader = DictReader(fl)
            headers = csv_reader.fieldnames[1:]
            data[endpoint] = {}

            for hdr in headers:
                data[endpoint][hdr] = []

            for row in csv_reader:
                for hdr in headers:
                    val = int(row[hdr])

                    if val != 0:
                        data[endpoint][hdr].append(val)
        
    return data, headers

def make_path(path):    
    tmp = ''

    for val in path.split('/'):
        tmp += val + '/'

        if not os.path.exists(tmp):
            os.mkdir(tmp)

def write_alg_csv(path, alg, labels, stats):
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

    make_path(path)

    with open(path + alg + '.csv', 'w') as fl:
        fl.writelines(lines)

def write_alg_cmp_csv(path, type, hdr, alg, all_stats):
    labels = settings.alg_labels[alg]
    lines = {}
    keys = []
    line = hdr + ',' + settings.alg_parser_opts[alg][1] + ','
    elem = deepcopy(next(iter(all_stats.values())))

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

    make_path(path)

    for end, label in zip(lines, labels):
        with open(path + type + '_' + alg + '_' + label + '.csv', 'w') as fl:
            fl.writelines(lines[end])

def write_serv_cmp_csv(path, hdr, serv, all_stats):
    labels = settings.serv_labels[serv]
    alg = settings.serv_to_alg[serv]
    lines = {}
    keys = []
    line = hdr + ',' + settings.alg_parser_opts[alg][1] + ','
    elem = deepcopy(next(iter(all_stats.values())))

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

    make_path(path)

    for end, label in zip(lines, labels):
        with open(path + 'serv_' + serv + '_' + label + '.csv', 'w') as fl:
            fl.writelines(lines[end])

def write_suite_servs_cmp_csv(path, hdr, all_stats, stype):
    labels = settings.serv_labels['ke']
    lines = {}
    keys = []
    line = hdr + ','

    for end in labels:
        lines[end] = []

    for alg in all_stats:
        for serv in all_stats[alg]['keys']:
            if serv not in keys:
                keys.append(serv)

    keys.sort()

    for serv in keys:
        line += serv + ','

    for end in lines:
        lines[end].append(line[:-1] + '\n')

    for alg in all_stats:
        entries = []

        for key in all_stats[alg]:
            if key.find(stype) != -1:
                entries.append(key)

        for end, entry in zip(lines, entries):
            sub = alg + ','
            tmp = {}

            for key, val in zip(all_stats[alg]['keys'], all_stats[alg][entry]):
                tmp[key] = val

            for key in keys:
                try:
                    sub += str(tmp[key]) + ','

                except KeyError:
                    sub += '0,'

            lines[end].append(sub[:-1] + '\n')

    make_path(path)

    for end, label in zip(lines, labels):
        with open(path + 'serv_all_' + label + '_' + stype + '.csv', 'w') as fl:
            fl.writelines(lines[end])

def write_session_cmp_csv(path, all_stats):
    lines = {'client': [], 'server': []}
    line = 'ciphersuite,'
    elem = deepcopy(next(iter(all_stats.values())))

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

def write_config_values_csv(path, hdr, all_values):
    labels = {'hs': settings.serv_labels['ke'], 'rec': ['out', 'in']}
    tags = {'hs': 'security bits', 'rec': 'message size (bits)'}
    lines = {}
    keys = {}
    tmp = deepcopy(next(iter(all_values)))

    for serv in all_values[tmp]:
        lines[serv] = {}

        for end in labels[serv]:
            lines[serv][end] = []

    for serv in all_values[tmp]:
        keys[serv] = []
        idx = len(labels[serv][0]) + 1

        for key in all_values[tmp][serv]:
            if key.find(labels[serv][0]) != -1:
                keys[serv].append(key[:-idx])

    for serv in keys:
        line = hdr + ',' + tags[serv] + ','
        
        for val in keys[serv]:
            line += val + ','

        for end in lines[serv]:
            lines[serv][end].append(line[:-1] + '\n')

    # print('')
    for serv in keys:
        # print(f'{serv}:')
        for suite in all_values:
            # print(f'  {suite}:')
            for end in labels[serv]:
                # print(f'    {end}:')
                line = suite + ','

                for id in range(len(all_values[suite][serv]['keys'])):
                    # print(f'      {id}:')
                    new = line + all_values[suite][serv]['keys'][id] + ','

                    for key in keys[serv]:
                        try:
                            # print(f'        {key}: {all_values[suite][serv][key + "_" + end][id]}')
                            new += str(all_values[suite][serv][key + '_' + end][id]) + ','
                        
                        except KeyError:
                            new += '0,'

                    lines[serv][end].append(new[:-1] + '\n')

    make_path(path)

    for serv in lines:
        for end in labels[serv]:
            with open(path + 'serv_config_' + serv + '_' + end + '.csv', 'w') as fl:
                fl.writelines(lines[serv][end])

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

def custom_errorbar(x, y, e, ax, title=None, xlabel='msglen', ylabel=None, kwargs={}):
    ax.errorbar(x, y, yerr=e, fmt='.', capsize=5, barsabove=True, **kwargs)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    return(ax)

def custom_plots(x, y1, y2, ax, title=None, xlabel='msglen', ylabel=None, kwargs1={}, kwargs2={}):
    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()
    return(ax)

def multiple_custom_plots(x, y_lst, ax, title=None, xlabel='msglen', ylabel=None, kwargs_lst=None):
    for y, kwargs in zip(y_lst, kwargs_lst):
        ax.plot(x, y, **kwargs)

    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()
    return(ax)

def grouped_custom_bar(y_list, yerr, ax, title=None, labels=[], label_lim=0, xlabel='msglen', xtickslabels=None, ylabel=None):
    x_list = [0]

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

def multiple_custom_bar(y_list, yerr, ax, width=0.5, title=None, labels=[], xlabel='msglen', xtickslabels=None, ylabel=None):
    x = np.arange(len(xtickslabels))
    x *= (len(y_list)//2 + 1)

    for i in range(len(y_list)):
        x1 = x + (i + (1 - len(y_list))/2)*width
        ax.bar(x1, y_list[i], width=width, label=labels[i], yerr=yerr[i], capsize=6*width)

    ax.set_xticks(x)
    ax.set_xticklabels(xtickslabels, fontsize=20)
    ax.set_yscale('log')
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.title.set_size(20)
    ax.xaxis.label.set_size(20)
    ax.yaxis.label.set_size(20)
    ax.tick_params(axis='y', labelsize=20)
    ax.legend(loc='upper right', ncol=2, frameon=False, prop={"size": 20})

    return(ax)

def stacked_custom_bar(y_list, ax, handshake=False, width=0.5, title=None, scale='linear', xlabel='msglen', xtickslabels=None, ylabel=None):
    x = np.arange(len(xtickslabels))
    bottom = []
    size = len(y_list[list(y_list.keys())[0]])

    if handshake:
        ax.bar(x, y_list['ALL'], width=width, label='Handshake', color='lightgrey')
    
    while len(bottom) < size:
        bottom.append(0)

    for alg in settings.ke_operations:
        try:
            ax.bar(x, y_list[alg], width=width, label=alg, bottom=bottom)

            for j in range(len(bottom)):
                bottom[j] += y_list[alg][j]
        
        except KeyError:
            continue

    ax.set_xticks(x)
    ax.set_xticklabels(xtickslabels, fontsize=20)
    ax.set_yscale(scale)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.title.set_size(20)
    ax.xaxis.label.set_size(20)
    ax.yaxis.label.set_size(20)
    ax.tick_params(axis='y', labelsize=20)
    ax.text(0.05, 0.95, 'A - Authentication\nB - Key Establishment\nC - Perfect Forward Secrecy\nD - Encrypted Client Key Exchange' +
            '\nE - Signed Server Key Exchange', transform=ax.transAxes, fontsize=20, verticalalignment='top')
    ax.legend(loc='upper right', ncol=2, frameon=False, prop={"size": 20})
    return(ax)

def custom_scatter(x, y, ax, title=None, xlabel='msglen', xtickslabels=None, ylabel=None, kwargs={}):
    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(np.arange(len(xtickslabels)))
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    return(ax)

########## DATA ANALYSIS UTILS ##########
def sort_keys(all_data, sort_dict):
    srt_keys = []
    new_data = {}

    for key in all_data:
        srt_keys.append(key)

    srt_keys.sort(key=lambda alg: sort_dict[alg])

    for key in srt_keys:
        new_data[key] = all_data[key]

    return new_data

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

# def filter_iqr(data, weight=2):
#     for key in data:
#         sub_dict = data[key]

#         for sub in sub_dict:
#             tmp = []
#             q1 = np.quantile(sub_dict[sub], 0.25)
#             q3 = np.quantile(sub_dict[sub], 0.75)
#             iqr = q3 - q1

#             for val in sub_dict[sub]:
#                 iqrw = weight * iqr

#                 if val > (q3 + iqrw):
#                     continue

#                 elif val < (q1 - iqrw):
#                     continue

#                 else:
#                     tmp.append(val)
            
#             data[key][sub] = tmp

#     return data

def calc_statistics(data, stats_type):
    stats = {'keys': list(data.keys())}
    sub_keys = []
    ops = {
        'mean': np.mean,
        'stddev': np.std,
        'median':np.median,
        'mode': mode
    }

    for key in stats['keys']:
        for sub in data[key]:
            if sub not in sub_keys:
                sub_keys.append(sub)

            for stat in stats_type:
                elem = stat + '_' + sub

                if elem not in stats:
                    stats[elem] = []

    for key in stats['keys']:
        for sub in sub_keys:
            for stat in stats_type:
                try:
                    stats[stat + '_' + sub].append(round(ops[stat](data[key][sub]), 3))

                except KeyError:
                    stats[stat + '_' + sub].append(0)

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
        print(f'error\n    Got an unexpected return code!!!\n    Details: -{return_code:#0{6}x}')

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
    # args = ['python', '--version']
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, stderr = p.communicate()
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
