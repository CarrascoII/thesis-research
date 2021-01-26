import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_session_cmp_bar(name, ylabel, stats, labels, stats_type):
    endpoints = stats[0]['keys']
    
    for stype in stats_type:
        for end in endpoints:
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []

            for stat in stats:
                y.append([stat[stype][end]])
                yerr.append([stat['stddev'][end]])

            ax = utils.custom_bar(y, yerr, ax=ax, xlabel='ciphersuite', xtickslabels=labels, title=end, ylabel=ylabel)
            utils.save_fig(fig, '../docs/' + end + '_' + name + '_' + stype + '_' + ylabel + '.png')

def make_alg_cmp_bar(alg, ylabel, stats, labels, stats_type):
    for stype in stats_type:
        xtickslabels = stats[0]['data_size']
        operations = []
        extentions = ['_out', '_in']

        if alg == 'cipher':
            operations = ['encrypt', 'decrypt']
        elif alg == 'md':
            operations = ['hash', 'verify']

        for ext, op in zip(extentions, operations):
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []
        
            for stat in stats:
                y.append(stat[stype + ext])
                yerr.append(stat['stddev' + ext])

            ax = utils.multiple_custom_bar(y, yerr, ax=ax, title=op + ' (' + stype + ')',
                                        labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)

            utils.save_fig(fig, '../docs/' + alg + '_alg_' + op + '_' + stype + '_' + ylabel + '.png')

def make_cmp_figs(ciphersuites, alg, weight=1.5, strlen=40, spacing=''):
    all_data = []
    all_headers = []
    print(spacing + '  Parsing data'.ljust(strlen, '.'), end=' ')

    for suite in ciphersuites:
        path = '../docs/' + suite + '/' + alg + '_data.csv'
        data = {}
        hdr = []

        if alg != 'session':
            data, hdr = utils.parse_alg_data(path)
        else:
            data, hdr = utils.parse_session_data(path)

        all_data.append(data)
        all_headers.append(hdr)

    for hdr in all_headers[1:]:
        if all_headers[0] != hdr:
            print('error')
            print(spacing + 'Data has different headers. Cannot be compared!!!\n')
            
            return None

    print('ok')

    if weight != 0:
        print(spacing + '  Removing outliers from data'.ljust(strlen, '.'), end=' ')
        
        for i in range(len(all_data)):
            data = utils.filter_iqr(all_data[i], weight=weight)
            all_data[i] = data
        
        print('ok')

    all_stats = []
    stats_type = ['mean', 'stddev']

    for hdr in all_headers[0]:
        print(spacing + f'  [{hdr}] Calculating statistics'.ljust(strlen, '.'), end=' ')
        all_stats = []

        for data in all_data:
            stats = {}

            if alg != 'session':
                stats = utils.calc_alg_statistics(data, hdr, stats_type)
            else:
                stats = utils.calc_session_statistics(data, hdr, stats_type)

            if stats == None:
                return None
            
            all_stats.append(stats)

        print('ok')

        print(spacing + f'  [{hdr}] Generating figures'.ljust(strlen, '.'), end=' ')
        if alg != 'session':
            make_alg_cmp_bar(alg, hdr, all_stats, ciphersuites, stats_type[:-1])
        else:
            make_session_cmp_bar(alg, hdr, all_stats, ciphersuites, stats_type[:-1])

        print('ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cms', ['help', 'filter=', 'cipher', 'md', 'session'])
    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No ciphersuites where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('comparator.py [-f <weight>] [-c] [-m] [-s] <ciphersuite_list>')
            print('comparator.py [--filter=<weight>] [--cipher] [--md] [--session] <ciphersuite_list>')
            sys.exit(0)

        if opt in ('-f', '--filter'):
            weight = float(arg)
        elif opt in ('-c', '--cipher'):
            algs.append('cipher')
        elif opt in ('-m', '--md'):
            algs.append('md')
        elif opt in ('-s', '--session'):
            algs.append('session')
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    ciphersuites = utils.parse_ciphersuites(args[0])
    
    for alg in algs:
        print('\n' + alg.upper() + ' data:')
        make_cmp_figs(ciphersuites, alg, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])