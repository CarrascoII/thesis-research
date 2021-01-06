import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_cmp_bar(alg, ylabel, stats, labels):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 10))
    op = []
    xtickslabels = stats[0]['data_size']
    y1 = []
    y2 = []
    width = 0.5

    if alg == 'cipher':
        op = ['cipher', 'decipher']
    elif alg == 'md':
        op = ['hash', 'verify']

    for stat in stats:
        y1 += [stat['mean_out']]
        y2 += [stat['mean_in']]

    ax1 = utils.custom_bar(y1, ax=ax1, width=width, title=op[0], labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)
    ax2 = utils.custom_bar(y2, ax=ax2, width=width, title=op[1], labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)

    utils.save_fig(fig, '../docs/cmp_' + alg + '_' + ylabel + '_bar.png')

def make_cmp_figs2(ciphersuites, alg, weight=1.5, strlen=40, spacing=''):
    all_data = []
    all_headers = []
    print(spacing + '  Parsing data'.ljust(strlen, '.'), end=' ')

    for suite in ciphersuites:
        path = '../docs/' + suite + '/' + alg + '_data.csv'
        data, hdr = utils.parse_csv_to_data(path)

        all_data.append(data)    
        all_headers.append(hdr)

    for hdr in all_headers[1:]:
        if all_headers[0] != hdr:
            print('error')
            print(spacing + 'Data has different headers. Cannot be compared!!!\n')
            return

    print('ok')

    if weight != 0:
        print(spacing + '  Removing outliers from data'.ljust(strlen, '.'), end=' ')
        
        for i in range(len(all_data)):
            data = utils.filter_iqr(all_data[i], all_headers[i], weight=weight)
            all_data[i] = data
        
        print('ok')

    all_stats = []

    for hdr in all_headers[0]:
        print(spacing + f'  [{hdr}] Calculating statistics'.ljust(strlen, '.'), end=' ')

        for data in all_data:
            stats = utils.calc_statistics(data[hdr + '_out'], data[hdr + '_in'])
            all_stats.append({key: stats[key] for key in ['data_size', 'mean_out', 'mean_in']})

        print('ok')
        print(spacing + f'  [{hdr}] Generating figures'.ljust(strlen, '.'), end=' ')
        make_cmp_bar(alg, hdr, all_stats, ciphersuites)
        print('ok')

def main2(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cm', ['help', 'filter=', 'cipher', 'md'])
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
            print('comparator.py [-f <weight>] [-c] [-m] <ciphersuite_list>')
            print('comparator.py [--filter=<weight>] [--cipher] [--md] <ciphersuite_list>')
            sys.exit(0)
        if opt in ('-f', '--nfilter'):
            weight = float(arg)
        elif opt in ('-c', '--cipher'):
            algs.append('cipher')
        elif opt in ('-m', '--md'):
            algs.append('md')
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    ciphersuites = utils.parse_ciphersuites(args[0])
    
    for alg in algs:
        print('\n' + alg.upper() + ' algorithm:')

        make_cmp_figs2(ciphersuites, alg, weight=weight)

if __name__ == '__main__':
   main2(sys.argv[1:])