import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_cmp_plot(alg, ylabel, stats1, label1, stats2, label2, hdrs):
    params1 = {'color': 'red', 'label': label1}
    params2 = {'color': 'blue', 'label': label2}
    op = []
    ext = ['_out', '_in']

    if alg == 'cipher':
        op = ['encrypt', 'decrypt']
    elif alg == 'md':
        op = ['hash', 'verify']

    for hdr in hdrs:
        fig, axes = plt.subplots(1, 2, figsize=(10, 5))

        for i in range(len(axes)):
            axes[i] = utils.multiple_custom_plots(stats1['keys'], stats1[hdr + '_' + ylabel + ext[i]],
                                                stats2[hdr + '_' + ylabel + ext[i]], ax=axes[i], title=op[i] + ' (' + hdr + ')',
                                                ylabel=ylabel, kwargs1=params1, kwargs2=params2)

        utils.save_fig(fig, '../docs/cmp_' + alg + '_' + ylabel + '_' + hdr + '.png')

def make_cmp_figs(ciphersuite1, ciphersuite2, algs, weight=1.5, strlen=40, spacing=''):
    path1 = '../docs/' + ciphersuite1 + '/'
    path2 = '../docs/' + ciphersuite2 + '/'

    print(f'Comparing {ciphersuite1} VS {ciphersuite2}', end='')

    for alg in algs:
        print('\n' + spacing + f'{alg.upper()} algorithm:')
        print(spacing + '  Parsing data'.ljust(strlen, '.'), end=' ')
        data1, headers1 = utils.parse_alg_data(path1 + alg + '_data.csv')
        data2, headers2 = utils.parse_alg_data(path2 + alg + '_data.csv')
       
        if headers1 != headers2:
            print('error')
            print(spacing + 'Data has different headers. Cannot be compared!!!\n')
            continue

        print('ok')

        if weight != 0:
            print(spacing + '  Removing outliers from data'.ljust(strlen, '.'), end=' ')
            data1 = utils.filter_iqr(data1, weight=weight)
            data2 = utils.filter_iqr(data2, weight=weight)
            print('ok')

        stats_type = ['mean', 'median']

        print(spacing + f'  Calculating statistics'.ljust(strlen, '.'), end=' ')
        stats1 = utils.calc_statistics(data1, stats_type)
        stats2 = utils.calc_statistics(data2, stats_type)

        if stats1 == None or stats2 == None:
            sys.exit(2)

        print('ok')

        print(spacing + f'  Saving statistics'.ljust(strlen, '.'), end=' ')
        path = '../docs/cmp_' + alg + '_alg_'
        utils.write_alg_cmp_csv(path, {ciphersuite1: stats1, ciphersuite2: stats2})
        print('ok')

        print(spacing + f'  Generating figures'.ljust(strlen, '.'), end=' ')

        for hdr in headers1:
            make_cmp_plot(alg, hdr, stats1, ciphersuite1, stats2, ciphersuite2, stats_type)
        
        print('ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cm', ['help', 'filter=', 'cipher', 'md'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No ciphersuites where given')
        sys.exit(2)

    if len(args) > 2:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('comparator_plot.py [-f <weight>] [-c] [-m] <ciphersuite1> <ciphersuite2>')
            print('comparator_plot.py [--filter=<weight>] [--cipher] [--md] <ciphersuite1> <ciphersuite2>')
            sys.exit(0)

        if opt in ('-f', '--filter'):
            weight = float(arg)

        elif opt in ('-c', '--cipher'):
            algs.append('cipher')

        elif opt in ('-m', '--md'):
            algs.append('md')
            
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    make_cmp_figs(args[0], args[1], algs, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])