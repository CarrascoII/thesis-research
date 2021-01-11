import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_cmp_plot(alg, ylabel, stats1, label1, stats2, label2, hdrs):
    for hdr in hdrs:
        fig, axes = plt.subplots(1, 2, figsize=(10, 5))
        params1 = {'color': 'red', 'label': label1}
        params2 = {'color': 'blue', 'label': label2}
        op = []
        ext = ['_out', '_in']

        if alg == 'cipher':
            op = ['cipher', 'decipher']
        elif alg == 'md':
            op = ['hash', 'verify']

        for i in range(len(axes)):
            axes[i] = utils.multiple_custom_plots(
                            stats1['data_size'], stats1[hdr + ext[i]], stats2[hdr + ext[i]], ax=axes[i],
                            title=op[i] + ' (' + hdr + ')', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

        utils.save_fig(fig, '../docs/cmp_' + alg + '_' + ylabel + '_' + hdr + '_statistics.png')

def make_cmp_figs(ciphersuite1, ciphersuite2, algs, weight=1.5, strlen=40, spacing=''):
    print(f'Comparing {ciphersuite1} VS {ciphersuite2}', end='')
    path1 = '../docs/' + ciphersuite1 + '/'
    path2 = '../docs/' + ciphersuite2 + '/'

    for alg in algs:
        print('\n' + spacing + f'{alg.upper()} algorithm:')
        print(spacing + '  Parsing data'.ljust(strlen, '.'), end=' ')
        data1, headers1 = utils.parse_csv_to_data(path1 + alg + '_data.csv')
        data2, headers2 = utils.parse_csv_to_data(path2 + alg + '_data.csv')
       
        if headers1 != headers2:
            print('error')
            print(spacing + 'Data has different headers. Cannot be compared!!!\n')
            break

        print('ok')

        if weight != 0:
            print(spacing + '  Removing outliers from data'.ljust(strlen, '.'), end=' ')
            data1 = utils.filter_iqr(data1, headers1, weight=weight)
            data2 = utils.filter_iqr(data2, headers2, weight=weight)
            print('ok')

        stats_type = ['mean', 'median']

        for hdr in headers1:
            print(spacing + f'  [{hdr}] Calculating statistics'.ljust(strlen, '.'), end=' ')
            stats1 = utils.calc_statistics(data1, hdr, stats_type)
            stats2 = utils.calc_statistics(data2, hdr, stats_type)

            if stats1 == None or stats2 == None:
                sys.exit(2)

            print('ok')
            print(spacing + f'  [{hdr}] Generating figures'.ljust(strlen, '.'), end=' ')
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
            print('comparator.py [-f <weight>] [-c] [-m] <ciphersuite1> <ciphersuite2>')
            print('comparator.py [--filter=<weight>] [--cipher] [--md] <ciphersuite1> <ciphersuite2>')
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
    make_cmp_figs(args[0], args[1], algs, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])