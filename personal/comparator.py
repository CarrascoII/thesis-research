import sys, getopt
import matplotlib.pyplot as plt
import plotter, utils


def make_cmp_plot(alg, ylabel, stats1, label1, stats2, label2):
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(10, 10))

    op = []
    params1 = {'color': 'red', 'label': label1}
    params2 = {'color': 'blue', 'label': label2}

    if alg == 'cipher':
        op = ['cipher', 'decipher']
    elif alg == 'md':
        op = ['hash', 'verify']

    ax1 = plotter.multiple_custom_plots(stats1['data_size'], stats1['mean_out'], stats2['mean_out'], ax=ax1,
                                        title='Mean (' + op[0] + ')', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = plotter.multiple_custom_plots(stats1['data_size'], stats1['median_out'], stats2['median_out'], ax=ax2,
                                        title='Mean (' + op[1] + ')', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = plotter.multiple_custom_plots(stats1['data_size'], stats1['mean_in'], stats2['mean_in'], ax=ax3,
                                        title='Median (' + op[0] + ')', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax4 = plotter.multiple_custom_plots(stats1['data_size'], stats1['median_in'], stats2['median_in'], ax=ax4,
                                        title='Median (' + op[1] + ')', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    plotter.save_fig(fig, '../docs/cmp_' + alg + '_' + ylabel + '_statistics.png')

def make_cmp_figs(ciphersuite1, ciphersuite2, algs, weight=1.5, strlen=40, spacing=''):
    path1 = '../docs/' + ciphersuite1 + '/'
    path2 = '../docs/' + ciphersuite2 + '/'

    for alg in algs:
        print(spacing + f'[{alg}] Parsing data'.ljust(strlen, '.'), end=' ')
        data1, headers1 = utils.parse_csv_to_data(path1 + alg + '_data.csv')
        data2, headers2 = utils.parse_csv_to_data(path2 + alg + '_data.csv')
       
        if headers1 != headers2:
            print('error')
            print(spacing + f'Data has different headers. Cannot be compared!!!\n')
            break

        print(f'ok')

        if weight != 0:
            print(spacing + f'[{alg}] Removing outliers from data'.ljust(strlen, '.'), end=' ')
            data1 = utils.filter_iqr(data1, headers1, weight=weight)
            data2 = utils.filter_iqr(data2, headers2, weight=weight)
            print(f'ok')

        for header in headers1:
            print(spacing + f'\t[{header}] Calculating statistics'.ljust(strlen, '.'), end=' ')
            statistics1 = utils.calc_statistics(data1[header + '_out'], data1[header + '_in'])
            statistics2 = utils.calc_statistics(data2[header + '_out'], data2[header + '_in'])
            print(f'ok')

            print(spacing + f'\t[{header}] Generating figures'.ljust(strlen, '.'), end=' ')
            make_cmp_plot(alg, header, statistics1, ciphersuite1, statistics2, ciphersuite2)
            print(f'ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cm', ['help', 'filter=', 'cipher', 'md'])
    except getopt.GetoptError:
        print(f'One of the options does not exit.\nUse: "plotter.py -h" for help')
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
            print(f'plotter.py [-f <weight>] [-c] [-m] <ciphersuite1> <ciphersuite2>')
            print(f'plotter.py [--filter=<weight>] [--cipher] [--md] <ciphersuite1> <ciphersuite2>')
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

    make_cmp_figs(args[0], args[1], algs, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])