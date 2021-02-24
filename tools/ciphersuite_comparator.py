import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_cmp_plot(alg, ylabel, all_stats, labels, hdrs):
    op = []
    ext = ['_out', '_in']

    if alg == 'cipher':
        op = ['encrypt', 'decrypt']

    elif alg == 'md':
        op = ['hash', 'verify']

    for hdr in hdrs:
        fig, axes = plt.subplots(1, 2, figsize=(10, 5))
        
        for i in range(len(axes)):
            x = []
            y_lst = []
            kwargs_lst = []

            for suite in all_stats:
                x = all_stats[suite]['keys']
                y_lst.append(all_stats[suite][hdr + '_' + ylabel + ext[i]])
                kwargs_lst.append({'label': suite})

            axes[i] = utils.multiple_custom_plots(x, y_lst, ax=axes[i], title=op[i] + ' (' + hdr + ')', ylabel=ylabel, kwargs_lst=kwargs_lst)

        utils.save_fig(fig, '../docs/cmp_' + alg + '_' + ylabel + '_' + hdr + '.png')

def make_cmp_figs(ciphersuites, algs, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    all_headers = []

    for alg in algs:
        print('\n' + f'{spacing}{alg.upper()} algorithm:')
        print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for suite in ciphersuites:
            path = '../docs/' + suite + '/'            
            data, hdr = utils.parse_record_data(path + alg + '_data.csv')
       
            all_data[suite] = data
            all_headers.append(hdr)

        for hdr in all_headers[1:]:
            if all_headers[0] != hdr:
                print('error')
                print(f'{spacing}Data has different headers. Cannot be compared!!!\n')
                continue

        print('ok')

        if weight != 0:
            print(f'{spacing}  Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
            
            for suite in ciphersuites:
                data = utils.filter_iqr(all_data[suite], weight=weight)
                all_data[suite] = data

            print('ok')

        print(f'{spacing}  Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

        all_stats = {}
        stats_type = ['mean', 'median']

        for suite in ciphersuites:
            stats = utils.calc_statistics(all_data[suite], stats_type)

            if stats == None:
                return None

            all_stats[suite] = stats

        print('ok')
        print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
        
        path = '../docs/cmp_' + alg + '_alg_'
        utils.write_record_cmp_csv(path, all_stats)
        
        print('ok')
        print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)

        for hdr in all_headers[0]:
            make_cmp_plot(alg, hdr, all_stats, ciphersuites, stats_type)
        
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

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('ciphersuite_comparator.py [-f <weight>] [-c] [-m] <ciphersuite_list>')
            print('ciphersuite_comparator.py [--filter=<weight>] [--cipher] [--md] <ciphersuite_list>')
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
    ciphersuites = utils.parse_ciphersuites(args[0]) 
    make_cmp_figs(ciphersuites, algs, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])