import os
import sys, getopt
import matplotlib.pyplot as plt
import utils, settings


def make_alg_cmp_bar(alg, operations, ylabel, stats, stats_type):
    labels = list(stats.keys())
    xtickslabels = stats[next(iter(stats))]['keys']
    
    if alg == 'ke':
        for i, val in enumerate(xtickslabels):
            xtickslabels[i] = settings.security_lvls[settings.keylen_to_sec_lvl[val]]

    for stype in stats_type:
        for op in operations:
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []
        
            for key in stats:
                y.append(stats[key][stype + '_' + ylabel + '_' + op])
                yerr.append(stats[key]['stddev_' + ylabel + '_' + op])

            ax = utils.multiple_custom_bar(y, yerr, ax=ax, title=op + ' (' + stype + ')',
                                        labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)
            utils.save_fig(fig, '../docs/alg_' + alg + '_' + op + '_' + stype + '_' + ylabel + '.png')

def make_alg_cmp_figs(grouped_suites, alg, labels, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_stats = {}
    stats_type = ['mean', 'stddev']

    print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for key in grouped_suites:
        all_data[key] = {}

        for suite in grouped_suites[key]:
            path = '../docs/' + suite + '/' + alg + '_data.csv'
            data, hdr = utils.parse_alg_data(path, alg)

            if all_data[key] == {}:
                all_data[key] = data
                headers = hdr
            
            elif headers == hdr:
                for sub in list(all_data[key].keys()):
                    for entry in data[sub]:
                        all_data[key][sub][entry] += data[sub][entry]

            else:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
                return None

        if all_data[key] == {}:
            all_data.pop(key)

    print('ok')

    if weight != 0:
        print(f'{spacing}  Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for key in all_data:
            data = utils.filter_iqr(all_data[key], weight=weight)
            all_data[key] = data
        
        print('ok')

    print(f'{spacing}  Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for key in all_data:
        stats = utils.calc_statistics(all_data[key], stats_type)

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')

    print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    utils.write_alg_cmp_csv('../docs/alg_' + alg + '_', 'algorithm', alg, all_stats)
    print('ok')
    
    print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_alg_cmp_bar(alg, labels, hdr, all_stats, stats_type[:-1])

    print('ok')

def make_figs(algs_fname, ciphersuites, alg_set=[], weight=1.5, strlen=40, spacing=''):
    if alg_set == []:
        alg_set = settings.alg_types

    labels = settings.alg_labels
    algs = utils.parse_algorithms_grouped(algs_fname, alg_set, ciphersuites)
    
    for alg in algs:
        print(f'{spacing}\n{alg.upper()} data:')

        make_alg_cmp_figs(algs[alg], alg, labels[alg], weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hw:cmk', ['help', 'weight=', 'cipher', 'md', 'ke'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No inputs where given')
        sys.exit(2)

    if len(args) > 2:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5
    suites = []
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('algs_comparator.py [-w <filter_weight>] [-c] [-m] [-k] <algorithm_list> <ciphersuite_list>')
            print('algs_comparator.py [--weight=<filter_weight>] [--cipher] [--md] [--ke] <algorithm_list> <ciphersuite_list>')
            sys.exit(0)

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        elif opt in ('-c', '--cipher'):
            algs.append('cipher')

        elif opt in ('-m', '--md'):
            algs.append('md')

        elif opt in ('-k', '--ke'):
            algs.append('ke')

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    settings.init()
    suites = utils.parse_ciphersuites(args[1])
    
    make_figs(args[0], suites, weight=weight, alg_set=algs)

if __name__ == '__main__':
   main(sys.argv[1:])