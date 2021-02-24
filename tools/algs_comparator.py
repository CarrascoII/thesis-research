import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_record_alg_cmp_bar(alg, ylabel, stats, stats_type):
    labels = list(stats.keys())
    xtickslabels = stats[next(iter(stats))]['keys']
    operations = []
    extentions = []

    if alg == 'cipher':
        operations = ['encrypt', 'decrypt']
        extentions = ['_out', '_in']

    elif alg == 'md':
        operations = ['hash', 'verify']
        extentions = ['_out', '_in']

    elif alg == 'ke':
        operations = ['handshake']
        extentions = ['']

    for stype in stats_type:
        for ext, op in zip(extentions, operations):
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []
        
            for key in stats:
                y.append(stats[key][stype + '_' + ylabel + ext])
                yerr.append(stats[key]['stddev_' + ylabel + ext])

            ax = utils.multiple_custom_bar(y, yerr, ax=ax, title=op + ' (' + stype + ')',
                                        labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)
            utils.save_fig(fig, '../docs/alg_' + alg + '_' + op + '_' + stype + '_' + ylabel + '.png')

def make_alg_cmp_figs(grouped_suites, alg, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    headers = []

    data_ops = {
        'cipher': utils.parse_record_data,
        'md': utils.parse_record_data,
        'ke':utils.parse_handshake_data
    }

    write_ops = {
        'cipher': utils.write_record_cmp_csv,
        'md': utils.write_record_cmp_csv,
        'ke':utils.write_handshake_cmp_csv
    }

    print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for key in grouped_suites:
        all_data[key] = {}

        for suite in grouped_suites[key]:
            path = '../docs/' + suite + '/' + alg + '_data.csv'
            data, hdr = data_ops[alg](path)

            if all_data[key] == {}:
                all_data[key] = data
                headers = hdr
            
            elif len(headers) == len(hdr):
                for key1, key2 in zip(list(all_data[key].keys()), list(data.keys())):
                    for entry in data[key2]:
                        all_data[key][key1][entry] += data[key2][entry]

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

    all_stats = {}
    stats_type = ['mean', 'stddev']

    for key in all_data:
        stats = utils.calc_statistics(all_data[key], stats_type)

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')
    print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    
    path = '../docs/alg_' + alg + '_'
    write_ops[alg](path, all_stats)
    
    print('ok')
    print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_record_alg_cmp_bar(alg, hdr, all_stats, stats_type[:-1])

    print('ok')

def make_figs(algs_fname, ciphersuites, alg_set=['cipher', 'md', 'ke'], weight=1.5, strlen=40, spacing=''):
    algs = utils.parse_algorithms_grouped(algs_fname, alg_set, ciphersuites)
    
    for alg in algs:
        print(f'{spacing}\n{alg.upper()} data:')

        make_alg_cmp_figs(algs[alg], alg, weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cmks:', ['help', 'filter=', 'cipher', 'md', 'ke', 'suites='])

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
    fname = ''
    suites = []
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('algs_comparator.py [-f <weight>] [-c] [-m] [-k] [-s <ciphersuite_list>] <algorithm_list>')
            print('algs_comparator.py [--filter=<weight>] [--cipher] [--md] [--ke] [--suites=<ciphersuite_list>] <algorithm_list>')
            sys.exit(0)

        elif opt in ('-f', '--filter'):
            weight = float(arg)

        elif opt in ('-c', '--cipher'):
            algs.append('cipher')

        elif opt in ('-m', '--md'):
            algs.append('md')

        elif opt in ('-k', '--ke'):
            algs.append('ke')

        elif opt in ('-s', '--suites'):
            fname = arg

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')

    if fname != '':
        suites = utils.parse_ciphersuites(fname)
    
    make_figs(args[0], suites, weight=weight, alg_set=algs)

if __name__ == '__main__':
   main(sys.argv[1:])