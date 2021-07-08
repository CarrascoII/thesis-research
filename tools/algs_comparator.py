import os, sys, getopt
from copy import deepcopy
from matplotlib import use
import matplotlib.pyplot as plt
import utils, settings


def make_alg_cmp_bar(path, alg, operations, ylabel, stats):
    labels = list(stats.keys())
    xtickslabels = deepcopy(stats[next(iter(stats))]['keys'])
    
    if alg == 'ke':
        for i, val in enumerate(xtickslabels):
            xtickslabels[i] = settings.sec_str[int(val)]

    for op in operations:
        fig, ax = plt.subplots(1, 1, figsize=(30, 10))
        y = []
        yerr = []
    
        for key in stats:
            y.append(stats[key]['mean_' + ylabel + '_' + op])
            yerr.append(stats[key]['stddev_' + ylabel + '_' + op])

        ax = utils.multiple_custom_bar(y, yerr, ax, title=op + ' (mean)',
                                    labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)
        utils.save_fig(fig, 'statistics/' + path + '/alg_' + alg + '_' + op + '_' + ylabel + '.png')

def make_alg_cmp_figs(path, grouped_suites, alg, labels, weight=2, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_stats = {}
    stats_type = ['mean', 'stddev']
    data_ops_func = {
        'cipher': utils.parse_record_data,
        'md': utils.parse_record_data,
        'ke': utils.parse_handshake_data
    }

    print(f'{spacing}Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for key in grouped_suites:
        all_data[key] = {}

        for suite in grouped_suites[key]:
            fname = '../docs/' + path + '/' + suite + '/'
            data, hdr = data_ops_func[alg](fname, alg)

            # print(f'\n{suite}:')
            # for a in data:
            #     print(f'  {a}')
            #     for b in data[a]:
            #         print(f'    {b}: {data[a][b]}')
            #     print('')

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
        print(f'{spacing}Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for key in all_data:
            data = utils.filter_z_score(all_data[key], weight=weight)
            all_data[key] = data
        
        print('ok')

    print(f'{spacing}Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for key in all_data:
        stats = utils.calc_statistics(all_data[key], stats_type)

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')

    print(f'{spacing}Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    utils.write_alg_cmp_csv('statistics/' + path + '/', 'alg', 'algorithm', alg, all_stats)
    print('ok')
    
    print(f'{spacing}Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_alg_cmp_bar(path, alg, labels, hdr, all_stats)

    print('ok')

def make_figs(path, algs_fname, ciphersuites, alg_set=[], weight=2, strlen=40, spacing=''):
    if alg_set == []:
        print('\nError!! No algorithms were selected to analyse!!!')
        return None

    use('Agg')
    labels = settings.alg_labels
    algs = utils.parse_algorithms_grouped(algs_fname, alg_set, ciphersuites)
    
    for alg in algs:
        print(f'{spacing}\n{alg.upper()} data:')

        make_alg_cmp_figs(path, algs[alg], alg, labels[alg], weight=weight, strlen=strlen, spacing=spacing)

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

    weight = 2
    suites = []
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('algs_comparator.py [-w <filter_weight>] [-c] [-m] [-k] <path_to_data> <algorithm_list>')
            print('algs_comparator.py [--weight=<filter_weight>] [--cipher] [--md] [--ke] <path_to_data> <algorithm_list>')
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
    suites = [f.name for f in os.scandir('../docs/' + args[0]) if f.is_dir()]
    
    make_figs(args[0], args[1], suites, weight=weight, alg_set=algs)

if __name__ == '__main__':
   main(sys.argv[1:])