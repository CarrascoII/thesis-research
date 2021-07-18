import os
import sys, getopt
import matplotlib
import matplotlib.pyplot as plt
import utils, settings


def make_errorbar(ylabel, operations, file_path, stats, types, xlabel):
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    params = [{'color': 'red'}, {'color': 'blue'}]

    for i in range(len(axes)):
        axes[i] = utils.custom_errorbar(stats['keys'], stats[types[0] + '_' + ylabel + '_' + operations[i]],
                                    stats[types[1] + '_' + ylabel + '_' + operations[i]], axes[i], title=operations[i],
                                    xlabel=xlabel, ylabel=ylabel, kwargs=params[i])

    utils.save_fig(fig, file_path + ylabel + '_deviation.png')

def make_plot(ylabel, operations, file_path, stats, types, xlabel):
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    params1 = {'color': 'red', 'linestyle': '-', 'label': operations[0]}
    params2 = {'color': 'blue', 'linestyle': '--', 'label': operations[1]}

    for ax, tp in zip(axes, types):
        ax = utils.custom_plots(stats['keys'], stats[tp + '_' + ylabel + '_' + operations[0]],
                            stats[tp + '_' + ylabel + '_' + operations[1]], ax,
                            title=tp.capitalize(), xlabel=xlabel, ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    utils.save_fig(fig, file_path + ylabel + '_statistics.png')

def make_scatter(ylabel, operations, file_path, data, xlabel):
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    x = {}
    y = {}
    xtickslabels = list(data.keys())
    kwargs = [{'color': 'red'}, {'color': 'blue'}]

    for op in operations:
        x[op] = []
        y[op] = []

        for key, i in zip(data, range(len(xtickslabels))):
            x[op] += [i for j in range(len(data[key][ylabel + '_' + op]))]
            y[op] += data[key][ylabel + '_' + op]
        
    for i in range(len(axes)):
        axes[i] = utils.custom_scatter(x[operations[i]], y[operations[i]], axes[i], title=operations[i],
                                    xtickslabels=xtickslabels, xlabel=xlabel, ylabel=ylabel, kwargs=kwargs[i])
        utils.save_fig(fig, file_path + ylabel + '_distribution.png')

def make_alg_suite_figs(fname, alg, weight=2, strlen=40, spacing=''):
    path = fname.replace('../docs/', 'statistics/')
    stats_type = ['mean', 'median', 'mode', 'stddev']
    labels = settings.alg_labels[alg]
    data_ops_func = {
        'cipher': utils.parse_record_data,
        'md': utils.parse_record_data,
        'ke': utils.parse_handshake_data
    }
    xlabels = {
        'cipher': 'message size',
        'md': 'message size',
        'ke': 'security level'
    }

    print(f'{spacing}Parsing obtained data'.ljust(strlen, '.'), end=' ', flush=True)
    data, headers = data_ops_func[alg](fname, alg)
    print('ok')

    if weight != 0:
        print(f'{spacing}Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        data = utils.filter_z_score(data, weight=weight)
        print('ok')

    print(f'{spacing}Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)
    stats = utils.calc_statistics(data, stats_type)
    print('ok')
    
    print(f'{spacing}Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    utils.write_alg_csv(path, alg, labels, stats)
    print('ok')

    print(f'{spacing}Generating figures'.ljust(strlen, '.'), end=' ', flush=True)

    for hdr in headers:
        make_scatter(hdr, labels, path + alg + '_', data, xlabels[alg])
        make_plot(hdr, labels, path + alg + '_', stats, stats_type[:-1], xlabels[alg])
        make_errorbar(hdr, labels, path + alg + '_', stats, [stats_type[0], stats_type[-1]], xlabels[alg])
    
    print('ok')

def make_figs(path, ciphersuites, alg_set=[], weight=2, strlen=40, spacing='  '):
    if alg_set == []:
        print('\nError!! No algorithms were selected to analyse!!!')
        return None
    
    matplotlib.use('Agg')
    current = 1

    for suite in ciphersuites:
        print(f'\nCreating graphs for: {suite} ({current}/{len(ciphersuites)})', end='')
        current +=1
        
        for alg in alg_set:
            fname = '../docs/' + path + '/' + suite + '/'

            print('\n' + alg.upper() + ' algorithm:')
            make_alg_suite_figs(fname, alg, weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hw:cmk', ['help', 'weight=', 'cipher', 'md', 'ke'])
    
    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "algs_plotter.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No ciphersuites where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    weight = 2
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('algs_plotter.py [-w <filter_weight>] [-c] [-m] [-k] <path_to_data>')
            print('algs_plotter.py [--weight=<filter_weight>] [--cipher] [--md] [--ke] <path_to_data>')
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

    make_figs(args[0], suites, alg_set=algs, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])