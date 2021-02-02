import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_errorbar(ylabel, file_path, stats, types):
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    operations = []
    params = [{'color': 'red'}, {'color': 'blue'}]
    entry = ['_out', '_in']

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    for i in range(len(axes)):
        axes[i] = utils.custom_errorbar(stats['keys'], stats[types[0] + '_' + ylabel + entry[i]],
                                    stats[types[1] + '_' + ylabel + entry[i]], ax=axes[i], title=operations[i],
                                    ylabel=ylabel, kwargs=params[i])

    utils.save_fig(fig, file_path + ylabel + '_deviation.png')

def make_plot(ylabel, file_path, stats, types):
    fig, axes = plt.subplots(1, 3, figsize=(15, 5))
    params1 = {'color': 'red', 'linestyle': '-'}
    params2 = {'color': 'blue', 'linestyle': '--'}
    entry = ['_out', '_in']

    if file_path.find('cipher') != -1:
        params1['label'] = 'encryption'
        params2['label'] = 'decryption'
    elif file_path.find('md') != -1:
        params1['label'] = 'digest'
        params2['label'] = 'verify'

    for ax, tp in zip(axes, types):
        ax = utils.multiple_custom_plots(stats['keys'], stats[tp + '_' + ylabel + entry[0]], stats[tp + '_' + ylabel + entry[1]],
                                    ax=ax, title=tp.capitalize(), ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    utils.save_fig(fig, file_path + ylabel + '_statistics.png')

# def make_hist(ylabel, file_path, data_out, data_in):
#     fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

#     operations = None
#     x1 = []
#     x2 = []
#     params1 = {'label': list(data_out.keys())}
#     params2 = {'label': list(data_in.keys())}

#     if file_path.find('cipher') != -1:
#         operations = ['cipher', 'decipher']
#     elif file_path.find('md') != -1:
#         operations = ['hash', 'verify']

#     for key in data_out:
#         x1.append(data_out[key])

#     for key in data_in:
#         x2.append(data_in[key])

#     ax1 = utils.custom_hist(x1, ax=ax1, title=operations[0], ylabel=ylabel, kwargs=params1)
#     ax2 = utils.custom_hist(x2, ax=ax2, title=operations[1], ylabel=ylabel, kwargs=params2)
#     save_fig(fig, file_path + ylabel + '_hist.png')

def make_scatter(ylabel, file_path, data):
    fig, axes = plt.subplots(1, 2, figsize=(10, 5))
    operations = []
    x = {}
    y = {}
    xtickslabels = list(data.keys())
    kwargs = [{'color': 'red'}, {'color': 'blue'}]

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    for op, sub in zip(operations, [ylabel + '_out', ylabel + '_in']):
        x[op] = []
        y[op] = []

        for key, i in zip(data, range(len(xtickslabels))):
            x[op] += [i for j in range(len(data[key][sub]))]
            y[op] += data[key][sub]
        
    for i in range(len(axes)):
        axes[i] = utils.custom_scatter(x[operations[i]], y[operations[i]], ax=axes[i], title=operations[i],
                                    xtickslabels=xtickslabels, ylabel=ylabel, kwargs=kwargs[i])
        utils.save_fig(fig, file_path + ylabel + '_distribution.png')

def make_figs(filename, weight=1.5, strlen=40, spacing=''):
    path = filename.replace('data.csv', '')

    print(spacing + 'Parsing obtained data'.ljust(strlen, '.'), end=' ')
    data, headers = utils.parse_alg_data(filename)
    print('ok')

    if weight != 0:
        print(spacing + 'Removing outliers from data'.ljust(strlen, '.'), end=' ')
        data = utils.filter_iqr(data, weight=weight)
        print('ok')

    print(spacing + f'Calculating statistics'.ljust(strlen, '.'), end=' ')
    stats_type = ['mean', 'stddev','median', 'mode']
    stats = utils.calc_statistics(data, stats_type)
    print('ok')
    
    print(spacing + f'Saving statistics'.ljust(strlen, '.'), end=' ')
    utils.write_alg_csv(path + 'statistics.csv', stats)
    print('ok')

    print(spacing + f'Generating figures'.ljust(strlen, '.'), end=' ')
    for hdr in headers:
        make_scatter(hdr, path, data)
        # make_hist(hdr, path, data[hdr + '_out'], data[hdr + '_in'])
        make_plot(hdr, path, stats, [stats_type[0]] + stats_type[2:])
        make_errorbar(hdr, path, stats, stats_type[:2])    
    print('ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cm', ['help', 'filter=', 'cipher', 'md'])
    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "plotter.py -h" for help')
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
            print('plotter.py [-f <weight>] [-c] [-m] <ciphersuite_list>')
            print('plotter.py [--filter=<weight>] [--cipher] [--md] <ciphersuite_list>')
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
    current = 1

    for suite in ciphersuites:
        print(f'\nCreating graphs for: {suite} ({current}/{len(ciphersuites)})', end='')
        current +=1
        
        for alg in algs:
            print('\n' + alg.upper() + ' algorithm:')
            fname = '../docs/' + suite + '/' + alg + '_data.csv'

            make_figs(fname, weight=weight, spacing='  ')

if __name__ == '__main__':
   main(sys.argv[1:])