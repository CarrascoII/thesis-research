import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_errorbar(ylabel, file_path, stats):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    operations = None
    params2 = {'color': 'red'}
    params4 = {'color': 'blue'}

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    ax1 = utils.custom_errorbar(stats['data_size'], stats['mean_out'], stats['stdev_out'], ax=ax1,
                            title=operations[0], ylabel=ylabel, kwargs=params2)
    ax2 = utils.custom_errorbar(stats['data_size'], stats['mean_in'], stats['stdev_in'], ax=ax2,
                            title=operations[1], ylabel=ylabel, kwargs=params4)

    utils.save_fig(fig, file_path + ylabel + '_deviation.png')

def make_plot(ylabel, file_path, stats):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))

    params1 = {'color': 'red', 'linestyle': '-'}
    params2 = {'color': 'blue', 'linestyle': '--'}

    if file_path.find('cipher') != -1:
        params1['label'] = 'encryption'
        params2['label'] = 'decryption'
    elif file_path.find('md') != -1:
        params1['label'] = 'digest'
        params2['label'] = 'verify'

    ax1 = utils.multiple_custom_plots(stats['data_size'], stats['mean_out'], stats['mean_in'],
                                ax=ax1, title='Mean', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = utils.multiple_custom_plots(stats['data_size'], stats['median_out'], stats['median_in'],
                                ax=ax2, title='Median', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = utils.multiple_custom_plots(stats['data_size'], stats['mode_out'], stats['mode_in'],
                                ax=ax3, title='Mode', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

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

def make_scatter(ylabel, file_path, data_out, data_in):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    operations = None
    x1 = []
    y1 = []
    xticks1 = [tick + 1 for tick in range(len(data_out))]
    xtickslabels1 = list(data_out.keys())

    x2 = []
    y2 = []
    xticks2 = [tick + 1 for tick in range(len(data_in))]
    xtickslabels2 = list(data_in.keys())

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    i = 0
    for key in data_out:
        x1 += [xticks1[i] for j in range(len(data_out[key]))]
        y1 += data_out[key]
        i += 1

    i = 0
    for key in data_in:
        x2 += [xticks2[i] for j in range(len(data_in[key]))]
        y2 += data_in[key]
        i += 1

    ax1 = utils.custom_scatter(x1, y1, ax=ax1, title=operations[0], xticks=xticks1,
                            xtickslabels=xtickslabels1, ylabel=ylabel, kwargs={'color': 'red'})
    ax2 = utils.custom_scatter(x2, y2, ax=ax2, title=operations[1], xticks=xticks2,
                            xtickslabels=xtickslabels2, ylabel=ylabel, kwargs={'color': 'blue'})

    utils.save_fig(fig, file_path + ylabel + '_distribution.png')

def make_figs(filename, weight=1.5, strlen=40, spacing=''):
    path = filename.replace('data.csv', '')

    print(spacing + 'Parsing obtained data'.ljust(strlen, '.'), end=' ')
    data, headers = utils.parse_csv_to_data(filename)
    print('ok')

    if weight != 0:
        print(spacing + 'Removing outliers from data'.ljust(strlen, '.'), end=' ')
        data = utils.filter_iqr(data, headers, weight=weight)
        print('ok')

    for hdr in headers:
        print(spacing + f'[{hdr}] Calculating statistics'.ljust(strlen, '.'), end=' ')
        statistics = utils.calc_statistics(data[hdr + '_out'], data[hdr + '_in'])
        print('ok')

        print(spacing + f'[{hdr}] Generating figures'.ljust(strlen, '.'), end=' ')
        make_scatter(hdr, path, data[hdr + '_out'], data[hdr + '_in'])
        # make_hist(hdr, path, data[hdr + '_out'], data[hdr + '_in'])
        make_plot(hdr, path, statistics)
        make_errorbar(hdr, path, statistics)
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