import sys, getopt
import matplotlib.pyplot as plt
import utils


def save_fig(fig, fname):
    fig.tight_layout()
    fig.savefig(fname)
    plt.close(fig)
    plt.cla()

def custom_errorbar(x, y, e, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, fmt='.', capsize=5, barsabove=True, **kwargs)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

def multiple_custom_plots(x, y1, y2, ax=None, title=None, ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()
    
    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

def custom_scatter(x, y, ax=None, title=None, xlabel=None, xticks=None, xtickslabels=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xticks(xticks)
    ax.set_xticklabels(xtickslabels)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

def make_errorbar(ylabel, file_path, stats):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))
    
    operations = None
    params2 = {'color': 'red'}
    params4 = {'color': 'blue'}

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    ax1 = custom_errorbar(stats['data_size'], stats['mean_out'], stats['stdev_out'], ax=ax1, title=operations[0], ylabel=ylabel, kwargs=params2)
    ax2 = custom_errorbar(stats['data_size'], stats['mean_in'], stats['stdev_in'], ax=ax2, title=operations[1], ylabel=ylabel, kwargs=params4)

    save_fig(fig, file_path + ylabel + '_deviation.png')

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

    ax1 = multiple_custom_plots(stats['data_size'], stats['mean_out'], stats['mean_in'],
                                ax=ax1, title='Mean', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(stats['data_size'], stats['median_out'], stats['median_in'],
                                ax=ax2, title='Median', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(stats['data_size'], stats['mode_out'], stats['mode_in'],
                                ax=ax3, title='Mode', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    save_fig(fig, file_path + ylabel + '_statistics.png')

def make_scatter(ylabel, file_path, data, data_sizes):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    operations = None
    x1 = []
    x2 = []
    xticks = [tick + 1 for tick in range(len(data_sizes))]

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    i = 0
    for val in data['size_out']:
        while val != data_sizes[i]:
            i += 1
        x1.append(xticks[i])
                
    i = 0
    for val in data['size_in']:
        while val != data_sizes[i]:
            i += 1
        x2.append(xticks[i])

    # print(f'\nx1:\n{x1}')
    # print(f'\ny1:\n{data["val_out"]}')
    # print(f'\nxticks:\n{xticks}')
    # print(f'\nxtickslabels:\n{data_sizes}')

    ax1 = custom_scatter(x1, data['val_out'], ax=ax1, title=operations[0], xticks=xticks, xtickslabels=data_sizes, ylabel=ylabel, kwargs={'color': 'red'})
    ax2 = custom_scatter(x2, data['val_in'], ax=ax2, title=operations[1], xticks=xticks, xtickslabels=data_sizes, ylabel=ylabel, kwargs={'color': 'blue'})

    save_fig(fig, file_path + ylabel + '_distribution.png')

def make_figs(filename, parse_time=True, weight=2, spacing=''):
    path = filename.replace('data.csv', '')

    print(spacing + f'Parsing obtained data.................... ', end='')
    data, data_sizes, n_results = utils.parse_csv_to_data(filename, parse_time=parse_time)
    print(f'ok')

    # print('')
    # for i in range(len(data['size_out'])):
    #     print(f'data({i}) = {data["size_out"][i]}:{data["cycles_out"][i]}')
    # print('')
    if weight != 0:
        print(spacing + f'Removing outliers from data.............. ', end='')
        cycles_data, time_data = utils.filter_data(data, n_results, weight=weight)
        print(f'ok')
    
    # print('')
    # for i in range(len(cycles_data['size_out'])):
    #     print(f'cycles_data({i}) = {cycles_data["size_out"][i]}:{cycles_data["val_out"][i]}')
    # print('')

    print(spacing + f'[cycles] Grouping data................... ', end='')
    cycles_out, cycles_in = utils.group_data(cycles_data)
    print(f'ok')

    print(spacing + f'[cycles] Calculating statistics.......... ', end='')
    statistics = utils.calc_statistics(cycles_out, cycles_in)
    print(f'ok')

    print(spacing + f'[cycles] Generating figures.............. ', end='')
    make_scatter('cycles', path, cycles_data, data_sizes)
    make_plot('cycles', path, statistics)
    make_errorbar('cycles', path, statistics)
    print(f'ok')

    if parse_time:
        print(spacing + f'[time] Grouping data..................... ', end='')
        time_out, time_in = utils.group_data(time_data)
        print(f'ok')

        print(spacing + f'[time] Calculating statistics............ ', end='')
        statistics = utils.calc_statistics(time_out, time_in)
        print(f'ok')

        print(spacing + f'[time] Generating figures................ ', end='')
        make_scatter('time', path, time_data, data_sizes)
        make_plot('time', path, statistics)
        make_errorbar('time', path, statistics)
        print(f'ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'htf:c:m:', ['help', 'no_time', 'filter=', 'cfile=', 'mfile='])
    except getopt.GetoptError:
        print(f'One of the options does not exit.\nUse: "plotter.py -h" for help')
        sys.exit(2)

    if args:
        print(f'Could not parse {args}')
        sys.exit(2)

    parse_time = True
    weight = 2

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'plotter.py [-t] [-f <weight>] [-c <cipher_file>] [-m <md_file>]')
            print(f'plotter.py [--no_time] [--filter=<weight>] [--cfile=<cipher_file>] [--mfile=<md_file>]')
            sys.exit(0)
        if opt in ('-t', '--no_time'):
            parse_time = False
        if opt in ('-f', '--nfilter'):
            weight = int(arg)
        elif opt in ('-c', '--cfile') or opt in ('-m', '--mfile'):
            make_figs(arg, parse_time, weight)
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

if __name__ == '__main__':
   main(sys.argv[1:])