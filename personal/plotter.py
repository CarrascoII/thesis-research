import sys, getopt
import matplotlib.pyplot as plt
import parser


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

def custom_scatter(x, y, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    # ticks = []
    # ticks_unique = []
    # ticks_label = []
    # counter = 0
    # for val in x:
    #     if val not in ticks_label:
    #         ticks_label.append(val)
    #         counter += 1
    #         ticks_unique.append(counter)
    #     ticks.append(counter)

    ax.scatter(x, y, marker='.', **kwargs)
    ax.set_xscale('log', base=2)
#    ax.scatter(ticks, y, marker='.', **kwargs)
#    ax.set_xticks(ticks_unique)
#    ax.set_xticklabels(ticks_label)
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

    fig.tight_layout()
    fig.savefig(file_path + ylabel + '_deviation.png')
    plt.close(fig)
    plt.cla()

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

    fig.tight_layout()
    fig.savefig(file_path + ylabel + '_statistics.png')
    plt.close(fig)
    plt.cla()

def make_scatter(ylabel, file_path, data):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

    operations = None
    keys = [ylabel + '_out', ylabel + '_in']

    params1 = {'color': 'red'}
    params2 = {'color': 'blue'}

    if file_path.find('cipher') != -1:
        operations = ['cipher', 'decipher']
    elif file_path.find('md') != -1:
        operations = ['hash', 'verify']

    ax1 = custom_scatter(data['output_size'], data[keys[0]], ax=ax1, title=operations[0], ylabel=ylabel, kwargs=params1)
    ax2 = custom_scatter(data['input_size'], data[keys[1]], ax=ax2, title=operations[1], ylabel=ylabel, kwargs=params2)

    fig.tight_layout()
    fig.savefig(file_path + ylabel + '_distribution.png')
    plt.close(fig)
    plt.cla()

def make_figs(filename, usec=False, spacing=''):
        path = filename.replace('data.csv', '')

        print(spacing + f'Parsing obtained data.................... ', end='')
        data, cycles_out, cycles_in, usec_out, usec_in = parser.csv_to_data(filename, parse_usec=usec)
        print(f'ok')

        print(spacing + f'Calculating statistics (CPU cycles)...... ', end='')
        statistics = parser.calc_statistics(cycles_out, cycles_in)
        print(f'ok')

        print(spacing + f'Generating figures (CPU cycles).......... ', end='')
        make_scatter('cycles', path, data)
        make_plot('cycles', path, statistics)
        make_errorbar('cycles', path, statistics)
        print(f'ok')

        if usec_out != None and usec_in != None:
            print(spacing + f'Calculating statistics (useconds)........ ', end='')
            statistics = parser.calc_statistics(usec_out, usec_in)
            print(f'ok')

            print(spacing + f'Generating figures (useconds)............ ', end='')
            make_scatter('usec', path, data)
            make_plot('usec', path, statistics)
            make_errorbar('usec', path, statistics)
            print(f'ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hsc:m:', ['help', 'useconds', 'cfile=', 'mfile='])
    except getopt.GetoptError:
        print(f'One of the options does not exit.\nUse: "plotter.py -h" for help')
        sys.exit(2)

    if args:
        print(f'Could not parse {args}')
        sys.exit(2)

    usec = False

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'plotter.py [-s] [-c <cipher_file>] [-m <md_file>]')
            print(f'plotter.py [--useconds] [--cfile=<cipher_file>] [--mfile=<md_file>]')
            sys.exit(0)
        if opt in ('-s', '--useconds'):
            usec = True
        elif opt in ('-c', '--cfile') or opt in ('-m', '--mfile'):
            make_figs(arg, usec)
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

if __name__ == '__main__':
   main(sys.argv[1:])