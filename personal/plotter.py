import sys, getopt
import matplotlib.pyplot as plt
import statistics
import parser


def custom_errorbar(x, y, e, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, **kwargs)
    ax.set(xlabel='data_size', ylabel=ylabel, title=title)

    return(ax)

def custom_scatter(x, y, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, **kwargs)
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

def scatter(ylabel, file_path, data, stats):
    fig, (ax1, ax2, ax3, ax4) = plt.subplots(1, 4, figsize=(20, 5))
    
    operations = None
    params1 = {'color': 'red', 'marker': '.'}
    params2 = {'color': 'red', 'fmt': 'o'}
    params3 = {'color': 'blue', 'marker': '.'}
    params4 = {'color': 'blue', 'fmt': 'o'}

    if file_path.find('cipher'):
        operations = ['cipher', 'decipher']
    elif file_path.find('md'):
        operations = ['hash', 'verify']

    ax1 = custom_scatter(data['output_size'], data['cycles_out'], ax=ax1, title=operations[0], ylabel=ylabel, kwargs=params1)
    ax2 = custom_errorbar(stats['data_size'], stats['mean_out'], stats['stdev_out'], ax=ax2, title=operations[0], ylabel=ylabel, kwargs=params2)
    ax3 = custom_scatter(data['input_size'], data['cycles_in'], ax=ax3, title=operations[1], ylabel=ylabel, kwargs=params3)
    ax4 = custom_errorbar(stats['data_size'], stats['mean_in'], stats['stdev_in'], ax=ax4, title=operations[1], ylabel=ylabel, kwargs=params4)

    fig.tight_layout()
    fig.savefig(file_path + '_' + ylabel + '_distribution.png')
    
    plt.cla()

def plot(ylabel, file_path, stats):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
    
    params1 = {'color': 'red', 'linestyle': '-'}
    params2 = {'color': 'blue', 'linestyle': '--'}

    if file_path.find('cipher'):
        params1['label'] = 'encryption'
        params2['label'] = 'decryption'
    elif file_path.find('md'):
        params1['label'] = 'digest'
        params2['label'] = 'verify'

    ax1 = multiple_custom_plots(stats['data_size'], stats['mean_out'], stats['mean_in'],
                                ax=ax1, title='Mean', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(stats['data_size'], stats['median_out'], stats['median_in'],
                                ax=ax2, title='Median', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(stats['data_size'], stats['mode_out'], stats['mode_in'],
                                ax=ax3, title='Mode', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    fig.tight_layout()
    fig.savefig(file_path + '_' + ylabel + '.png')
    
    plt.cla()

def calc_statistics(out_op, in_op):
    data_size = []
    mean_out = []
    stdev_out = []
    median_out = []
    mode_out = []
    mean_in = []
    stdev_in = []
    median_in = []
    mode_in = []

    for key in out_op:
        data_size.append(key)

#        print(f'out_op for {key}:\n{out_op[key]}')
        mean = statistics.mean(out_op[key])
        stdev = statistics.pstdev(out_op[key])
        median = statistics.median(out_op[key])
        mode = statistics.mode(out_op[key])
#        print(f'out_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')

        mean_out.append(mean)
        stdev_out.append(stdev)
        median_out.append(median)
        mode_out.append(mode)

#        print(f'in_op for {key}:\n{in_op[key]}')
        mean = statistics.mean(in_op[key])
        stdev = statistics.pstdev(in_op[key])
        median = statistics.median(in_op[key])
        mode = statistics.mode(in_op[key])
#        print(f'in_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')

        mean_in.append(mean)
        stdev_in.append(stdev)
        median_in.append(median)
        mode_in.append(mode)

    return {
        'data_size': data_size,
        'mean_out': mean_out, 'mean_in': mean_in,
        'stdev_out': stdev_out, 'stdev_in': stdev_in,
        'median_out': median_out, 'median_in': median_in,
        'mode_out': mode_out, 'mode_in': mode_in
    }

def make_graphs(filename, usec=False):
        path = filename.replace('data.csv', '')

        print(f'Parsing {filename}... ', end='')
        data, cycles_out, cycles_in, usec_out, usec_in = parser.csv_to_data(filename, parse_usec=usec)
        print(f'Done')

        print(f'Calculating statistics (CPU cycles) from {filename}... ', end='')
        statistics = calc_statistics(cycles_out, cycles_in)
        print(f'Done')

        print(f'Making plot (CPU cycles) from {filename}... ', end='')
        plot('cycles', path, statistics)
        print(f'Done')

        print(f'Making scatter (CPU cycles) from {filename}... ', end='')
        scatter('cycles', path, data, statistics)
        print(f'Done')

        if usec_out != None and usec_in != None:
            print(f'Calculating statistics (useconds) from {filename}... ', end='')
            statistics = calc_statistics(usec_out, usec_in)
            print(f'Done')

            print(f'Making plot (useconds) from {filename}... ', end='')
            plot('usec', path, statistics)
            print(f'Done')

            print(f'Making scatter (useconds) from {filename}... ', end='')
            scatter('usec', path, data, statistics)
            print(f'Done')

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
            make_graphs(arg, usec)
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

if __name__ == '__main__':
   main(sys.argv[1:])