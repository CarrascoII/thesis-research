import sys, getopt
import csv
import matplotlib.pyplot as plt
import statistics

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

def scatter(ylabel, plotname, data, stats):
    fig, (ax1, ax2, ax3, ax4) = plt.subplots(1, 4, figsize=(20, 5))
    
    operations = None
    params1 = {'color': 'red', 'marker': '.'}
    params2 = {'color': 'red', 'fmt': 'o'}
    params3 = {'color': 'blue', 'marker': '.'}
    params4 = {'color': 'blue', 'fmt': 'o'}

    if plotname.find('CIPHER'):
        operations = ['cipher', 'decipher']
    elif plotname.find('MD'):
        operations = ['hash', 'verify']

    ax1 = custom_scatter(data['output_size'], data['cycles_out'], ax=ax1, title=operations[0], ylabel=ylabel, kwargs=params1)
    ax2 = custom_errorbar(stats['data_size'], stats['mean_out'], stats['stdev_out'], ax=ax2, title=operations[0], ylabel=ylabel, kwargs=params2)
    ax3 = custom_scatter(data['input_size'], data['cycles_in'], ax=ax3, title=operations[1], ylabel=ylabel, kwargs=params3)
    ax4 = custom_errorbar(stats['data_size'], stats['mean_in'], stats['stdev_in'], ax=ax4, title=operations[1], ylabel=ylabel, kwargs=params4)

    fig.tight_layout()
    fig.savefig('../docs/' + plotname + '-DISTRIBUTION.png')
    
    plt.cla()

def plot(ylabel, plotname, stats):
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
    
    params1 = {'color': 'red', 'linestyle': '-'}
    params2 = {'color': 'blue', 'linestyle': '--'}

    if plotname.find('CIPHER'):    
        params1['label'] = 'encryption'
        params2['label'] = 'decryption'
    elif plotname.find('MD'):
        params1['label'] = 'digest'
        params2['label'] = 'verify'

    ax1 = multiple_custom_plots(stats['data_size'], stats['mean_out'], stats['mean_in'],
                                ax=ax1, title='Mean', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(stats['data_size'], stats['median_out'], stats['median_in'],
                                ax=ax2, title='Median', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(stats['data_size'], stats['mode_out'], stats['mode_in'],
                                ax=ax3, title='Mode', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    fig.tight_layout()
    fig.savefig('../docs/' + plotname + '-' + ylabel.upper() + '.png')
    
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

def csv_parser(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        
        data = {
             'output_size': [], 'input_size': [],
            'cycles_out': [], 'cycles_in': []
        }
        cycles_out = {}
        cycles_in = {}
        # usec_out = {}
        # usec_in = {}

        for row in csv_reader:
#            print(f'row: {row["endpoint"]}, {row["operation"]}, {row["data_size"]}, {row["cycles"]}, {row["usec"]}')            
            
            key = row['data_size']
            if key == 'close' or key == '48' or key == '2': # TODO: Change 48 and 2 to close
                continue
            elif not int(key) in data['output_size']:
                cycles_out[key] = []
            elif not int(key) in data['input_size']:
                cycles_in[key] = []
                # usec_out[key] = []
                # usec_in[key] = []


            if row['operation'] == 'encrypt' or row['operation'] == 'digest':
                data['output_size'].append(int(key))
                data['cycles_out'].append(int(row['cycles']))
                cycles_out[key].append(int(row['cycles']))
#                usec_out[key].append(int(row['usec']))
            elif row['operation'] == 'decrypt' or row['operation'] == 'verify':
                data['input_size'].append(int(key))
                data['cycles_in'].append(int(row['cycles']))
                cycles_in[key].append(int(row['cycles']))
#                usec_in[key].append(int(row['usec']))

#        return data, cycles_out, cycles_in, usec_out, usec_in
        return data, cycles_out, cycles_in

def make_graphs(filename):
        title = filename.replace('.csv', '')
#        cycles_out, cycles_in, usec_out, usec_in = csv_parser(filename)
        print(f'Parsing {filename}')
        data, cycles_out, cycles_in = csv_parser(filename)
        print(f'Done')

        print(f'Calculating statistics from {filename}')
        statistics = calc_statistics(cycles_out, cycles_in)
        print(f'Done')

        print(f'Making plot from {filename}')
        plot('cycles', title, statistics)
#        plot('usec', title, usec_out, usec_in)
        print(f'Done')

        print(f'Making scatter from {filename}')
        scatter('cycles', title, data, statistics)
#        scatter('usec', title, usec_out, usec_in)
        print(f'Done')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'h:c:m', ['help','cfile=','mfile='])
    except getopt.GetoptError:
        print(f'plotter.py -c <cipher_file> -m <md_file>')
        sys.exit(2)

    if args:
        print(f'Could not parse {args}')
        sys.exit(2)

    path = '../docs/'

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'plotter.py -c <cipher_file> -m <md_file>')
            print(f'plotter.py --cfile=<cipher_file> --mfile=<md_file>')
            sys.exit(0)
        elif opt in ('-c', '--cfile') or opt in ('-m', '--mfile'):
            make_graphs(path + arg)

if __name__ == '__main__':
   main(sys.argv[1:])