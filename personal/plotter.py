import sys, getopt
import csv
import matplotlib.pyplot as plt
import statistics

def custom_errorbar(x, y, e, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.errorbar(x, y, yerr=e, **kwargs)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)

    return(ax)

def custom_scatter(x, y, ax=None, title=None, xlabel=None, ylabel=None, kwargs={}):
    if ax is None:
        ax = plt.gca()

    ax.scatter(x, y, **kwargs)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)

    return(ax)

def multiple_custom_plots(x, y1, y2, ax=None, title=None, xlabel=None, ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()
    
    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=title)
    ax.legend()

    return(ax)

def scatter(ylabel, plotname, out_op, in_op):
    keys = []
    x = []
    y1 = []
    y2 = []
    mean1 = []
    mean2 = []
    std1 = []
    std2 = []

    for key in out_op.keys():
        mean_out = statistics.mean(out_op[key])
        mean_in = statistics.mean(in_op[key])
        std_out = statistics.pstdev(out_op[key])
        std_in = statistics.pstdev(in_op[key])
        
        # print(f'out({key}) = {mean_out} +/- {std_out}')
        # print(f'in({key}) = {mean_in} +/- {std_in}')

        keys.append(key)
        mean1.append(mean_out)
        mean2.append(mean_in)
        std1.append(std_out)
        std2.append(std_in)

        for i in range(0, len(out_op[key])):
            x.append(key)
            y1.append(out_op[key][i])
            y2.append(in_op[key][i])

    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 15))
    params1 = {'color': 'red', 'marker': 'o'}
    params2 = {'color': 'blue', 'fmt': 'o'}

    if plotname.find('CIPHER'):
        plotname = plotname.replace('TLS-CIPHER-','')
        ax1 = custom_scatter(x, y1, ax=ax1, title='cipher', xlabel='input_size', ylabel=ylabel, kwargs=params1)
        ax2 = custom_errorbar(keys, mean1, std1, ax=ax2, title='cipher', xlabel='input_size', ylabel=ylabel, kwargs=params2)
        ax3 = custom_scatter(x, y2, ax=ax3, title='decipher', xlabel='input_size', ylabel=ylabel, kwargs=params1)
        ax4 = custom_errorbar(keys, mean2, std2, ax=ax4, title='decipher', xlabel='input_size', ylabel=ylabel, kwargs=params2)
    elif plotname.find('MD'):
        plotname = plotname.replace('TLS-MD-','')
        ax1 = custom_scatter(x, y1, ax=ax1, title='hash', xlabel='input_size', ylabel=ylabel, kwargs=params1)
        ax2 = custom_errorbar(keys, mean1, std1, ax=ax2, title='hash', xlabel='input_size', ylabel=ylabel, kwargs=params2)
        ax3 = custom_scatter(x, y2, ax=ax3, title='verify', xlabel='input_size', ylabel=ylabel, kwargs=params1)
        ax4 = custom_errorbar(keys, mean2, std2, ax=ax4, title='verify', xlabel='input_size', ylabel=ylabel, kwargs=params2)

    
    fig.tight_layout()
    fig.savefig('../docs/' + plotname + '-' + ylabel.upper() + '-DISTRIBUTION.png')
    
    plt.cla()

def plot(ylabel, plotname, out_op, in_op):
    x = out_op.keys()
    y1 = []
    y2 = []
    y3 = []
    y4 = []
    y5 = []
    y6 = []

    for key in out_op:
        mean = statistics.mean(out_op[key])
        median = statistics.median(out_op[key])
        mode = statistics.mode(out_op[key])

#        print(f'out_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
        y1.append(mean)
        y2.append(median)
        y3.append(mode)

        mean = statistics.mean(in_op[key])
        median = statistics.median(in_op[key])
        mode = statistics.mode(in_op[key])

#        print(f'in_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
        y4.append(mean)
        y5.append(median)
        y6.append(mode)

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))
    params1 = {}
    params2 = {}

    if plotname.find('CIPHER'):    
        plotname = plotname.replace('TLS-CIPHER-','')
        params1 = {'color': 'red', 'linestyle': '-', 'label': 'encryption'}
        params2 = {'color': 'blue', 'linestyle': '--', 'label': 'decryption'}
    elif plotname.find('MD'):
        plotname = plotname.replace('TLS-MD-','')
        params1 = {'color': 'red', 'linestyle': '-', 'label': 'digest'}
        params2 = {'color': 'blue', 'linestyle': '--', 'label': 'verify'}

    ax1 = multiple_custom_plots(x, y1, y4, ax=ax1, title='Mean', xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(x, y2, y5, ax=ax2, title='Median', xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(x, y3, y6, ax=ax3, title='Mode', xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    fig.tight_layout()
    fig.savefig('../docs/' + plotname + '-' + ylabel.upper() + '.png')
    
    plt.cla()

def parser(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        cycles_out = {}
        cycles_in = {}
        usec_out = {}
        usec_in = {}
        keys = []

        for row in csv_reader:
#            print(f'row: {row["endpoint"]}, {row["operation"]}, {row["input_size"]}, {row["cycles"]}, {row["usec"]}')            
            key = row['input_size']
            if key == 'close' or key == '48' or key == '2': # TODO: Change 48 and 2 to close
                continue
            elif not key in keys:
                keys.append(key)
                cycles_out[key] = []
                cycles_in[key] = []
                usec_out[key] = []
                usec_in[key] = []

            if row['operation'] == 'encrypt' or row['operation'] == 'digest':
                cycles_out[key].append(int(row['cycles']))
                usec_out[key].append(int(row['usec']))
            elif row['operation'] == 'decrypt' or row['operation'] == 'verify':
                cycles_in[key].append(int(row['cycles']))
                usec_in[key].append(int(row['usec']))

        return cycles_out, cycles_in, usec_out, usec_in

def make_graphs(filename):
        title = filename.replace('-II.csv', '')
        cycles_out, cycles_in, usec_out, usec_in = parser(filename)

        print(f'Making plot from {filename}')
        plot('cycles', title, cycles_out, cycles_in)
#        plot('usec', title, usec_out, usec_in)
        print(f'Done')

        print(f'Making scatter from {filename}')
        scatter('cycles', title, cycles_out, cycles_in)
#        scatter('usec', title, usec_out, usec_in)
        print(f'Done')

def main(argv):
    try:
        # opts, args = getopt.getopt(argv, 'h:c:m:k', ['help','cfile=','mfile=','kfile='])
        opts, args = getopt.getopt(argv, 'h:c:m', ['help','cfile=','mfile='])
    except getopt.GetoptError:
        # print(f'plotter.py -c <cipher_file> -m <md_file> -k <ke_file>')
        print(f'plotter.py -c <cipher_file> -m <md_file>')
        sys.exit(2)

    if args:
        print(f'Could not parse {args}')
        sys.exit(2)

    path = '../docs/'

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            # print(f'plotter.py -c <cipher_file> -m <md_file> -k <ke_file>')
            # print(f'plotter.py --cfile=<cipher_file> --mfile=<md_file> --kfile=<ke_file>')
            print(f'plotter.py -c <cipher_file> -m <md_file>')
            print(f'plotter.py --cfile=<cipher_file> --mfile=<md_file>')
            sys.exit(0)
        elif opt in ('-c', '--cfile') or opt in ('-m', '--mfile'):
            make_graphs(path + arg)
        # elif opt in ('-k', '--kfile'):
        #     files['ke'] = path + arg        

if __name__ == '__main__':
   main(sys.argv[1:])