import sys, getopt
import csv
import matplotlib.pyplot as plt
import statistics

def multiple_custom_plots(x, y1, y2, name, ax=None, xlabel=None, ylabel=None, kwargs1={}, kwargs2={}):
    if ax is None:
        ax = plt.gca()
    
    ax.plot(x, y1, **kwargs1)
    ax.plot(x, y2, **kwargs2)
    ax.set(xlabel=xlabel, ylabel=ylabel, title=name)
    ax.legend()

    return(ax)

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
    plotname = plotname.replace('../docs/TLS-','')

    if plotname.find('CIPHER') == 0:    
        params1 = {'color': 'red', 'linestyle': '-', 'label': 'encryption'}
        params2 = {'color': 'blue', 'linestyle': '--', 'label': 'decryption'}
    elif plotname.find('MD') == 0:
        params1 = {'color': 'red', 'linestyle': '-', 'label': 'digest'}
        params2 = {'color': 'blue', 'linestyle': '--', 'label': 'verify'}

    ax1 = multiple_custom_plots(x, y1, y4, 'Mean', ax=ax1, xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(x, y2, y5, 'Median', ax=ax2, xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(x, y3, y6, 'Mode', ax=ax3, xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

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

def main(argv):
    path = '../docs/'
    files = {}

    try:
        opts, args = getopt.getopt(argv, 'h:c:m:k', ['help','cfile=','mfile=','kfile='])
    except getopt.GetoptError:
        print(f'plotter.py -c <cipher_file> -m <md_file> -k <ke_file>')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'plotter.py -c <cipher_file> -m <md_file> -k <ke_file>')
            print(f'plotter.py --cfile=<cipher_file> --mfile=<md_file> --kfile=<ke_file>')
            sys.exit()
        elif opt in ('-c', '--cfile'):
            files['cipher'] = path + arg
        elif opt in ('-m', '--mfile'):
            files['md'] = path + arg
        elif opt in ('-k', '--kfile'):
            files['ke'] = path + arg

    for file_type in files:
        title = files[file_type].replace('-II.csv', '')

#        if file_type != 'ke':
        print(f'Making plot from {title}.csv')
        cycles_out, cycles_in, usec_out, usec_in = parser(files[file_type])
        plot('cycles', title, cycles_out, cycles_in)
        plot('usec', title, usec_out, usec_in)
        # else:
        #     cycles_hash, cycles_ver, usec_hash, usec_ver = ke_parser(files[file_type])
        #     plot('cycles', cipher, cycles_out, cycles_in)
        #     plot('usec', cipher, usec_out, usec_in)
        

if __name__ == '__main__':
   main(sys.argv[1:])