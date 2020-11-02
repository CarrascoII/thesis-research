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

def plot(ylabel, plotname, encryption, decryption):
    x = encryption.keys()
    y1 = []
    y2 = []
    y3 = []
    y4 = []
    y5 = []
    y6 = []

    for key in encryption:
        mean = statistics.mean(encryption[key])
        median = statistics.median(encryption[key])
        mode = statistics.mode(encryption[key])

        print(f'encryption: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
        y1.append(mean)
        y2.append(median)
        y3.append(mode)

        mean = statistics.mean(decryption[key])
        median = statistics.median(decryption[key])
        mode = statistics.mode(decryption[key])

        print(f'decryption: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
        y4.append(mean)
        y5.append(median)
        y6.append(mode)

    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(15, 5))

    params1 = {'color': 'red', 'linestyle': '-', 'label': 'encryption'}
    params2 = {'color': 'blue', 'linestyle': '--', 'label': 'decryption'}

    ax1 = multiple_custom_plots(x, y1, y4, 'Mean', ax=ax1, xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax2 = multiple_custom_plots(x, y2, y5, 'Median', ax=ax2, xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)
    ax3 = multiple_custom_plots(x, y3, y6, 'Mode', ax=ax3, xlabel='input_size', ylabel=ylabel, kwargs1=params1, kwargs2=params2)

    fig.tight_layout()
    fig.savefig('../docs/' + plotname + '-' + ylabel.upper() + '.png')
    
    plt.cla()

def parser(filename):
    print(f'parser:\tInput file is {filename}')

    with open(filename, mode='r') as file:
        csv_reader = csv.DictReader(file)
        cycles_enc = {}
        cycles_dec = {}
        usec_enc = {}
        usec_dec = {}

        for row in csv_reader:
            # print(f'row: {row["input_size"]}, {row["enc_cycles"]}, {row["enc_usec"]}, {row["dec_cycles"]}, {row["dec_usec"]}')            
            
            key = row["input_size"]
            if(key == 'close'):
                continue

            elif(not key in cycles_enc.keys() and not key in cycles_dec.keys() and
               not key in usec_enc.keys() and not key in usec_dec.keys()):
                cycles_enc[key] = []
                cycles_dec[key] = []
                usec_enc[key] = []
                usec_dec[key] = []

            cycles_enc[key].append(int(row["enc_cycles"]))
            cycles_dec[key].append(int(row["dec_cycles"]))
            usec_enc[key].append(int(row["enc_usec"]))
            usec_dec[key].append(int(row["dec_usec"]))

        # print(f'\n{cycles_enc}')
        return cycles_enc, cycles_dec, usec_enc, usec_dec

def main(argv):
    inputfile = ''
    try:
        opts, args = getopt.getopt(argv,'hi:o:', ['ifile='])
    except getopt.GetoptError:
        print(f'plotter.py -i <inputfile>')
        sys.exit(2)

    for opt, arg in opts:
        if opt == '-h':
            print(f'plotter.py -i <inputfile>')
            sys.exit()
        elif opt in ('-i', '--ifile'):
            inputfile = arg
    print(f'main:\tInput file is {inputfile}')

    cycles_enc, cycles_dec, usec_enc, usec_dec = parser('../docs/' + inputfile)

    cipher = inputfile.replace('.csv', '')
    plot('cycles', cipher, cycles_enc, cycles_dec)
    plot('usec', cipher, usec_enc, usec_dec)

if __name__ == '__main__':
   main(sys.argv[1:])