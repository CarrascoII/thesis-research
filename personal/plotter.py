import sys, getopt
import csv
import matplotlib.pyplot as plt
import statistics

def plot(ylabel, plotname, encryption, decryption):
    x = encryption.keys()
    y1 = []
    y2 = []
    y3 = []
    y4 = []

    for key in encryption:
        mean = statistics.mean(encryption[key])
        median = statistics.median(encryption[key])
        mode = statistics.mode(encryption[key])

        print(f'encryption: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
        y1.append(mean)
        y2.append(median)

        mean = statistics.mean(decryption[key])
        median = statistics.median(decryption[key])
        mode = statistics.mode(decryption[key])

        print(f'decryption: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
        y3.append(mean)
        y4.append(median)

    plt.plot(x, y1, label = "encryption_mean")
    plt.plot(x, y3, label = "decryption_mean") 

    plt.plot(x, y2, label = "encryption_median")
    plt.plot(x, y4, label = "decryption_median") 

    plt.xlabel('input_size')
    plt.ylabel(ylabel) 
    plt.title(plotname)
    
    plt.legend()
    plt.show()
    plt.savefig('../docs/' + ylabel + '_' + plotname + '.png')
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
    plot('CPU cycles', cipher, cycles_enc, cycles_dec)
    plot('microseconds', cipher, usec_enc, usec_dec)

if __name__ == '__main__':
   main(sys.argv[1:])