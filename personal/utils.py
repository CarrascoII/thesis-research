import csv
import statistics


def parse_csv_to_data(filename, parse_usec=False):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        
        data = {
            'output_size': [], 'input_size': [],
            'cycles_out': [], 'cycles_in': [],
            'usec_out': [], 'usec_in': []
        }
        cycles_out = {}
        cycles_in = {}
        usec_out = {}
        usec_in = {}

        for row in csv_reader:
#            print(f'row: {row["endpoint"]}, {row["operation"]}, {row["data_size"]}, {row["cycles"]}, {row["usec"]}')            
            key = row['data_size']

            if not int(key) in data['output_size']:
                cycles_out[key] = []
                if parse_usec:
                    usec_out[key] = []

            elif not int(key) in data['input_size']:
                cycles_in[key] = []
                if parse_usec:
                    usec_in[key] = []

            if row['operation'] == 'encrypt' or row['operation'] == 'digest':
                data['output_size'].append(int(key))
                data['cycles_out'].append(int(row['cycles']))
                cycles_out[key].append(int(row['cycles']))
                
                if parse_usec:
                    usec_out[key].append(int(row['usec']))
                    data['usec_out'].append(int(row['usec']))

            elif row['operation'] == 'decrypt' or row['operation'] == 'verify': 
                data['input_size'].append(int(key))
                data['cycles_in'].append(int(row['cycles']))
                cycles_in[key].append(int(row['cycles']))
                
                if parse_usec:
                    usec_in[key].append(int(row['usec']))
                    data['usec_in'].append(int(row['usec']))

        return data, cycles_out, cycles_in, usec_out, usec_in

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

#        print(f'\nout_op for {key}:\n{out_op[key]}')
        mean = statistics.mean(out_op[key])
        stdev = statistics.pstdev(out_op[key])
        median = statistics.median(out_op[key])
        mode = statistics.mode(out_op[key])
#        print(f'out_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
#        print(f'\nout_op({key}) = {mean} +/- {stdev}')

        mean_out.append(mean)
        stdev_out.append(stdev)
        median_out.append(median)
        mode_out.append(mode)

#        print(f'\nin_op for {key}:\n{in_op[key]}')
        mean = statistics.mean(in_op[key])
        stdev = statistics.pstdev(in_op[key])
        median = statistics.median(in_op[key])
        mode = statistics.mode(in_op[key])
#        print(f'in_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
#        print(f'in_op({key}) = {mean} +/- {stdev}')

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

def parse_txt_to_list(filename):
    with open(filename, 'r') as fl:
        ciphersuites = [line.strip() for line in fl.readlines()]

        return ciphersuites

#def filter_outlines(dicts, means, stds):
