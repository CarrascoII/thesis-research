import csv
import statistics


def parse_csv_to_data(filename):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        headers = csv_reader.fieldnames[3:]
        data = {}
        data_keys = {}

        for header in headers:
            for ext in ['_out', '_in']:
                entry = header + ext
                data[entry] = {}
                data_keys[entry] = [] 

        for row in csv_reader:
            data_size = row['data_size']
            operation = row['operation']

            for header in headers:
                val = int(row[header])

                if val != 0:
                    # print(f'\nrow: operation = {operation}, data_size = {data_size}, {header} = {val}')
                    if operation == 'encrypt' or operation == 'digest':
                        header += '_out'
                    elif operation == 'decrypt' or operation == 'verify':
                        header += '_in'

                    if data_size not in data_keys[header]:
                        data_keys[header].append(data_size)
                        data[header][data_size] = []

                    data[header][data_size].append(val)
        
        return data, headers

def filter_z_score(data, headers, weight=2):
    for header in headers:
        for ext in ['_out', '_in']:
            entry = header + ext
            op_dict = data[entry]
            
            for key in op_dict:
                mean = statistics.mean(op_dict[key])
                stdev = statistics.pstdev(op_dict[key])
                tmp = []
                # print(f'\nAnalysing data[{entry}][{key}] = {op_dict[key]}')
                # print(f'Statistics = {mean} +/- {stdev}')
                for val in op_dict[key]:
                    stdw = weight * stdev
                    # print(f'z_score({val}) = {(val - mean) / stdev}')
                    if val > (mean + stdw):
                        continue
                    elif val < (mean - stdw):
                        continue
                    else:
                        tmp.append(val)
                
                data[entry][key] = tmp

    return data

def calc_statistics(out_op, in_op):
    stats = {
        'data_size': [],
        'mean_out': [], 'mean_in': [],
        'stdev_out': [], 'stdev_in': [],
        'median_out': [], 'median_in': [],
        'mode_out': [], 'mode_in': []
    }

    for key in out_op:
        stats['data_size'].append(key)

#        print(f'\nout_op for {key}:\n{out_op[key]}')
        mean = statistics.mean(out_op[key])
        stdev = statistics.pstdev(out_op[key])
        median = statistics.median(out_op[key])
        mode = statistics.mode(out_op[key])
#        print(f'out_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
#        print(f'\nout_op({key}) = {mean} +/- {stdev}')

        stats['mean_out'].append(mean)
        stats['stdev_out'].append(stdev)
        stats['median_out'].append(median)
        stats['mode_out'].append(mode)

#        print(f'\nin_op for {key}:\n{in_op[key]}')
        mean = statistics.mean(in_op[key])
        stdev = statistics.pstdev(in_op[key])
        median = statistics.median(in_op[key])
        mode = statistics.mode(in_op[key])
#        print(f'in_op: key = {key}, mean = {mean}, median = {median}, mode = {mode}')
#        print(f'in_op({key}) = {mean} +/- {stdev}')

        stats['mean_in'].append(mean)
        stats['stdev_in'].append(stdev)
        stats['median_in'].append(median)
        stats['mode_in'].append(mode)

    return stats

def parse_txt_to_list(filename):
    with open(filename, 'r') as fl:
        return [line.strip() for line in fl.readlines()]