import csv
import statistics


def parse_csv_to_data(filename, parse_time=True):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)

        data_sizes = []
        size_out = []
        size_in = []
        cycles_out = []
        cycles_in = []
        time_out = []
        time_in = []

        for row in csv_reader:
#            print(f'row: {row["endpoint"]}, {row["operation"]}, {row["data_size"]}, {row["cycles"]}, {row["time"]}')
            key = int(row['data_size'])

            if key not in data_sizes:
                data_sizes.append(key)

            if row['operation'] == 'encrypt' or row['operation'] == 'digest':
                size_out.append(key)
                cycles_out.append(int(row['cycles']))

                if parse_time:
                    time_out.append(int(row['time']))

            elif row['operation'] == 'decrypt' or row['operation'] == 'verify':
                size_in.append(key)
                cycles_in.append(int(row['cycles']))

                if parse_time:
                    time_in.append(int(row['time']))

        n_results = int(len(size_out) // len(data_sizes))

        data = {
            'size_out': size_out, 'size_in': size_in,
            'cycles_out': cycles_out, 'cycles_in': cycles_in,
            'time_out': time_out, 'time_in': time_in
        }

        return data, data_sizes, n_results

def filter_data(data, n_results, weight=2, filter_time=True):
    cycles_data = {
        'size_out': [], 'size_in': [],
        'val_out': [], 'val_in': []
    }

    time_data = {
        'size_out': [], 'size_in': [],
        'val_out': [], 'val_in': []
    }

    n_data_sizes = int(len(data['size_out']) // n_results)
    keys = ['cycles_']
    operations = ['out', 'in']

    if filter_time:
        keys.append('time_')

    for key in keys:
        for op in operations:
            entry = key + op

            for i in range(n_data_sizes):
                start = int(i * n_results)
                end = int((i + 1) * n_results)

                mean = statistics.mean(data[entry][start:end])
                stdev = statistics.pstdev(data[entry][start:end])

                # print('')
                # print(f'Analysing data[{entry}][{start}:{end-1}] = {data[entry][start:end]}')
                # print(f'Statistics = {mean} +/- {stdev}')

                for j in range(n_results):
                    pos = i * n_results + j

                    if data[entry][pos] == 0:
                        continue

                    stdw = weight * stdev
                    # print(f'\ndata[{entry}][{pos}] = {data[entry][pos]}')
                    # print(f'z_score = {(data[entry][pos] - mean) / stdev}')
                    
                    if data[entry][pos] > (mean + stdw):
                        continue
                    elif data[entry][pos] < (mean - stdw):
                        continue
                    else:
                        if key == 'cycles_':
                            cycles_data['size_' + op].append(data['size_' + op][pos])
                            cycles_data['val_' + op].append(data[entry][pos])

                        elif key == 'time_':
                            time_data['size_' + op].append(data['size_' + op][pos])
                            time_data['val_' + op].append(data[entry][pos])

            # if key == 'cycles_':
            #     print(f'\ndata[{entry}]: inital = {len(data["size_" + op])}, finish = {len(cycles_data["size_" + op])}')
            # elif key == 'time_':
            #     print(f'\ndata[{entry}]: inital = {len(data["size_" + op])}, finish = {len(time_data["size_" + op])}')
            # print('---------------------------------------------------------------------------------------------------')

    return cycles_data, time_data

def group_data(data):
    keys_out = []
    keys_in = []
    dict_out = {}
    dict_in = {}

    for i in range(len(data['size_out'])):
        key = str(data['size_out'][i])

        if key not in keys_out:
            keys_out.append(key)
            dict_out[key] = []

        dict_out[key].append(data['val_out'][i])

    for i in range(len(data['size_in'])):
        key = str(data['size_in'][i])

        if key not in keys_in:
            keys_in.append(key)
            dict_in[key] = []

        dict_in[key].append(data['val_in'][i])

    return dict_out, dict_in

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