import csv


def csv_to_data(filename, parse_usec=False):
    with open(filename, mode='r') as fl:
        csv_reader = csv.DictReader(fl)
        
        data = {
             'output_size': [], 'cycles_out': [],
             'input_size': [], 'cycles_in': []
        }
        cycles_out = {}
        cycles_in = {}
        usec_out = None
        usec_in = None

        if parse_usec:
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

            elif row['operation'] == 'decrypt' or row['operation'] == 'verify':
                data['input_size'].append(int(key))
                data['cycles_in'].append(int(row['cycles']))
                cycles_in[key].append(int(row['cycles']))

                if parse_usec:
                    usec_in[key].append(int(row['usec']))

        return data, cycles_out, cycles_in, usec_out, usec_in

def txt_to_list(filename):
    with open(filename, 'r') as fl:
        ciphersuites = [line.strip() for line in fl.readlines()]

        return ciphersuites