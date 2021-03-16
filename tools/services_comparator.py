import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_record_alg_cmp_bar(serv, operations, ylabel, stats, stats_type):
    labels = list(stats.keys())
    xtickslabels = []
    extentions = []

    if serv == 'conf' or serv == 'int':
        extentions = ['_out', '_in']
        xtickslabels = stats[next(iter(stats))]['keys']

    elif serv == 'auth' or serv == 'pfs':
        extentions = ['_server', '_client']
        xtickslabels = ['Sec Lvl 0', 'Sec Lvl 1', 'Sec Lvl 2', 'Sec Lvl 3']

    for stype in stats_type:
        for ext, op in zip(extentions, operations):
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []
        
            for key in stats:
                y.append(stats[key][stype + '_' + ylabel + ext])
                yerr.append(stats[key]['stddev_' + ylabel + ext])

            ax = utils.multiple_custom_bar(y, yerr, ax=ax, title=op + ' (' + stype + ')',
                                        labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)
            utils.save_fig(fig, '../docs/serv_' + serv + '_' + op + '_' + stype + '_' + ylabel + '.png')

def make_pfs_cmp_figs(pfs_suites, non_pfs_suites, serv, labels, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    all_alt_data = {}
    headers = []

    print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for key in pfs_suites:
        all_data[key] = {}
        all_alt_data[key] = {}

        for suite in pfs_suites[key]:
            path = '../docs/' + suite + '/ke_data.csv'
            data, hdr = utils.parse_handshake_data(path)

            if all_data[key] == {}:
                all_data[key] = data
                headers = hdr
            
            elif headers == hdr:
                for key1, key2 in zip(list(all_data[key].keys()), list(data.keys())):
                    for entry in data[key2]:
                        all_data[key][key1][entry] += data[key2][entry]

            else:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
                return None

        for suite in non_pfs_suites[key]:
            path = '../docs/' + suite + '/ke_data.csv'
            data, hdr = utils.parse_handshake_data(path)

            if all_alt_data[key] == {}:
                all_alt_data[key] = data
                headers = hdr
            
            elif headers == hdr:
                for key1, key2 in zip(list(all_alt_data[key].keys()), list(data.keys())):
                    for entry in data[key2]:
                        all_alt_data[key][key1][entry] += data[key2][entry]

            else:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
                return None

        if all_data[key] == {} or all_alt_data[key] == {}:
            all_data.pop(key)
            all_alt_data.pop(key)

    print('ok')

    if weight != 0:
        print(f'{spacing}  Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for key in all_data:
            data = utils.filter_iqr(all_data[key], weight=weight)
            all_data[key] = data

            alt_data = utils.filter_iqr(all_alt_data[key], weight=weight)
            all_alt_data[key] = alt_data
        
        print('ok')

    print(f'{spacing}  Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    all_stats = {}
    stats_type = ['mean', 'stddev']

    for key in all_data:
        stats = utils.calc_pfs_statistics(all_data[key], all_alt_data[key], stats_type, headers)

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')
    print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    
    path = '../docs/serv_' + serv + '_'
    utils.write_handshake_cmp_csv(path, 'algorithm', labels, all_stats)
    
    print('ok')
    print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_record_alg_cmp_bar(serv, labels, hdr, all_stats, stats_type[:-1])

    print('ok')

def make_serv_cmp_figs(grouped_suites, serv, labels, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    headers = []
    data_files = {'conf': 'cipher', 'int': 'md', 'auth': 'ke'}

    data_ops = {
        'conf': utils.parse_record_data,
        'int': utils.parse_record_data,
        'auth': utils.parse_handshake_data
    }

    write_ops = {
        'conf': utils.write_record_cmp_csv,
        'int': utils.write_record_cmp_csv,
        'auth': utils.write_handshake_cmp_csv
    }

    print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for key in grouped_suites:
        all_data[key] = {}

        for suite in grouped_suites[key]:
            path = '../docs/' + suite + '/' + data_files[serv] + '_data.csv'
            data, hdr = data_ops[serv](path)

            if all_data[key] == {}:
                all_data[key] = data
                headers = hdr
            
            elif headers == hdr:
                for key1, key2 in zip(list(all_data[key].keys()), list(data.keys())):
                    for entry in data[key2]:
                        all_data[key][key1][entry] += data[key2][entry]

            else:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
                return None

        if all_data[key] == {}:
            all_data.pop(key)

    print('ok')

    if weight != 0:
        print(f'{spacing}  Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for key in all_data:
            data = utils.filter_iqr(all_data[key], weight=weight)
            all_data[key] = data
        
        print('ok')

    print(f'{spacing}  Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    all_stats = {}
    stats_type = ['mean', 'stddev']

    for key in all_data:
        stats = utils.calc_statistics(all_data[key], stats_type)

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')
    print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    
    path = '../docs/serv_' + serv + '_'
    write_ops[serv](path, 'algorithms', labels, all_stats)
    
    print('ok')
    print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_record_alg_cmp_bar(serv, labels, hdr, all_stats, stats_type[:-1])

    print('ok')

def make_figs(servs_fname, ciphersuites, serv_set=['conf', 'int', 'auth', 'pfs'],
            labels={'conf': ['encrypt', 'decrypt'], 'int': ['hash', 'verify'], 'auth': ['server', 'client'],
            'pfs': ['server', 'client']}, weight=1.5, strlen=40, spacing=''):
    servs = utils.parse_services_grouped(servs_fname, serv_set, ciphersuites)

    for serv in serv_set:
        print(f'{spacing}\n{serv.upper()} data:')

        if serv != 'pfs':
            make_serv_cmp_figs(servs[serv], serv, labels[serv], weight=weight, strlen=strlen, spacing=spacing)
        
        else:
            make_pfs_cmp_figs(servs['pfs'], servs['non-pfs'], serv, labels[serv], weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:caip', ['help', 'filter=', 'conf', 'int', 'auth', 'pfs'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No inputs where given')
        sys.exit(2)

    if len(args) > 2:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5
    suites = []
    servs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('services_comparator.py [-f <weight>] [-c] [-i] [-a] [-p] <services_list> <ciphersuite_list>')
            print('services_comparator.py [--filter=<weight>] [--conf] [--int] [--auth] [--pfs] <services_list> <ciphersuite_list>')
            sys.exit(0)

        elif opt in ('-f', '--filter'):
            weight = float(arg)

        elif opt in ('-c', '--conf'):
            servs.append('conf')

        elif opt in ('-i', '--int'):
            servs.append('int')

        elif opt in ('-a', '--auth'):
            servs.append('auth')

        elif opt in ('-p', '--pfs'):
            servs.append('pfs')

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    suites = utils.parse_ciphersuites(args[1])
    
    make_figs(args[0], suites, weight=weight, serv_set=servs)

if __name__ == '__main__':
   main(sys.argv[1:])