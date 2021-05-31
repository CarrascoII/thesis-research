import os
import sys, getopt
import matplotlib.pyplot as plt
import utils, settings


def make_record_alg_cmp_bar(serv, operations, ylabel, stats, stats_type):
    labels = list(stats.keys())
    xtickslabels = stats[next(iter(stats))]['keys']
    
    if serv != 'conf' and serv != 'int':
        for i, val in enumerate(xtickslabels):
            xtickslabels[i] = settings.sec_str[int(val)]

    for stype in stats_type:
        for op in operations:
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []
        
            for key in stats:
                y.append(stats[key][stype + '_' + ylabel + '_' + op])
                yerr.append(stats[key]['stddev_' + ylabel + '_' + op])

            ax = utils.multiple_custom_bar(y, yerr, ax=ax, title=op + ' (' + stype + ')',
                                        labels=labels, xtickslabels=xtickslabels, xlabel='security strength (in bits)', ylabel=ylabel)
            utils.save_fig(fig, '../docs/serv_' + serv + '_' + op + '_' + stype + '_' + ylabel + '.png')

def make_serv_cmp_figs(grouped_suites, serv, labels, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_stats = {}
    stats_type = ['mean', 'stddev']
    data_ops_params = {'serv': serv}
    data_ops_func = {
        'conf': utils.parse_record_data,
        'int': utils.parse_record_data,
        'auth': utils.parse_handshake_data,
        'ke': utils.parse_handshake_data,
        'pfs': utils.parse_handshake_data
    }

    print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for key in grouped_suites:
        all_data[key] = {}
        data_ops_params['alg'] = key

        for suite in grouped_suites[key]:
            data_ops_params['filename'] = '../docs/' + suite + '/'
            data, hdr = data_ops_func[serv](**data_ops_params)

            if data == {}:
                continue

            elif all_data[key] == {}:
                all_data[key] = data
                headers = hdr
            
            elif headers == hdr:
                for sub in list(all_data[key].keys()):
                    for entry in data[sub]:
                        if entry not in all_data[key][sub]:
                            all_data[key][sub][entry] = []

                        all_data[key][sub][entry] += data[sub][entry]

            else:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
                return None

            # print(f'\n{suite} ({key}):')
            # for a in data:
            #     print(f'  {a}')
            #     for b in data[a]:
            #         print(f'    {b}: {data[a][b]} : {len(data[a][b])}')
            #     print('')

        if all_data[key] == {}:
            all_data.pop(key)

    # print('')
    # for a in all_data:
    #     print(f'{a}:')
    #     for b in all_data[a]:
    #         print(f'  {b}:')            
    #         for c in all_data[a][b]:
    #             print(f'    {c}: {all_data[a][b][c]} : {len(all_data[a][b][c])}')
    #     print('')

    all_data = utils.sort_keys(all_data)
    print('ok')

    if weight != 0:
        print(f'{spacing}  Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for key in all_data:
            data = utils.filter_iqr(all_data[key], weight=weight)
            all_data[key] = data
        
        print('ok')

    print(f'{spacing}  Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for key in all_data:
        stats = utils.calc_statistics(all_data[key], stats_type)

        # print(f'\nstats[{key}]:\n{list(stats.keys())}')

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')

    print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    utils.write_serv_cmp_csv('../docs/serv_' + serv + '_', 'algorithms', serv, all_stats)
    print('ok')

    print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_record_alg_cmp_bar(serv, labels, hdr, all_stats, stats_type[:-1])

    print('ok')

def make_figs(servs_fname, ciphersuites, serv_set=[], weight=1.5, strlen=40, spacing=''):
    if serv_set == []:
        serv_set = settings.serv_types

    labels = settings.serv_labels
    servs = utils.parse_services_grouped(servs_fname, serv_set, ciphersuites)

    # print('')
    # for a in servs:
    #     print(f'{a}:')
    #     for b in servs[a]:
    #         print(f'  {b}: {servs[a][b]}')

    for serv in serv_set:
        print(f'\n{serv.upper()} data:')
        make_serv_cmp_figs(servs[serv], serv, labels[serv], weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hw:ciakp', ['help', 'weight=', 'conf', 'int', 'auth', 'ke', 'pfs'])

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
            print('services_comparator.py [-w <filter_weight>] [-c] [-i] [-a] [-k] [-p] <services_list> <ciphersuite_list>')
            print('services_comparator.py [--weight=<filter_weight>] [--conf] [--int] [--auth] [--ke] ' +
                    '[--pfs] <services_list> <ciphersuite_list>')
            sys.exit(0)

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        elif opt in ('-c', '--conf'):
            servs.append('conf')

        elif opt in ('-i', '--int'):
            servs.append('int')

        elif opt in ('-a', '--auth'):
            servs.append('auth')

        elif opt in ('-k', '--ke'):
            servs.append('ke')

        elif opt in ('-p', '--pfs'):
            servs.append('pfs')

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    settings.init()
    suites = utils.parse_ciphersuites(args[1])
    
    make_figs(args[0], suites, weight=weight, serv_set=servs)

if __name__ == '__main__':
   main(sys.argv[1:])