import os
import sys, getopt
import matplotlib.pyplot as plt
import utils, settings


def make_record_alg_cmp_bar(operations, ylabel, stats, stats_type):
    labels = list(stats.keys())
    xtickslabels = []
    sec_lvl = []
    scale_type = ['linear', 'log']

    for key in stats[labels[0]]['keys']:
        val = key.split('_')

        if val[1] not in sec_lvl:
            sec_lvl.append(val[1])

    for alg in stats:
        xtickslabels.append(alg)

    for stype in stats_type:
        for op in operations:
            for lvl in sec_lvl:
                for scale in scale_type:
                    fig, ax = plt.subplots(1, 1, figsize=(30, 10))
                    y = {}

                    for alg in stats:
                        for key in stats[alg]['keys']:
                            elem = key.split('_')

                            if elem[0] not in y:
                                y[elem[0]] = []

                    for serv in y:
                        for alg in stats:
                            try:
                                idx = stats[alg]['keys'].index(serv + '_' + lvl)
                                y[serv].append(stats[alg][stype + '_' + ylabel + '_' + op][idx])
                            
                            except ValueError:
                                y[serv].append(0)

                    # print('')
                    # for a in y:
                    #     print(f'{a}: {y[a]} : {len(y[a])}')

                    ax = utils.stacked_custom_bar(y, ax=ax, title=op + ' (' + stype + ')', scale=scale,
                                                xlabel='algorithms', xtickslabels=xtickslabels, ylabel=ylabel)
                    utils.save_fig(fig, '../docs/serv_all_' + op + '_' + settings.sec_str[int(lvl)] + '_' + ylabel + '_' + scale + '.png')

def make_serv_cmp_figs(grouped_suites, labels, weight=1.5, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_stats = {}
    stats_type = ['mean']

    print(f'{spacing}  Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for algs in grouped_suites:
        all_data[algs] = {}

        for suite in grouped_suites[algs]:
            filename = '../docs/' + suite + '/'
            data, hdr = utils.parse_servs_data(filename, algs)

            # print(f'\n{suite} ({algs}):')
            # for a in data:
            #     print(f'  {a}')
            #     for b in data[a]:
            #         print(f'    {b}: {data[a][b]} : {len(data[a][b])}')
            #     print('')

            if all_data[algs] == {}:
                all_data[algs] = data
                headers = hdr
            
            elif headers == hdr:
                for sub in list(all_data[algs].keys()):
                    for entry in data[sub]:
                        if entry not in all_data[algs][sub]:
                            all_data[algs][sub][entry] = []

                        all_data[algs][sub][entry] += data[sub][entry]

            else:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
                return None

        if all_data[algs] == {}:
            all_data.pop(algs)

    # print('')
    # for a in all_data:
    #     print(f'{a}:')
    #     for b in all_data[a]:
    #         print(f'  {b}:')            
    #         for c in all_data[a][b]:
    #             print(f'    {c}: {all_data[a][b][c]} : {len(all_data[a][b][c])}')
    #     print('')

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

        if stats == None:
            return None

        all_stats[key] = stats

    print('ok')

    # print('')
    # for a in all_stats:
    #     print(f'{a}:')
    #     for b in all_stats[a]:
    #         print(f'  {b}: {all_stats[a][b]} : {len(all_stats[a][b])}')
    #     print('')

    print(f'{spacing}  Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    for hdr in headers:
        utils.write_suite_servs_cmp_csv('../docs/serv_all_', 'algorithms', all_stats, hdr)
    print('ok')

    print(f'{spacing}  Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_record_alg_cmp_bar(labels, hdr, all_stats, stats_type)

    print('ok')

def make_figs(suites, weight=1.5, strlen=40, spacing=''):   
    grouped_suites = utils.group_ciphersuites(suites)
    labels = settings.serv_labels['ke']

    print(f'\n{spacing}ALL data:')
    make_serv_cmp_figs(grouped_suites, labels, weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hw:', ['help', 'weight='])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No inputs where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('ciphersuite_analyser.py [-w <filter_weight>] <ciphersuite_list>')
            print('ciphersuite_analyser.py [--weight=<filter_weight>] <ciphersuite_list>')
            sys.exit(0)

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    settings.init()
    suites = utils.parse_ciphersuites(args[0])
    
    make_figs(suites, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])