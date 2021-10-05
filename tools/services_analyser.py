import os, sys, getopt
from matplotlib import use
import matplotlib.pyplot as plt
import utils, settings


def make_record_alg_cmp_bar(path, operations, ylabel, stats, extra_labels, handshake=False):
    xtickslabels = []
    sec_lvl = []
    scale_type = ['linear', 'log']

    for key in stats[list(stats.keys())[0]]['keys']:
        val = key.split('_')

        if val[1] not in sec_lvl:
            sec_lvl.append(val[1])

    for key in stats:
        tmp = ''

        for id in extra_labels[key]:
            tmp += id

        if tmp == '':
            xtickslabels.append(key)
        else:
            xtickslabels.append(key + '\n(' + tmp + ')')

    for op in operations:
        for lvl in sec_lvl:
            y = {}

            for key in stats:
                for key in stats[key]['keys']:
                    elem = key.split('_')

                    if elem[0] not in y:
                        y[elem[0]] = []
            
            for alg in y:
                for key in stats:
                    try:
                        idx = stats[key]['keys'].index(alg + '_' + lvl)
                        y[alg].append(stats[key]['mean_' + ylabel + '_' + op][idx])
                    
                    except (ValueError, KeyError):
                        y[alg].append(0)

            # print('')
            # for a in y:
            #     print(f'{a}: {y[a]} : {len(y[a])}')

            for scale in scale_type:
                fig, ax = plt.subplots(1, 1, figsize=(30, 10))

                ax = utils.stacked_custom_bar(y, ax, handshake=handshake, title=op + ' (mean)', scale=scale,
                                            xlabel='algorithms', xtickslabels=xtickslabels, ylabel=ylabel)
                utils.save_fig(fig, 'statistics/' + path + '/serv_all_' + op +
                                            '_' + settings.sec_str[int(lvl)] + '_' + ylabel + '_' + scale + '.png')

def make_serv_cmp_figs(path, grouped_suites, labels, servs, handshake=False, weight=2, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_labels = {}
    all_stats = {}
    stats_type = ['mean']

    print(f'{spacing}Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for algs in grouped_suites:
        all_data[algs] = {}

        for suite in grouped_suites[algs]:
            filename = '../docs/' + path + '/' + suite + '/'
            data, hdr = utils.parse_servs_data(filename, algs, servs)

            if handshake:
                hs_data, hs_headers = utils.parse_handshake_data(filename, 'handshake')

                if hdr == hs_headers:
                    for sec_lvl in hs_data.keys():
                        data['ALL_' + sec_lvl] = hs_data[sec_lvl]

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

            all_labels[algs] = utils.get_extra_labels(filename, algs, servs)

        if all_data[algs] == {}:
            all_data.pop(algs)

    all_data = utils.sort_keys(all_data, settings.hs_alg_prio)

    # print('')
    # for a in all_data:
    #     print(f'{a}:')
    #     for b in all_data[a]:
    #         print(f'  {b}:')
    #         for c in all_data[a][b]:
    #             print(f'    {c}: {all_data[a][b][c]} : {len(all_data[a][b][c])}')
    #     print('')

    # print('')
    # for a in all_labels:
    #     print(f'{a}: {all_labels[a]}')

    print('ok')

    if weight != 0:
        print(f'{spacing}Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for key in all_data:
            data = utils.filter_z_score(all_data[key], weight=weight)
            all_data[key] = data

        print('ok')

    print(f'{spacing}Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for key in all_data:
        stats = utils.calc_statistics(all_data[key], stats_type)

        if stats == None:
            return None

        # print('')
        # print(f'{key}:')
        # for a in stats:
        #     print(f'  {a}: {stats[a]} : {len(stats[a])}')

        all_stats[key] = stats

    print('ok')

    # print('')
    # for a in all_stats:
    #     print(f'{a}:')
    #     for b in all_stats[a]:
    #         print(f'  {b}: {all_stats[a][b]} : {len(all_stats[a][b])}')
    #     print('')

    print(f'{spacing}Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for hdr in headers:
        utils.write_suite_servs_cmp_csv('statistics/' + path + '/', 'algorithms', all_stats, hdr)
    
    print('ok')

    print(f'{spacing}Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    
    for hdr in headers:
        make_record_alg_cmp_bar(path, labels, hdr, all_stats, all_labels, handshake=handshake)

    print('ok')

def make_figs(path, suites, serv_set=[], handshake=False, weight=2, strlen=40, spacing=''):
    if serv_set == []:
        print('\nError!! No services were selected to analyse!!!')
        return None

    use('Agg')
    plt.rcParams.update({'font.size': settings.fontsize})

    grouped_suites = utils.group_ciphersuites(suites, serv_set)
    labels = settings.serv_labels['ke']

    print(f'\nSERVICES data:')
    make_serv_cmp_figs(path, grouped_suites, labels, serv_set, handshake=handshake, weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hw:Hakp', ['help', 'weight=', 'handshake', 'auth', 'ke', 'pfs'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "services_analysers.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No inputs where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    servs = []
    handshake = False
    weight = 2

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('services_analyser.py [-w <filter_weight>] [-H] [-a] [-k] [-p] <path_to_data>')
            print('services_analyser.py [--weight=<filter_weight>] [--handshake] [--auth] [--ke] [--pfs] <path_to_data>')
            sys.exit(0)

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        elif opt in ('-H', '--handshake'):
            handshake = True

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
    suites = [f.name for f in os.scandir('../docs/' + args[0]) if f.is_dir()]

    make_figs(args[0], suites, serv_set=servs, handshake=handshake, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])