import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_session_cmp_bar_by_ke(ylabel, stats, labels, stats_type):
    endpoints = stats[labels[0]]['keys']
    ke = utils.parse_ke(labels)

    for stype in stats_type:
        for i in range(len(endpoints)):
            fig, ax = plt.subplots(1, 1, figsize=(20, 15))
            y = []
            y_tmp = {}
            yerr = []
            yerr_tmp = {}
            lab = []
            labels_tmp = {}
            m = 0

            for key in ke:
                for suite in stats:
                    if suite.find('TLS-' + key + '-WITH') != -1:
                        if key not in y_tmp.keys():
                            y_tmp[key] = []
                            yerr_tmp[key] = []
                            labels_tmp[key] = []

                        y_tmp[key].append(stats[suite][stype + '_' + ylabel][i])
                        yerr_tmp[key].append(stats[suite]['stddev_' + ylabel][i])
                        labels_tmp[key].append(suite)

            for key in ke:
                n = max(y_tmp[key])
                y.append(y_tmp[key])
                yerr.append(yerr_tmp[key])
                lab.append(labels_tmp[key])

                if n > m:
                    m = n

            ax = utils.grouped_custom_bar(y, yerr, ax=ax, labels=lab, label_lim=m,
                                        xlabel='ciphersuites', xtickslabels=ke, ylabel=ylabel)
            utils.save_fig(fig, '../docs/session_' + endpoints[i] + '_' + stype + '_' + ylabel + '.png')

# def make_session_cmp_bar(ylabel, stats, labels, stats_type):
#     endpoints = stats[labels[0]]['keys']

#     for stype in stats_type:
#         for i in range(len(endpoints)):
#             fig, ax = plt.subplots(1, 1, figsize=(30, 10))
#             y = []
#             yerr = []

#             for suite in stats:
#                 y.append([stats[suite][stype + '_' + ylabel][i]])
#                 yerr.append([stats[suite]['stddev_' + ylabel][i]])

#             ax = utils.custom_bar(y, yerr, ax=ax, xlabel='ciphersuites', xtickslabels=labels, title=endpoints[i], ylabel=ylabel)
#             utils.save_fig(fig, '../docs/' + endpoints[i] + '_session_' + stype + '_' + ylabel + '.png')

def make_figs(ciphersuites, weight=1.5, strlen=40, spacing=''):
    print(f'{spacing}Parsing data'.ljust(strlen, '.'), end=' ', flush=True)
    all_data = {}
    headers = []

    for suite in ciphersuites:
        path = '../docs/' + suite + '/session_data.csv'
        data, hdr = utils.parse_handshake_data(path, index=2)
        all_data[suite] = data

        if headers == []:
            headers = hdr
        
        elif headers != hdr:
            print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n')
            return None

    print('ok')

    if weight != 0:
        print(f'{spacing}Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for suite in ciphersuites:
            data = utils.filter_iqr(all_data[suite], weight=weight)
            all_data[suite] = data
        
        print('ok')

    print(f'{spacing}Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)
    
    all_stats = {}
    stats_type = ['mean', 'stddev']

    for suite in ciphersuites:
        stats = utils.calc_statistics(all_data[suite], stats_type)

        if stats == None:
            return None

        all_stats[suite] = stats

    print('ok')
    print(f'{spacing}Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)

    path = '../docs/session_'
    utils.write_handshake_cmp_csv(path, all_stats)

    print('ok')
    print(f'{spacing}Generating figures'.ljust(strlen, '.'), end=' ', flush=True)

    for hdr in headers:
        make_session_cmp_bar_by_ke(hdr, all_stats, ciphersuites, stats_type[:-1])
        # make_session_cmp_bar(ylabel, stats, labels, stats_type[:-1])

    print('ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:', ['help', 'filter='])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No ciphersuites where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    weight = 1.5

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('session_comparator.py [-f <weight>] <ciphersuite_list>')
            print('session_comparator.py [--filter=<weight>] <ciphersuite_list>')
            sys.exit(0)

        elif opt in ('-f', '--filter'):
            weight = float(arg)

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    ciphersuites = utils.parse_ciphersuites(args[0])
    make_figs(ciphersuites, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])