import os
import sys, getopt
import matplotlib
import matplotlib.pyplot as plt
import utils


def make_session_cmp_bar_by_ke(ylabel, stats, labels, stats_type):
    endpoints = stats[labels[0]]['keys']
    ke = utils.get_ke_algs(labels)

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

            ax = utils.grouped_custom_bar(y, yerr, ax, labels=lab, label_lim=m,
                                        xlabel='ciphersuites', xtickslabels=ke, ylabel=ylabel)
            utils.save_fig(fig, 'statistics/session_' + endpoints[i] + '_' + stype + '_' + ylabel + '.png')

def make_figs(ciphersuites, weight=2, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_stats = {}
    stats_type = ['mean', 'stddev']

    print(f'{spacing}Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for suite in ciphersuites:
        path = '../docs/' + suite + '/'
        data, hdr = utils.parse_session_data(path)
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
            data = utils.filter_z_score(all_data[suite], weight=weight)
            all_data[suite] = data
        
        print('ok')

    print(f'{spacing}Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for suite in ciphersuites:
        stats = utils.calc_statistics(all_data[suite], stats_type)

        if stats == None:
            return None

        all_stats[suite] = stats

    print('ok')

    print(f'{spacing}Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    utils.write_session_cmp_csv('statistics/session_', all_stats)
    print('ok')
    
    print(f'{spacing}Generating figures'.ljust(strlen, '.'), end=' ', flush=True)
    matplotlib.use('Agg')

    for hdr in headers:
        make_session_cmp_bar_by_ke(hdr, all_stats, ciphersuites, stats_type[:-1])

    print('ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:', ['help', 'weight='])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "comparator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No ciphersuites where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    weight = 2

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('session_comparator.py [-w <filter_weight>] <ciphersuite_list>')
            print('session_comparator.py [--weight=<filter_weight>] <ciphersuite_list>')
            sys.exit(0)

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    ciphersuites = utils.parse_ciphersuites(args[0])
    make_figs(ciphersuites, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])