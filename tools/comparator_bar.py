import os
import sys, getopt
import matplotlib.pyplot as plt
import utils


def make_session_cmp_bar_by_ke(name, ylabel, stats, labels, stats_type):
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
            utils.save_fig(fig, '../docs/' + endpoints[i] + '_' + name + '_' + stype + '_' + ylabel + '.png')

def make_session_cmp_bar(name, ylabel, stats, labels, stats_type):
    endpoints = stats[labels[0]]['keys']

    for stype in stats_type:
        for i in range(len(endpoints)):
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []

            for suite in stats:
                y.append([stats[suite][stype + '_' + ylabel][i]])
                yerr.append([stats[suite]['stddev_' + ylabel][i]])

            ax = utils.custom_bar(y, yerr, ax=ax, xlabel='ciphersuites', xtickslabels=labels, title=endpoints[i], ylabel=ylabel)
            utils.save_fig(fig, '../docs/' + endpoints[i] + '_' + name + '_' + stype + '_' + ylabel + '.png')

def make_alg_cmp_bar(alg, ylabel, stats, labels, stats_type):
    xtickslabels = stats[labels[0]]['keys']
    operations = []
    extentions = ['_out', '_in']

    if alg == 'cipher':
        operations = ['encrypt', 'decrypt']
    elif alg == 'md':
        operations = ['hash', 'verify']

    for stype in stats_type:
        for ext, op in zip(extentions, operations):
            fig, ax = plt.subplots(1, 1, figsize=(30, 10))
            y = []
            yerr = []
        
            for suite in stats:
                y.append(stats[suite][stype + '_' + ylabel + ext])
                yerr.append(stats[suite]['stddev_' + ylabel + ext])

            ax = utils.multiple_custom_bar(y, yerr, ax=ax, title=op + ' (' + stype + ')',
                                        labels=labels, xtickslabels=xtickslabels, ylabel=ylabel)
            utils.save_fig(fig, '../docs/' + alg + '_alg_' + op + '_' + stype + '_' + ylabel + '.png')

def make_cmp_figs(ciphersuites, alg, weight=1.5, strlen=40, spacing=''):
    print(spacing + '  Parsing data'.ljust(strlen, '.'), end=' ')
    all_data = {}
    all_headers = []

    for suite in ciphersuites:
        path = '../docs/' + suite + '/' + alg + '_data.csv'
        data = {}
        hdr = []

        if alg != 'session':
            data, hdr = utils.parse_alg_data(path)
        else:
            data, hdr = utils.parse_session_data(path)

        all_data[suite] = data
        all_headers.append(hdr)

    for hdr in all_headers[1:]:
        if all_headers[0] != hdr:
            print('error')
            print(spacing + 'Data has different headers. Cannot be compared!!!\n')
            
            return None

    print('ok')

    if weight != 0:
        print(spacing + '  Removing outliers from data'.ljust(strlen, '.'), end=' ')
        
        for suite in ciphersuites:
            data = utils.filter_iqr(all_data[suite], weight=weight)
            all_data[suite] = data
        
        print('ok')

    print(spacing + f'  Calculating statistics'.ljust(strlen, '.'), end=' ')
    all_stats = {}
    stats_type = ['mean', 'stddev']

    for suite in ciphersuites:
        stats = utils.calc_statistics(all_data[suite], stats_type)

        if stats == None:
            return None

        all_stats[suite] = stats

    print('ok')
    print(spacing + f'  Saving statistics'.ljust(strlen, '.'), end=' ')

    if alg != 'session':
        path = '../docs/' + alg + '_alg_'
        utils.write_alg_cmp_csv(path, all_stats)
    else:
        path = '../docs/'
        utils.write_session_cmp_csv(path, all_stats)


    print('ok')
    print(spacing + f'  Generating figures'.ljust(strlen, '.'), end=' ')
    
    for hdr in all_headers[0]:
        if alg != 'session':
            make_alg_cmp_bar(alg, hdr, all_stats, ciphersuites, stats_type[:-1])
        else:
            make_session_cmp_bar_by_ke(alg, hdr, all_stats, ciphersuites, stats_type[:-1])

    print('ok')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hf:cms', ['help', 'filter=', 'cipher', 'md', 'session'])
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
    algs = []

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('comparator_bar.py [-f <weight>] [-c] [-m] [-s] <ciphersuite_list>')
            print('comparator_bar.py [--filter=<weight>] [--cipher] [--md] [--session] <ciphersuite_list>')
            sys.exit(0)

        if opt in ('-f', '--filter'):
            weight = float(arg)
        elif opt in ('-c', '--cipher'):
            algs.append('cipher')
        elif opt in ('-m', '--md'):
            algs.append('md')
        elif opt in ('-s', '--session'):
            algs.append('session')
        else:
            print(f'Option "{opt}" does not exist')
            sys.exit(2)

    os.system('clear')
    ciphersuites = utils.parse_ciphersuites(args[0])
    
    for alg in algs:
        print('\n' + alg.upper() + ' data:')
        make_cmp_figs(ciphersuites, alg, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])