import os
import sys, getopt
import utils, settings


def sum_rec_vals(all_stats, servs):
    values = {'keys': all_stats[servs[0]]['keys']}
    op = {
        'conf': {
            'encrypt': 'out',
            'decrypt': 'in'
        },
        'int': {
            'hash': 'out',
            'verify': 'in'
        }
    }
    
    for serv in servs:
        for key in all_stats[serv]:            
            if key == 'keys':
                continue
            
            new = key

            for sub in op[serv]:
                if new.find(sub) != -1:
                    new = new.replace(sub, op[serv][sub])
                    break
            
            size = len(values['keys'])

            if new not in values.keys():
                values[new] = [0 for i in range(size)]

            for idx in range(size):
                values[new][idx] += all_stats[serv][key][idx]

    return values

def sum_hs_vals(stats):
    values = {}
    keys = []
    lvls = []

    for key in stats:
        if key == 'keys':
            for id in stats[key]:
                id = id.split('_')

                if id[1] not in lvls:
                    lvls.append(id[1])
        
        else:
            if key not in keys:
                keys.append(key)

    values['keys'] = [settings.sec_str[int(lvl)] for lvl in lvls]

    for key in keys:
        values[key] = []

        for lvl in lvls:
            total = 0

            for id, val in zip(stats['keys'], stats[key]):
                # print(f'  {id}: {val}')
                if id.find(lvl) != -1:
                    total += val
            
            values[key].append(total)

    return values

# def sort_vals(all_stats):
#     values = {}
#     servs = list(all_stats[next(iter(all_stats))].keys())

#     for serv in servs:
#         values[serv] = {}

#     return values

def make_serv_calcs(path, ciphersuites, serv_set, weight=2, strlen=40, spacing=''):
    all_data = {}
    headers = []
    all_stats = {}
    stats_type = ['mean']

    for suite in ciphersuites:
        all_data[suite] = {}

    print(f'{spacing}Parsing data'.ljust(strlen, '.'), end=' ', flush=True)

    for suite in ciphersuites:
        filename = '../docs/' + path + '/' + suite + '/'

        if 'conf' in serv_set:
            all_data[suite]['conf'], hdr = utils.parse_record_data(filename, 'cipher', 'conf')
        
            if headers == []:
                headers = hdr

            elif headers != hdr:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n{spacing}Details: {headers} != {hdr}\n')
                return None

        if 'int' in serv_set:
            all_data[suite]['int'], hdr = utils.parse_record_data(filename, 'md', 'int')
        
            if headers == []:
                headers = hdr

            elif headers != hdr:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n{spacing}Details: {headers} != {hdr}\n')
                return None

        if any(serv in serv_set for serv in ['auth', 'ke', 'pfs']):
            algs = suite[4:suite.find('-WITH-')]
            all_data[suite]['hs'], hdr = utils.parse_servs_data(filename, algs, ['auth', 'ke', 'pfs'])
            
            if headers == []:
                headers = hdr

            elif headers != hdr:
                print(f'error\n{spacing}Data has different headers. Cannot be compared!!!\n{spacing}Details: {headers} != {hdr}\n')
                return None

    print('ok')

    # for suite in all_data:
    #     print(f'\n{suite}:')
    #     for a in all_data[suite]:
    #         print(f'  {a}:')
    #         for b in all_data[suite][a]:
    #             print(f'    {b}:')
    #             for c in all_data[suite][a][b]:
    #                 print(f'      {c}: {len(all_data[suite][a][b][c])}')
    #             print('')

    if weight != 0:
        print(f'{spacing}Removing outliers from data'.ljust(strlen, '.'), end=' ', flush=True)
        
        for suite in all_data:
            for serv in all_data[suite]:
                all_data[suite][serv] = utils.filter_z_score(all_data[suite][serv], weight=weight)
        
        print('ok')

    print(f'{spacing}Calculating statistics'.ljust(strlen, '.'), end=' ', flush=True)

    for suite in all_data:
        all_stats[suite] = {}

        for serv in all_data[suite]:
            stats = utils.calc_statistics(all_data[suite][serv], stats_type)

            if stats == None:
                return None

            all_stats[suite][serv] = stats

    for suite in all_stats:
        rec_servs = [serv for serv in list(all_stats[suite].keys()) if serv in ['conf', 'int']]

        if rec_servs != []:
            all_stats[suite]['rec'] = sum_rec_vals(all_stats[suite], rec_servs)

            for serv in rec_servs:
                all_stats[suite].pop(serv)

        if 'hs' in list(all_stats[suite].keys()):
            all_stats[suite]['hs'] = sum_hs_vals(all_stats[suite]['hs'])

    print('ok')

    # for suite in all_stats:
    #     print(f'\n{suite}:')
    #     for a in all_stats[suite]:
    #         print(f'  {a}:')
    #         for b in all_stats[suite][a]:
    #             print(f'    {b}: {all_stats[suite][a][b]} : {len(all_stats[suite][a][b])}')
    #         print('')

    # print(f'{spacing}Calculating best configuration'.ljust(strlen, '.'), end=' ', flush=True)
    # all_stats = sort_vals(all_stats)
    # print('ok')

    print(f'{spacing}Saving statistics'.ljust(strlen, '.'), end=' ', flush=True)
    utils.write_config_values_csv('results/' + path + '/', 'ciphersuite', all_stats)
    print('ok')

def make_calcs(path, ciphersuites, serv_set=[], weight=2, strlen=40, spacing=''):
    if serv_set == []:
        print('\nError!! No services were selected to analyse!!!')
        return None

    make_serv_calcs(path, ciphersuites, serv_set, weight=weight, strlen=strlen, spacing=spacing)

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hw:ciakp', ['help', 'weight=', 'conf', 'int', 'auth', 'ke', 'pfs'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "services_calculator.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No inputs where given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    servs = []
    weight = 2

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('services_calculator.py [-w <filter_weight>] [-c] [-i] [-a] [-k] [-p] <path_to_data>')
            print('services_calculator.py [--weight=<filter_weight>] [--conf] [--int] ' +
                '[--auth] [--ke] [--pfs] <path_to_data>')
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
    suites = [f.name for f in os.scandir('../docs/' + args[0]) if f.is_dir()]
    
    make_calcs(args[0], suites, serv_set=servs, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])