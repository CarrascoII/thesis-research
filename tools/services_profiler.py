import sys, getopt
import subprocess
from os import system
from datetime import datetime
from multiprocessing.pool import ThreadPool
import services_comparator, services_calculator, services_analyser, utils, settings


def run_cli(target, tls_opts):
    args = ['./../l-tls/' + target + '/client.out']

    for opt in tls_opts:
        args.append(opt + '=' + tls_opts[opt])

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'client', tls_opts['ciphersuite'], stdout, stderr, settings.strlen)
    
def run_srv(target, tls_opts):
    args = ['./../l-tls/' + target + '/server.out']

    for opt in tls_opts:
        args.append(opt + '=' + tls_opts[opt])

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'server', tls_opts['ciphersuite'], stdout, stderr, settings.strlen)

def make_figs(path, suites_file, success_ciphersuites, weight, handshake=False, serv_set=[]):
    print('\nCreating comparison graphs from all ciphersuites:')
    services_comparator.make_figs(path, suites_file, success_ciphersuites, serv_set=serv_set,
                                weight=weight, strlen=settings.strlen, spacing='  ')

    tmp = [serv for serv in serv_set if serv in settings.ke_operations_per_service.keys()]
    services_analyser.make_figs(path, success_ciphersuites, serv_set=tmp,
                            handshake=handshake, weight=weight, strlen=settings.strlen, spacing='  ')

    print('\nFinding best configuration:')
    services_calculator.make_calcs(path, success_ciphersuites, serv_set=serv_set, weight=weight, strlen=settings.strlen, spacing='  ')

def exec_tls(suites_file, target, tls_opts, serv_set, handshake=False, weight=False):
    # Step 1: Parse service list
    print('--- STARTING CIPHERSUITE SELECTION PROCESS ---')
    print(f'\nParsing ciphersuites from {suites_file}'.ljust(settings.strlen, '.'), end=' ', flush=True)    
    
    total_ciphersuites = utils.parse_services(suites_file)
    n_total = len(total_ciphersuites)
    success_ciphersuites = []
    not_ciphersuites = []
    error_ciphersuites = []
    current = 1
    
    print(f'ok\nGot {n_total} ciphersuites')
    print('\nRunning with options:')
    print(f'    -Starting security level: {tls_opts["sec_lvl"]}' +
        f'\n    -Ending security level: {tls_opts["max_sec_lvl"]}' +
        f'\n    -Starting input size: {tls_opts["msg_size"]} bytes' +
        f'\n    -Ending input size: {tls_opts["max_msg_size"]} bytes' +
        f'\n    -Number of tests: {tls_opts["n_tests"]}' +
        f'\n    -Data\'s directory: {tls_opts["path"]}'
        f'\n    -Generate statistics: {"No" if weight == False else "Yes"}')
    print('\n--- STARTING DATA ACQUISITION PROCESS ---')

    # Step 2: Compile libs and programs
    print(f'\nPrepararing libraries and programs'.ljust(settings.strlen, '.'), end=' ', flush=True)
    pool = ThreadPool(processes=2)
    async_result_make = pool.apply_async(utils.make_progs, (target,))
    make_ret = async_result_make.get()
    
    if make_ret != 0:
        sys.exit(2)

    for suite in total_ciphersuites:
        print(f'\nStarting analysis for: {suite} ({current}/{n_total})')
        current += 1
        tls_opts['ciphersuite'] = suite

    # Step 3: Start server in thread 1
        print('    Starting server'.ljust(settings.strlen, '.'), end=' ', flush=True)
        async_result_srv = pool.apply_async(run_srv, (target, tls_opts))
        print('ok')

    # Step 4: Start client in thread 2
        print('    Starting client'.ljust(settings.strlen, '.'), end=' ', flush=True)
        async_result_cli = pool.apply_async(run_cli, (target, tls_opts))
        print('ok')

    # Step 5: Verify result from server and client
        srv_ret = async_result_srv.get()
        cli_ret = async_result_cli.get()

        if srv_ret == 1 and cli_ret == 1:
            not_ciphersuites.append(suite)

        elif srv_ret != 0 or cli_ret != 0:
            error_ciphersuites.append(suite)

        else:
            print('\n    Data successfully obtained!!!')
            success_ciphersuites.append(suite)

    pool.close()
    pool.join()
    n_success = len(success_ciphersuites)
    n_not = len(not_ciphersuites)
    n_error = len(error_ciphersuites)

    if weight != False:
        # Step 6: Analyse data and create comparison plots for all ciphersuites that ended successfully
        print('\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
        make_figs(tls_opts['path'], suites_file, success_ciphersuites, weight, handshake=handshake, serv_set=serv_set)

        # Step 7: For each target, save successful ciphersuites in a file
        # utils.write_ciphersuites('services', success_ciphersuites)

    # Step 8: Report final status
    print('\n--- FINAL STATUS ---')
    print('\nData generation:')
    print(f'    -Number of ciphersuites: {n_total}')
    print(f'    -Number of successes: {n_success}')
    print(f'    -Number of n/a: {n_not}')
    print(f'    -Number of errors: {n_error}')

    if n_not > 0:
        print('    -N/A ciphersuites:')

        for suite in not_ciphersuites:
            print(f'        {suite}')

    if n_error > 0:
        print('    -Error ciphersuites:')

        for suite in error_ciphersuites:
            print(f'        {suite}')

    if weight != False:
        print('\nPlots generation:')
        print(f'    -Number of ciphersuites: {n_success}')

    print('\nData aquisition and analysis has ended.')
    print(f'You can check all the csv data in the docs/{tls_opts["path"]} directory', end='')
    
    if weight != False:
        print(f' and the generated plots and statistics in the tools/statistics/{tls_opts["path"]} ' +
            f'and tools/results/{tls_opts["path"]} directories, respectively', end='')

    print('.')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'ht:w:m:s:n:d:Hciakp', ['help', 'target=', 'weight=', 'message_size=',
                                'sec_lvl=', 'n_tests=', 'data_path=', 'handshake', 'conf', 'int', 'auth', 'ke', 'pfs'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "services_profiler.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    target = 'tls_algs'
    weight = False
    tls_opts = {
        'sec_lvl': '0', 'max_sec_lvl': '4',
        'msg_size': '32', 'max_msg_size': '16384',
        'n_tests': '20', 'path': datetime.now().strftime('%d%m%Y.%H%M')
    }
    handshake = False
    serv_set = []
    
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('services_profiler.py [-t <compilation_target>] [-w <filter_weight>] ' +
                '[-s <initial_lvl>,<final_lvl>] [-m <initial_size>,<final_size>] [-n <n_tests>] ' +
                '[-d <data_directory>] [-H] [-c] [-i] [-a] [-k] [-p] <services_list>')
            print('services_profiler.py [--target=<compilation_target>] [--weight=<filter_weight>]  ' +
                '[--sec_lvl=<initial_lvl>,<final_lvl] [--message_size=<initial_size>,<final_size>] [--n_tests=<n_tests>] ' +
                '[--data_path=<data_directory>] [--handshake] [--conf] [--int] [--auth] [--ke] [--pfs] <services_list>')
            sys.exit(0)

        elif opt in ('-t', '--target'):
            target = arg

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        elif opt in ('-s', '--sec_lvl'):
            lst = arg.split(',')

            if lst[0] != '':
                tls_opts['sec_lvl'] = lst[0]

            if lst[1] != '':
                tls_opts['max_sec_lvl'] = lst[1]

        elif opt in ('-m', '--message_size'):
            lst = arg.split(',')

            if lst[0] != '':
                tls_opts['msg_size'] = lst[0]

            if lst[1] != '':
                tls_opts['max_msg_size'] = lst[1]

        elif opt in ('-n', '--n_tests'):
            tls_opts['n_tests'] = arg

        elif opt in ('-d', '--data_path'):
            tls_opts['path'] = arg

        elif opt in ('-H', '--handshake'):
            handshake = True

        elif opt in ('-c', '--conf'):
            serv_set.append('conf')

        elif opt in ('-i', '--int'):
            serv_set.append('int')

        elif opt in ('-a', '--auth'):
            serv_set.append('auth')

        elif opt in ('-k', '--ke'):
            serv_set.append('ke')

        elif opt in ('-p', '--pfs'):
            serv_set.append('pfs')

    system('clear')
    settings.init()
    exec_tls(args[0], target, tls_opts, serv_set, handshake=handshake, weight=weight)

if __name__ == '__main__':
   main(sys.argv[1:])