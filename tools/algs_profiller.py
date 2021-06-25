import os
import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import algs_comparator, algs_plotter, utils, settings


def run_cli(target, tls_opts):
    args = ['./../l-tls/tls_' + target + '/client.out']

    for opt in tls_opts:
        args.append(opt + '=' + tls_opts[opt])

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'client', tls_opts['ciphersuite'], stdout, stderr, settings.strlen)
    
def run_srv(target, tls_opts):
    args = ['./../l-tls/tls_' + target + '/server.out']

    for opt in tls_opts:
        args.append(opt + '=' + tls_opts[opt])

    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'server', tls_opts['ciphersuite'], stdout, stderr, settings.strlen)

def make_figs(suites_file, success_ciphersuites, weight, alg_set=[]):
    # Step 7.1: Create individual data plots
    print(f'\nCreating data graphs for all ciphersuites:')
    algs_plotter.make_figs(success_ciphersuites, alg_set=alg_set, weight=weight, strlen=settings.strlen, spacing='  ')

    # Step 7.2: Create comparison plots
    print(f'\nCreating comparison graphs from all ciphersuites:')
    algs_comparator.make_figs(suites_file, success_ciphersuites, alg_set=alg_set, weight=weight, strlen=settings.strlen, spacing='  ')

def exec_tls(suites_file, target, timeout, tls_opts, weight, gen_stats=True):
    # Step 1: Parse ciphersuite list
    print('--- STARTING CIPHERSUITE SELECTION PROCESS ---')
    print(f'\nParsing ciphersuites from {suites_file}'.ljust(settings.strlen, '.'), end=' ', flush=True)    
    
    total_ciphersuites = utils.parse_algorithms(suites_file)
    n_total = len(total_ciphersuites)
    success_ciphersuites = []
    not_ciphersuites = []
    error_ciphersuites = []
    current = 1
    
    print(f'ok\nGot {n_total} ciphersuites')
    print('\nRunning with options:')
    print(f'    -Timeout: {timeout} sec' +
        f'\n    -Starting input size: {tls_opts["input_size"]} bytes' +
        f'\n    -Ending input size: {tls_opts["max_input_size"]} bytes' +
        f'\n    -Starting security level: {tls_opts["sec_lvl"]}' +
        f'\n    -Ending security level: {tls_opts["max_sec_lvl"]}' +
        f'\n    -Number of tests: {tls_opts["n_tests"]}' +
        f'\n    -Generate statistics: {"Yes" if gen_stats else "No"}')
    print('\n--- STARTING DATA ACQUISITION PROCESS ---')

    # Step 3: Compile libs and programs
    print(f'\nPrepararing libraries and programs'.ljust(settings.strlen, '.'), end=' ', flush=True)
    thread = ThreadPool(processes=1)
    async_result_make = thread.apply_async(utils.make_progs, (target,))
    make_ret = async_result_make.get()
    
    if make_ret != 0:
        sys.exit(2)

    pool = ThreadPool(processes=2)

    for suite in total_ciphersuites:
        print(f'\nStarting analysis for: {suite} ({current}/{n_total})')
        current += 1
        tls_opts['ciphersuite'] = suite

    # Step 4: Start server in thread 1
        print('    Starting server'.ljust(settings.strlen, '.'), end=' ', flush=True)
        async_result_srv = pool.apply_async(run_srv, (target, tls_opts))
        print('ok')
        time.sleep(timeout)

    # Step 5: Start client in thread 2
        print('    Starting client'.ljust(settings.strlen, '.'), end=' ', flush=True)
        async_result_cli = pool.apply_async(run_cli, (target, tls_opts))
        print('ok')

    # Step 6: Verify result from server and client
        srv_ret = async_result_srv.get()
        cli_ret = async_result_cli.get()

        if srv_ret == 1 and cli_ret == 1:
            not_ciphersuites.append(suite)

        elif srv_ret != 0 or cli_ret != 0:
            error_ciphersuites.append(suite)

        else:
            print('\n    Data successfully obtained!!!')
            success_ciphersuites.append(suite)

    n_success = len(success_ciphersuites)
    n_not = len(not_ciphersuites)
    n_error = len(error_ciphersuites)

    # Step 7: Analyse data and create plots for ciphersuites that ended successfully
    if gen_stats:
        print('\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
        make_figs(suites_file, success_ciphersuites, weight, alg_set=settings.alg_types)

        # Step 8: For each target, save successful ciphersuites in a file
        # utils.write_ciphersuites(target, success_ciphersuites)

    # Step 9: Report final status
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

    if gen_stats:
        print('\nPlots generation:')
        print(f'    -Number of ciphersuites: {n_success}')

    print(f'\nData aquisition{" and analysis" if gen_stats else ""} has ended.')
    print(f'You can check all the csv data{" and png figure files" if gen_stats else ""} in the docs/<ciphersuite_name>' +
        f'{" and tools/statistics" if gen_stats else ""} directories{", respectively" if gen_stats else ""}.')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hc:t:w:i:s:n:p', ['help', 'compile=', 'timeout=', 'weight=', 'input_size=',
                                                        'sec_lvl=', 'n_tests=', 'plot'])

    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "algs_profiller.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    target = 'algs'
    timeout = 2
    tls_opts = {'input_size': '256', 'max_input_size': '16384', 'sec_lvl': '0', 'max_sec_lvl': '4', 'n_tests': '500'}
    weight = 1.5
    gen_stats = False

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('algs_profiller.py [-c <compilation_target>] [-t <timeout>] [-w <filter_weight>] ' +
                '[-i <initial_size>,<final_size>] [-s <initial_lvl>,<final_lvl>] [-n <n_tests>]  [-p] <algorithms_list>')
            print('algs_profiller.py [--compile=<compilation_target>] [--timeout=<timeout>] [--weight=<filter_weight>]  ' +
                '[--input_size=<initial_size>,<final_size>] [--sec_lvl=<initial_lvl>,<final_lvl] [--n_tests=<n_tests>] ' +
                '[--plot] <algorithms_list>')
            sys.exit(0)

        elif opt in ('-c', '--compile'):
            target = arg

        elif opt in ('-t', '--timeout'):
            timeout = int(arg)

        elif opt in ('-i', '--input_size'):
            lst = arg.split(',')

            if lst[0] != '':
                tls_opts['input_size'] = lst[0]

            if lst[1] != '':
                tls_opts['max_input_size'] = lst[1]

        elif opt in ('-s', '--sec_lvl'):
            lst = arg.split(',')

            if lst[0] != '':
                tls_opts['sec_lvl'] = lst[0]

            if lst[1] != '':
                tls_opts['max_sec_lvl'] = lst[1]

        elif opt in ('-n', '--n_tests'):
            tls_opts['n_tests'] = arg

        elif opt in ('-w', '--weight'):
            weight = float(arg)

        elif opt in ('-p', '--plot'):
            gen_stats = True

    os.system('clear')
    settings.init()
    exec_tls(args[0], target, timeout, tls_opts, weight, gen_stats=gen_stats)

if __name__ == '__main__':
   main(sys.argv[1:])