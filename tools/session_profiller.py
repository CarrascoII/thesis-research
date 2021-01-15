import os
import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import comparator_bar, plotter, utils


strlen = 40

def run_cli(n_tests, ciphersuite):
    args = ['./../l-tls/tls_all/client.out', 'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'client', ciphersuite, stdout, stderr, strlen)

def run_srv(n_tests, ciphersuite):
    args = ['./../l-tls/tls_all/server.out', 'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'server', ciphersuite, stdout, stderr, strlen)

def exec_tls(filename, timeout, n_tests, weight):
    #Step 1: Parse ciphersuite list
    print('--- STARTING CIPHERSUITE SELECTION PROCESS ---')
    print(f'\nParsing ciphersuites from {filename}'.ljust(strlen, '.'), end=' ')    
    
    total_ciphersuites = utils.parse_algorithms(filename)
    n_total = len(total_ciphersuites)
    success_ciphersuites = []
    n_success = 0
    not_ciphersuites = []
    n_not = 0
    error_ciphersuites = []
    n_error = 0
    current = 1
    
    print(f'ok\nGot {n_total} ciphersuites')
    print('\nRunning with options:')
    print(f'\t-Timeout: {timeout} sec\n\t-Number of tests: {n_tests}')

    #Step 2: Compile libs and programs
    print('\n--- STARTING DATA ACQUISITION PROCESS ---')
    print(f'\nPrepararing libraries and programs'.ljust(strlen, '.'), end=' ')
    pool = ThreadPool(processes=1)
    async_result_make = pool.apply_async(utils.make_progs, ('all',))
    make_ret = async_result_make.get()
    
    if make_ret != 0:
        sys.exit(2)
    
    pool = ThreadPool(processes=2)

    for suite in total_ciphersuites:
        print(f'\nStarting analysis for: {suite} ({current}/{n_total})')
        current += 1

    #Step 3: Start server in thread 1
        print('\tStarting server'.ljust(strlen, '.'), end=' ')
        async_result_srv = pool.apply_async(run_srv, (n_tests, suite))
        print('ok')

        time.sleep(timeout)

    #Step 4: Start client in thread 2
        print('\tStarting client'.ljust(strlen, '.'), end=' ')
        async_result_cli = pool.apply_async(run_cli, (n_tests, suite))
        print('ok')

    #Step 5: Verify result from server and client
        srv_ret = async_result_srv.get()
        cli_ret = async_result_cli.get()

        if srv_ret == 1 and cli_ret == 1:
            not_ciphersuites.append(suite)
            n_not += 1
        elif srv_ret != 0 or cli_ret != 0:
            error_ciphersuites.append(suite)
            n_error += 1
        else:
            print('\n\tData successfully obtained!!!')
            success_ciphersuites.append(suite)
            n_success += 1

    #Step 6: Analyse data and create comparison plots for all ciphersuites that ended successfully
    print('\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
    print(f'\nCreating comparison graphs from all ciphersuites:')
    comparator_bar.make_cmp_figs(success_ciphersuites, 'session', weight=weight, strlen=strlen, spacing='\t')

    #Step 7: Report final status
    print('\n--- FINAL STATUS ---')

    print('\nData generation:')
    print(f'\t-Number of ciphersuites: {n_total}')
    print(f'\t-Number of successes: {n_success}')
    print(f'\t-Number of errors: {n_error}')
    print(f'\t-Number of n/a: {n_not}')

    if n_error > 0:
        print('\t-Error ciphersuites:')
        for suite in error_ciphersuites:
            print(f'\t\t{suite}')

    if n_not > 0:
        print('\t-N/A ciphersuites:')
        for suite in not_ciphersuites:
            print(f'\t\t{suite}')

    print('\nPlots generation:')
    print(f'\t-Number of ciphersuites: {n_success}')

    print('\nData aquisition and analysis has ended.')
    print('You can check all the csv data and png figure files in the docs directory and its subdirectories.')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'ht:n:f:', ['help', 'timeout=', 'n_tests=', 'filter='])
    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "session_profiller.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    timeout = 2
    n_tests = '500'
    weight = 1.5

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('profiller.py [-t <timeout>] [-n <n_tests>] [-f <weight>] <algorithms_list>')
            print('profiller.py [--timeout=<timeout>] [--n_tests=<n_tests>] [--filter=<weight>] <algorithms_list>')
            sys.exit(0)
        if opt in ('-t', '--timeout'):
            timeout = int(arg)
        if opt in ('-n', '--n_tests'):
            n_tests = arg
        if opt in ('-f', '--filter'):
            weight = float(arg)

    os.system('clear')
    exec_tls(args[0], timeout, n_tests, weight)

if __name__ == '__main__':
   main(sys.argv[1:])