import os
import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import comparator_bar, plotter, utils


strlen = 40

def run_cli(min_size, n_tests, ciphersuite):
    args = ['./../l-tls/tls_psk/client.out', 'input_size=' + min_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'client', ciphersuite, stdout, stderr, strlen)
    
def run_srv(min_size, n_tests, ciphersuite):
    args = ['./../l-tls/tls_psk/server.out', 'input_size=' + min_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'server', ciphersuite, stdout, stderr, strlen)

def exec_tls(filename, target, timeout, min_size, n_tests, weight):
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
    print(f'\t-Timeout: {timeout} sec\n\t-Number of tests: {n_tests}\n\t-Starting input size: {min_size} bytes')

    #Step 2: Compile libs and programs
    print('\n--- STARTING DATA ACQUISITION PROCESS ---')
    print(f'\nPrepararing libraries and programs'.ljust(strlen, '.'), end=' ')
    thread = ThreadPool(processes=1)
    async_result_make = thread.apply_async(utils.make_progs, (target,))
    make_ret = async_result_make.get()
    
    if make_ret != 0:
        sys.exit(2)

    pool = ThreadPool(processes=2)

    for suite in total_ciphersuites:
        print(f'\nStarting analysis for: {suite} ({current}/{n_total})')
        current += 1

    #Step 3: Start server in thread 1
        print('\tStarting server'.ljust(strlen, '.'), end=' ')
        async_result_srv = pool.apply_async(run_srv, (min_size, n_tests, suite))
        print('ok')

        time.sleep(timeout)

    #Step 4: Start client in thread 2
        print('\tStarting client'.ljust(strlen, '.'), end=' ')
        async_result_cli = pool.apply_async(run_cli, (min_size, n_tests, suite))
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

    #Step 6: Analyse data and create individual plots for ciphersuites that ended successfully
    print('\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
    current = 1

    for suite in success_ciphersuites:
        print(f'\nCreating graphs for: {suite} ({current}/{n_success})')
        current +=1

        print('\n    Cipher algorithm:')
        plotter.make_figs('../docs/' + suite + '/cipher_data.csv', weight=weight, strlen=strlen, spacing='\t')

        print('\n    MAC algorithm:')
        plotter.make_figs('../docs/' + suite + '/md_data.csv', weight=weight, strlen=strlen, spacing='\t')

    #Step 7: Analyse data and create comparison plots for all ciphersuites that ended successfully
    print(f'\nCreating comparison graphs from all ciphersuites:')

    print('\n    Cipher algorithm:')
    comparator_bar.make_cmp_figs(success_ciphersuites, 'cipher', weight=weight, strlen=strlen, spacing='\t')
    print('\n    MAC algorithm:')
    comparator_bar.make_cmp_figs(success_ciphersuites, 'md', weight=weight, strlen=strlen, spacing='\t')
    
    utils.write_ciphersuites('ciphersuites.txt', success_ciphersuites)

    #Step 8: Report final status
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
    print('You can check all the csv data and png figure files in the docs/<ciphersuite_name> directories.')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hc:t:m:n:f:', ['help', 'compile=', 'timeout=', 'min_size=', 'n_tests=', 'filter='])
    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "profiller.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    target = 'psk'
    timeout = 2
    min_size = '32'
    n_tests = '500'
    weight = 1.5

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('profiller.py [-c <compilation_target>] [-t <timeout>] [-m <min_input_size>] [-n <n_tests>] [-f <weight>] <algorithms_list>')
            print('profiller.py [--compile=<compilation_target>] [--timeout=<timeout>] [--min_size=<min_input_size>] ' +
                  '[--n_tests=<n_tests>] [--filter=<weight>] <algorithms_list>')
            sys.exit(0)
        if opt in ('-c', '--compile'):
            target = arg
        if opt in ('-t', '--timeout'):
            timeout = int(arg)
        if opt in ('-m', '--min_size'):
            min_size = arg
        if opt in ('-n', '--n_tests'):
            n_tests = arg
        if opt in ('-f', '--filter'):
            weight = float(arg)

    os.system('clear')
    exec_tls(args[0], target, timeout, min_size, n_tests, weight)

if __name__ == '__main__':
   main(sys.argv[1:])