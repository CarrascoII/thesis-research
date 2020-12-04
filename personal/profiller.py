import os
import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import utils, plotter

strlen = 40


def check_return_code(return_code, endpoint, ciphersuite, stdout, stderr):
    last_msg = ['Final status:', f'  -Suite being used:          {ciphersuite}']
    strout = stdout.decode('utf-8').strip('\n')
    last_out = strout.split('\n')[-2:]
    strerr = stderr.decode('utf-8').strip('\n')
    last_err = strerr.split('\n')

    print(f'\tChecking {endpoint} return code'.ljust(strlen, '.'), end=' ')

    if return_code != 0:
        print('error\n\tGot an unexpected return code!!!' + 
             f'\n\tDetails: {return_code}')
        return return_code

    if last_err[0] != '':
        print('error\n\tAn unexpected error occured!!!' +
             f'\n\tDetails:\n\t\t{last_err}')
        return -1

    for i in range(0, len(last_msg)):
        if last_msg[i] != last_out[i]:
            print('error\n\tLast message was not the expected one!!!' +
                 f'\n\t\tExpected:\n\t\t{last_msg[0]}\n\t\t{last_msg[1]}' +
                 f'\n\n\t\tObtained:\n\t\t{last_out[0]}\n\t\t{last_out[1]}')
            return -1

    print('ok')
    return return_code
    
def run_cli(min_size, n_tests, ciphersuite):
    args = ['./tls_psk/client.out', 'input_size=' + min_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return check_return_code(ret, 'client', ciphersuite, stdout, stderr)
    

def run_srv(min_size, n_tests, ciphersuite):
    args = ['./tls_psk/server.out', 'input_size=' + min_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return check_return_code(ret, 'server', ciphersuite, stdout, stderr)

def exec_tls(filename, timeout, min_size, n_tests, weight):
    os.system('clear')

    #Step 1: Parse ciphersuite list
    print('--- STARTING CIPHERSUITE SELECTION PROCESS ---')
    print(f'\nParsing ciphersuites from {filename}'.ljust(strlen, '.'), end=' ')    
    
    # total_ciphersuites = utils.parse_ciphersuites(filename)
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
    print(f'\t-Timeout: {timeout} sec\n\t-Number of tests: {n_tests}\n\t-Maximum input size: {min_size} bytes')

    print('\n--- STARTING DATA ACQUISITION PROCESS ---')
    pool = ThreadPool(processes=2)

    for ciphersuite in total_ciphersuites:
        print(f'\nStarting analysis for: {ciphersuite} ({current}/{n_total})')
        current += 1

    #Step 2: Start server in thread 1
        print('\tStarting server'.ljust(strlen, '.'), end=' ')
        async_result_srv = pool.apply_async(run_srv, (min_size, n_tests, ciphersuite))
        print('ok')

        time.sleep(timeout)

    #Step 3: Start client in thread 2
        print('\tStarting client'.ljust(strlen, '.'), end=' ')
        async_result_cli = pool.apply_async(run_cli, (min_size, n_tests, ciphersuite))
        print('ok')

    #Step 4: Verify result from server and client
        srv_ret = async_result_srv.get()
        cli_ret = async_result_cli.get()

        if srv_ret == 1 and cli_ret == 1:
            not_ciphersuites.append(ciphersuite)
            n_not += 1
        elif srv_ret != 0 or cli_ret != 0:
            error_ciphersuites.append(ciphersuite)
            n_error += 1
        else:
            print('\n\tData successfully obtained!!!')
            success_ciphersuites.append(ciphersuite)
            n_success += 1

    #Step 5: Analyse and create plots for ciphersuites that ended successfully
    print('\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
    current = 1

    for ciphersuite in success_ciphersuites:
        print(f'\nCreating graphs for: {ciphersuite} ({current}/{n_success})')
        current +=1

        print('\n    Cipher algorithm:')
        plotter.make_figs('../docs/' + ciphersuite + '/cipher_data.csv', weight=weight, strlen=strlen, spacing='\t')

        print('\n    MAC algorithm:')
        plotter.make_figs('../docs/' + ciphersuite + '/md_data.csv', weight=weight, strlen=strlen, spacing='\t')

    #Step 6: Report final status
    print('\n--- FINAL STATUS ---')

    print('\nData generation:')
    print(f'\t-Number of ciphersuites: {n_total}')
    print(f'\t-Number of successes: {n_success}')
    print(f'\t-Number of n/a: {n_not}')
    print(f'\t-Number of errors: {n_error}')

    if n_not > 0:
        print('\t-N/A ciphersuites:')
        for ciphersuite in not_ciphersuites:
            print(f'\t\t{ciphersuite}')

    if n_error > 0:
        print('\t-Error ciphersuites:')
        for ciphersuite in error_ciphersuites:
            print(f'\t\t{ciphersuite}')

    print('\nPlots generation:')
    print(f'\t-Number of ciphersuites: {n_success}')

    print('\nData aquisition and analysis has ended.')
    print('You can check all the csv data and png figure files in the docs/<ciphersuite_name> directories.')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'ht:m:n:f:', ['help', 'timeout=', 'min_size=', 'n_tests=', 'filter='])
    except getopt.GetoptError:
        print('One of the options does not exit.\nUse: "profiller.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print('No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print('Too many arguments')
        sys.exit(2)

    timeout = 2
    min_size = '16'
    n_tests = '500'
    weight = 1.5

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('profiller.py [-t <timeout>] [-m <min_input_size>] [-n <n_tests>] [-f <weight>] <ciphersuite_list>')
            print('profiller.py [--timeout=<timeout>] [--min_size=<min_input_size>] ' +
                  '[--n_tests=<n_tests>] [--filter=<weight>] <ciphersuite_list>')
            sys.exit(0)
        if opt in ('-t', '--timeout'):
            timeout = int(arg)
        if opt in ('-m', '--min_size'):
            min_size = arg
        if opt in ('-n', '--n_tests'):
            n_tests = arg
        if opt in ('-f', '--filter'):
            weight = float(arg)

    exec_tls(args[0], timeout, min_size, n_tests, weight)

if __name__ == '__main__':
   main(sys.argv[1:])