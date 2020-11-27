import os
import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import parser
import plotter


def check_return_code(return_code, endpoint, ciphersuite, stdout, stderr):
    last_msg = ['Final status:', f'  -Suite being used:          {ciphersuite}']
    strout = stdout.decode('utf-8').strip('\n')
    last_out = strout.split('\n')[-2:]
    strerr = stderr.decode('utf-8').strip('\n')
    last_err = strerr.split('\n')

    print(f'\tChecking {endpoint} return code.............. ', end='')

    if last_err[0] != '':
        print(f'error\n\tAn unexpected error occured!!!')
        print(f'\n\tDetails:\n\t\t{last_err}')
        return -1

    for i in range(0, len(last_msg)):
        if last_msg[i] != last_out[i]:
            print(f'error\n\tLast message was not the expected one!!!')
            print(f'\n\t\tExpected:\n\t\t{last_msg[0]}\n\t\t{last_msg[1]}')
            print(f'\n\t\tObtained:\n\t\t{last_out[0]}\n\t\t{last_out[1]}')
            return -1

    print(f'ok')
    return 0
    
def run_cli(max_size, n_tests, ciphersuite):
    args = ['./tls_psk/client.out', 'input_size=' + max_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return check_return_code(ret, 'client', ciphersuite, stdout, stderr)
    

def run_srv(max_size, n_tests, ciphersuite):
    args = ['./tls_psk/server.out', 'input_size=' + max_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return check_return_code(ret, 'server', ciphersuite, stdout, stderr)

def exec_tls(filename, timeout, max_size, n_tests):
    os.system('clear')

    #Step 1: Parse ciphersuite list
    print(f'--- STARTING CIPHERSUITE SELECTION PROCESS ---')
    print(f'\nParsing ciphersuites from {filename}....... ', end='')    
    
    total_ciphersuites = parser.txt_to_list(filename)
    n_total = len(total_ciphersuites)
    success_ciphersuites = []
    n_success = 0
    error_ciphersuites = []
    n_error = 0
    current = 1
    
    print(f'ok\nGot {n_total} ciphersuites')
    print(f'\nRunning with options:')
    print(f'\t-Timeout: {timeout} sec\n\t-Number of tests: {n_tests}\n\t-Maximum input size: {max_size} bytes')

    print(f'\n--- STARTING DATA ACQUISITION PROCESS ---')
    pool = ThreadPool(processes=2)

    for ciphersuite in total_ciphersuites:
        print(f'\nStarting analysis for: {ciphersuite} ({current}/{n_total})')
        current += 1

    #Step 2: Start server in thread 1
        print(f'\tStarting server.......................... ', end='')
        async_result_srv = pool.apply_async(run_srv, (max_size, n_tests, ciphersuite))
        print(f'ok')

        time.sleep(timeout)

    #Step 3: Start client in thread 2
        print(f'\tStarting client.......................... ', end='')
        async_result_cli = pool.apply_async(run_cli, (max_size, n_tests, ciphersuite))
        print(f'ok')

    #Step 4: Verify result from server and client
        srv_ret = async_result_srv.get()
        cli_ret = async_result_cli.get()

        if srv_ret != 0 or cli_ret != 0:
            error_ciphersuites.append(ciphersuite)
            n_error += 1
        else:
            print(f'\n\tData successfully obtained!!!')
            
            success_ciphersuites.append(ciphersuite)
            n_success += 1

    #Step 5: Analyse and create plots for ciphersuites that ended successfully
    print(f'\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
    current = 1

    for ciphersuite in success_ciphersuites:
        print(f'\nCreating graphs for: {ciphersuite} ({current}/{n_success})')
        current +=1

        print(f'\n    Cipher algorithm:')
        plotter.make_figs('../docs/' + ciphersuite + '/cipher_data.csv', spacing='\t')

        print(f'\n    MAC algorithm:')
        plotter.make_figs('../docs/' + ciphersuite + '/md_data.csv', spacing='\t')

    #Step 6: Report final status
    print(f'\n--- FINAL STATUS ---')

    print(f'\nData generation:')
    print(f'\t-Number of ciphersuites: {n_total}')
    print(f'\t-Number of successes: {n_success}')
    print(f'\t-Number of errors: {n_error}')

    if n_error > 0:
        print(f'\t-Error ciphersuites:')
        for ciphersuite in error_ciphersuites:
            print(f'\t\t{ciphersuite}')

    print(f'\nPlots generation:')
    print(f'\t-Number of ciphersuites: {n_success}')

    print(f'\nData aquisition and analysis has ended.')
    print(f'You can check all the csv data and png graph files in the docs/<ciphersuite> directories.')


def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'ht:m:n:', ['help', 'timeout=', 'max_size=', 'n_tests='])
    except getopt.GetoptError:
        print(f'One of the options does not exit.\nUse: "profiller.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print(f'No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print(f'Too many arguments')
        sys.exit(2)

    timeout = 2
    max_size = '4096'
    n_tests = '500'

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'profiller.py [-t <timeout>] [-m <max_input_size>] [-n <n_tests>] <ciphersuite_list>')
            print(f'profiller.py <ciphersuite_list> --timeout=<timeout> --max_size=<max_input_size> --n_tests=<n_tests>')
            sys.exit(0)
        if opt in ('-t', '--timeout'):
            timeout = int(arg)
        if opt in ('-m', '--max_size'):
            max_size = arg
        if opt in ('-n', '--n_tests'):
            n_tests = arg

    exec_tls(args[0], timeout, max_size, n_tests)

if __name__ == '__main__':
   main(sys.argv[1:])