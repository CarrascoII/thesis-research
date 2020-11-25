import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import parser
import plotter


def check_return_code(return_code, endpoint, ciphersuite, stdout):
    last_msg = ['  -TLS version being used:    TLSv1.2',
               f'  -Suite being used:          {ciphersuite}']
    strout = stdout.decode('utf-8')
    strout = strout.strip('\n')
    last_out = strout.split('\n')[-2:]

    for i in range(0, len(last_msg)):
        if last_msg[i] != last_out[i]:
            print(f'\n\t{endpoint}\'s last message was an unexpected one. Setting return code to -1...')
            print(f'\n\tExpected:\n\t{last_msg[0]}\n\t{last_msg[1]}')
            print(f'\n\tObtained:\n\t{last_out[0]}\n\t{last_out[1]}')
            return -1

    # print(f'\t{endpoint}\'s last message was the expected one. Setting return code to 0...')
    return 0
    
def run_cli(max_size, n_tests, ciphersuite):
    args = ['./tls_psk/client.out', 'input_size=' + max_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode
    # print(f'\n\tClient stdout:\n{stdout}')
    # print(f'\n\tClient stderr:\n{stderr}')

    return check_return_code(ret, 'Client', ciphersuite, stdout)
    

def run_srv(max_size, n_tests, ciphersuite):
    args = ['./tls_psk/server.out', 'input_size=' + max_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    # print(f'\n\tServer stdout:\n{stdout}')
    # print(f'\n\tServer stderr:\n{stderr}')

    return check_return_code(ret, 'Server', ciphersuite, stdout)

def exec_tls(filename, timeout, max_size, n_tests):
    #Step 1: Parse ciphersuite list
    print(f'Parsing ciphersuites from {filename}.... ', end='')    
    
    total_ciphersuites = parser.txt_to_list(filename)
    n_total = len(total_ciphersuites)
    success_ciphersuites = []
    n_success = 0
    error_ciphersuites = []
    n_error = 0
    current = 1
    
    print(f'ok\n\nGot {n_total} ciphersuites')
    print(f'Running with options:')
    print(f'\t-Timeout: {timeout} sec\n\t-Number of tests: {n_tests}\n\t-Maximum input size: {max_size} bytes')

    pool = ThreadPool(processes=2)
    for ciphersuite in total_ciphersuites:
        print(f'\nStarting analysis for: {ciphersuite} ({current}/{n_total})')
        current += 1

    #Step 2: Start server in thread 1
        print(f'\tStarting server.................... ', end='')
        async_result_srv = pool.apply_async(run_srv, (max_size, n_tests, ciphersuite))
        print(f'ok')

        time.sleep(timeout)

    #Step 3: Start client in thread 2
        print(f'\tStarting client.................... ', end='')
        async_result_cli = pool.apply_async(run_cli, (max_size, n_tests, ciphersuite))
        print(f'ok')

    #Step 4: Verify result from server and client
        print(f'\tChecking endpoints return code..... ', end='')
        srv_ret = async_result_srv.get()
        cli_ret = async_result_cli.get()

        if srv_ret != 0 or cli_ret != 0:
            print(f'error\n\tNon-zero return code from {ciphersuite}:')
            print(f'\t\tServer returned: {srv_ret}')
            print(f'\t\tClient returned: {cli_ret}')

            error_ciphersuites.append(ciphersuite)
            n_error += 1
        else:
            print(f'ok\n\tData successfully obtained!!!')
            
            success_ciphersuites.append(ciphersuite)
            n_success += 1

    #Step 5: Analyse and create plots for ciphersuites that ended successfully
    current = 1

    for ciphersuite in success_ciphersuites:
        print(f'\nCreating graphs for: {ciphersuite} ({current}/{n_success})')
        current +=1

        print(f'\tCreating encryption graphs....... ', end='')
        cipher_file = '../docs/' + ciphersuite + '/cipher_data.csv'
        plotter.make_graphs(cipher_file)
        print(f'ok')

        print(f'\tCreating MAC graphs.............. ', end='')
        md_file = '../docs/' + ciphersuite + '/md_data.csv'
        plotter.make_graphs(md_file)
        print(f'ok')

    #Step 6: Report final status
    print(f'\nFinal status:')
    print(f'\t-Number of ciphersuites: {n_total}')
    print(f'\t-Number of successes: {n_success}')
    print(f'\t-Number of errors: {n_error}')
    
    if n_error > 0:
        print(f'\t-Error ciphersuites:')
        for ciphersuite in error_ciphersuites:
            print(f'\t\t{ciphersuite}')

    print(f'\nData aquisition and analysis has ended.')
    print(f'You can check all the csv data and png graph files in the docs/<ciphersuite> directory.')


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