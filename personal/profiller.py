import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import parser

def run_srv(srv_args):
    args = ['./' + 'psk_server' + '.out', 'input_size=' + srv_args['input_size'], 'n_tests=' + srv_args['n_tests']]
    
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode
    

def exec_tls(filename, timeout, max_size, n_tests):
    #Step 1: parse ciphersuite list
    print(f'Parsing ciphersuites from {filename}.... ', end='')    
    ciphersuites = parser.txt_to_list(filename)
    success = 0
    error = 0
    current = 0
    total = len(ciphersuites)
    print(f'ok\nGot {total} ciphersuites\n')    

    pool = ThreadPool(processes=2)
    args = {'input_size': max_size, 'n_tests': n_tests}

    for ciphersuite in ciphersuites:
        current += 1
        print(f'Starting analysis for: {ciphersuite} ({current}/{total})')
        
        print(f'Done')
    #Step 2: start server in thread 1
        print(f'\tStarting server... ', end='')
        async_result_srv = pool.apply_async(args)
    #Step 3: start client in thread 2

    #Step 4: Verify result from server and client

    #Step 5: Analyse and create plots for ciphersuites that ended successfully

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'h:t:m:n', ['help', 'timeout=', 'max_size=', 'n_tests='])
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
    max_size = 4096
    n_tests = 500

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'profiller.py <ciphersuite_list>')
            sys.exit(0)
        if opt in ('-t', '--timeout'):
            timeout = int(arg)
        if opt in ('-m', '--max_size'):
            max_size = int(arg)
        if opt in ('-n', '--n_tests'):
            n_tests = int(arg)

    exec_tls(args[0], timeout, max_size, n_tests)

if __name__ == '__main__':
   main(sys.argv[1:])