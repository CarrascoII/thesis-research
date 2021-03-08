import os
import sys, getopt
from multiprocessing.pool import ThreadPool
import subprocess
import time
import algs_comparator, plotter, utils


strlen = 50

def run_cli(target, init_size, n_tests, ciphersuite):
    args = ['./../l-tls/tls_' + target + '/client.out', 'input_size=' + init_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'client', ciphersuite, stdout, stderr, strlen)
    
def run_srv(target, init_size, n_tests, ciphersuite):
    args = ['./../l-tls/tls_' + target + '/server.out', 'input_size=' + init_size,
            'n_tests=' + n_tests, 'ciphersuite=' + ciphersuite]
    p = subprocess.Popen(args, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    ret = p.returncode

    return utils.check_endpoint_ret(ret, 'server', ciphersuite, stdout, stderr, strlen)

# def exec_target(target, ciphersuites, timeout, init_size, n_tests, n_total, current):
#     successful = []
#     non_existent = []
#     error = []

#     # Step 3: Compile libs and programs
#     print(f'\nPrepararing libraries and programs'.ljust(strlen, '.'), end=' ', flush=True)
#     thread = ThreadPool(processes=1)
#     async_result_make = thread.apply_async(utils.make_progs, (target,))
#     make_ret = async_result_make.get()
    
#     if make_ret != 0:
#         sys.exit(2)

#     pool = ThreadPool(processes=2)

#     for suite in ciphersuites:
#         print(f'\nStarting analysis for: {suite} ({current}/{n_total})')
#         current += 1

#     # Step 4: Start server in thread 1
#         print('    Starting server'.ljust(strlen, '.'), end=' ', flush=True)
#         async_result_srv = pool.apply_async(run_srv, (target, init_size, n_tests, suite))
#         print('ok')
#         time.sleep(timeout)

#     # Step 5: Start client in thread 2
#         print('    Starting client'.ljust(strlen, '.'), end=' ', flush=True)
#         async_result_cli = pool.apply_async(run_cli, (target, init_size, n_tests, suite))
#         print('ok')

#     # Step 6: Verify result from server and client
#         srv_ret = async_result_srv.get()
#         cli_ret = async_result_cli.get()

#         if srv_ret == 1 and cli_ret == 1:
#             non_existent.append(suite)

#         elif srv_ret != 0 or cli_ret != 0:
#             error.append(suite)

#         else:
#             print('\n    Data successfully obtained!!!')
#             successful.append(suite)

#     return successful, error, non_existent, current

def exec_tls(suites_file, target, timeout, init_size, n_tests, weight):
    # Step 1: Parse ciphersuite list
    print('--- STARTING CIPHERSUITE SELECTION PROCESS ---')
    print(f'\nParsing ciphersuites from {suites_file}'.ljust(strlen, '.'), end=' ', flush=True)    
    
    total_ciphersuites = utils.parse_algorithms(suites_file)
    n_total = len(total_ciphersuites)
    success_ciphersuites = []
    not_ciphersuites = []
    error_ciphersuites = []
    current = 1
    
    print(f'ok\nGot {n_total} ciphersuites')

    # # Step 2: Parse target list
    # print(f'\nParsing compilation targets from {targets}'.ljust(strlen, '.'), end=' ', flush=True)    
    # exec_dict = utils.assign_target(total_ciphersuites, targets)
    # print(f'ok')

    print('\nRunning with options:')
    print(f'    -Timeout: {timeout} sec\n    -Number of tests: {n_tests}\n    -Starting input size: {init_size} bytes')
    print('\n--- STARTING DATA ACQUISITION PROCESS ---')
    
    # for key in exec_dict:
    #     successful, error, non_existent, end = exec_target(key, exec_dict[key], timeout, init_size, n_tests, n_total, current)
    #     exec_dict[key] = successful
    #     success_ciphersuites += successful
    #     error_ciphersuites += error
    #     not_ciphersuites += non_existent
    #     current = end

    # Step 3: Compile libs and programs
    print(f'\nPrepararing libraries and programs'.ljust(strlen, '.'), end=' ', flush=True)
    thread = ThreadPool(processes=1)
    async_result_make = thread.apply_async(utils.make_progs, (target,))
    make_ret = async_result_make.get()
    
    if make_ret != 0:
        sys.exit(2)

    pool = ThreadPool(processes=2)

    for suite in total_ciphersuites:
        print(f'\nStarting analysis for: {suite} ({current}/{n_total})')
        current += 1

    # Step 4: Start server in thread 1
        print('    Starting server'.ljust(strlen, '.'), end=' ', flush=True)
        async_result_srv = pool.apply_async(run_srv, (target, init_size, n_tests, suite))
        print('ok')
        time.sleep(timeout)

    # Step 5: Start client in thread 2
        print('    Starting client'.ljust(strlen, '.'), end=' ', flush=True)
        async_result_cli = pool.apply_async(run_cli, (target, init_size, n_tests, suite))
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

    # Step 7: Analyse data and create individual plots for ciphersuites that ended successfully
    print('\n--- STARTING DATA PLOTS GENERATION PROCESS ---')
    current = 1

    for suite in success_ciphersuites:
        print(f'\nCreating graphs for: {suite} ({current}/{n_success})')
        print('\n    Cipher algorithm:')
        plotter.make_figs('../docs/' + suite + '/cipher_data.csv', 'cipher', weight=weight, strlen=strlen, spacing='    ')
        print('\n    MAC algorithm:')
        plotter.make_figs('../docs/' + suite + '/md_data.csv', 'md', weight=weight, strlen=strlen, spacing='    ')
        current +=1

    # Step 8: Analyse data and create comparison plots for all ciphersuites that ended successfully
    print(f'\nCreating comparison graphs from all ciphersuites:')
    algs_comparator.make_figs(suites_file, success_ciphersuites, weight=weight, strlen=strlen, spacing='    ')

    # Step 9: For each target, save successful ciphersuites in a file
    # for key in exec_dict:
    #     utils.write_ciphersuites(key, exec_dict[key])
    utils.write_ciphersuites(target, success_ciphersuites)

    # Step 10: Report final status
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

    print('\nPlots generation:')
    print(f'    -Number of ciphersuites: {n_success}')
    print('\nData aquisition and analysis has ended.')
    print('You can check all the csv data and png figure files in the docs/<ciphersuite_name> directories.')

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'hc:t:i:n:f:', ['help', 'compile=', 'timeout=', 'init_size=', 'n_tests=', 'filter='])

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
    init_size = '32'
    n_tests = '500'
    weight = 1.5

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print('algs_profiller.py [-c <compilation_target>] [-t <timeout>] [-i <initial_data_size>] ' +
                '[-n <n_tests>] [-f <weight>] <algorithms_list>')
            print('algs_profiller.py [--compile=<compilation_target>] [--timeout=<timeout>] [--init_size=<initial_data_size>] ' +
                '[--n_tests=<n_tests>] [--filter=<weight>] <algorithms_list>')
            sys.exit(0)

        elif opt in ('-c', '--compile'):
            target = arg

        elif opt in ('-t', '--timeout'):
            timeout = int(arg)

        elif opt in ('-i', '--init_size'):
            init_size = arg

        elif opt in ('-n', '--n_tests'):
            n_tests = arg

        elif opt in ('-f', '--filter'):
            weight = float(arg)

    os.system('clear')
    exec_tls(args[0], target, timeout, init_size, n_tests, weight)

if __name__ == '__main__':
   main(sys.argv[1:])