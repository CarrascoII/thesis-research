import sys, getopt

def main(argv):
    try:
        opts, args = getopt.getopt(argv, 'h', ['help'])
    except getopt.GetoptError:
        print(f'One of the options does not exit.\nUse: "profiller.py -h" for help')
        sys.exit(2)

    if not args and not opts:
        print(f'No file with ciphersuites given')
        sys.exit(2)

    if len(args) > 1:
        print(f'Too many arguments')
        sys.exit(2)

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            print(f'profiller.py <ciphersuite_list>')
            sys.exit(0)

    #TODO: Continue to write the program

if __name__ == '__main__':
   main(sys.argv[1:])