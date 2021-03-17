def init():
    global alg_types
    alg_types = ['cipher', 'md', 'ke']

    global alg_labels
    alg_labels = {'cipher': ['encrypt', 'decrypt'], 'md': ['hash', 'verify'], 'ke': ['server', 'client']}

    global alg_parser_opts
    alg_parser_opts = {'cipher': [3, 'msglen', 'operation'], 'md': [3, 'msglen', 'operation'], 'ke': [2, 'keylen', 'endpoint']}

    global serv_types
    serv_types = ['conf', 'int', 'auth', 'pfs']

    global serv_labels
    serv_labels = {'conf': ['encrypt', 'decrypt'], 'int': ['hash', 'verify'], 'auth': ['server', 'client'], 'pfs': ['server', 'client']}

    global serv_to_alg
    serv_to_alg = {'conf': 'cipher', 'int': 'md', 'auth': 'ke', 'pfs': 'ke'}

    global security_lvls
    security_lvls = ['Insecure', 'Recomended Minimum', 'Secure', 'Strongly Secured']

    global keylen_to_sec_lvl
    keylen_to_sec_lvl = {
        '10': 0, '16': 1, '24': 2, '32': 3,
        '1024': 0, '2048': 1, '4096': 2, '8192': 3,
        '192': 0, '224': 1, '384': 2, '521': 3
    }

    global strlen
    strlen = 55