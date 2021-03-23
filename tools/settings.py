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
    security_lvls = ['80', '112', '128', '192', '256']

    global keylen_to_sec_lvl
    keylen_to_sec_lvl = {
        '10': 0, '14': 1, '16': 2,'24': 3, '32': 4,
        '1024': 0, '2048': 1, '3072': 2, '4096': 3, '8192': 4,
        '192': 0, '224': 1, '256': 2, '384': 3, '521': 4
    }

    global strlen
    strlen = 55